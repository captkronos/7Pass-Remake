﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Storage;
using Windows.Storage.AccessCache;
using Caliburn.Micro;
using Newtonsoft.Json;
using SevenPass.Messages;

namespace SevenPass.Services.Databases
{
    public class RegisteredDbsService : IRegisteredDbsService
    {
        private readonly IAsyncOperation<StorageFolder> _cacheFolder;
        private readonly IEventAggregator _events;

        public RegisteredDbsService(IEventAggregator events)
        {
            if (events == null)
                throw new ArgumentNullException("events");

            _events = events;

            var localFolder = ApplicationData.Current.LocalFolder;
            _cacheFolder = localFolder.CreateFolderAsync(
                "Databases", CreationCollisionOption.OpenIfExists);
        }

        /// <summary>
        /// Lists all registered databases.
        /// </summary>
        /// <returns>The registered databases.</returns>
        public ICollection<DatabaseRegistration> List()
        {
            return StorageApplicationPermissions
                .FutureAccessList
                .Entries
                .Select(Read)
                .Where(x => x != null)
                .ToList();
        }

        /// <summary>
        /// Registers the specified storage file.
        /// </summary>
        /// <param name="file">The database file.</param>
        /// <returns>The database registration information.</returns>
        public async Task<DatabaseRegistration> RegisterAsync(IStorageFile file)
        {
            var meta = new DatabaseMetaData
            {
                Name = GetName(file.Name),
            };

            var token = StorageApplicationPermissions.FutureAccessList
                .Add(file, JsonConvert.SerializeObject(meta));
            await file.CopyAsync(await _cacheFolder, token + ".kdbx");

            var info = new DatabaseRegistration
            {
                Id = token,
                Name = meta.Name,
            };

            // Send notification message
            _events.PublishOnCurrentThread(new DatabaseRegistrationMessage
            {
                Registration = info,
                Action = DatabaseRegistrationActions.Added,
            });

            return info;
        }

        /// <summary>
        /// Removes the specified database from registration.
        /// </summary>
        /// <param name="id">The database ID.</param>
        public async Task RemoveAsync(string id)
        {
            var file = await GetCachedFile(id);
            await file.DeleteAsync();

            StorageApplicationPermissions
                .FutureAccessList.Remove(id);
        }

        /// <summary>
        /// Retrieves the database file.
        /// </summary>
        /// <param name="id">The database ID.</param>
        /// <returns>The database file.</returns>
        public async Task<IStorageFile> RetrieveAsync(string id)
        {
            return await StorageApplicationPermissions
                .FutureAccessList.GetFileAsync(id);
        }

        /// <summary>
        /// Retrieves the cached database file.
        /// </summary>
        /// <param name="id">The database ID.</param>
        /// <returns>The cached database file.</returns>
        public async Task<IStorageFile> RetrieveCachedAsync(string id)
        {
            return await GetCachedFile(id);
        }

        private async Task<IStorageFile> GetCachedFile(string token)
        {
            var folder = await _cacheFolder;
            return await folder
                .GetFileAsync(token + ".kdbx");
        }

        /// <summary>
        /// Gets the default database name from file name.
        /// </summary>
        /// <param name="fileName">The file name.</param>
        /// <returns>The default database name.</returns>
        private static string GetName(string fileName)
        {
            if (fileName.EndsWith(".kdbx", StringComparison.OrdinalIgnoreCase))
                fileName = fileName.Substring(0, fileName.Length - 5);

            return fileName;
        }

        /// <summary>
        /// Reads the <see cref="DatabaseRegistration"/> from file access entry.
        /// </summary>
        /// <param name="entry">File access entry.</param>
        /// <returns>The database registration, or <c>null</c> if not valid.</returns>
        private static DatabaseRegistration Read(AccessListEntry entry)
        {
            try
            {
                var meta = JsonConvert.DeserializeObject
                    <DatabaseMetaData>(entry.Metadata);

                return new DatabaseRegistration
                {
                    Id = entry.Token,
                    Name = meta.Name,
                };
            }
            catch
            {
                return null;
            }
        }
    }
}