using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.System;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Input;
using Caliburn.Micro;
using SevenPass.IO;
using SevenPass.Messages;
using SevenPass.Services.Cache;
using SevenPass.Services.Databases;
using SevenPass.Services.Picker;
//NFCTag stuff
using KeePassNFC;

namespace SevenPass.ViewModels
{
    public sealed class PasswordViewModel : Screen
    {
        private readonly ICacheService _cache;
        private readonly IEventAggregator _events;
        private readonly INavigationService _navigation;
        private readonly PasswordData _password;
        private readonly IFilePickerService _picker;
        private readonly IRegisteredDbsService _registrations;
        private string _keyfileName;
        //NFCTag stuff
        private NFC theNFC = new NFC();
        private string _keyfileContentsAsHex;

        public bool CanClearKeyfile
        {
            get { return _password.HasKeyFile; }
        }

        /// <summary>
        /// Determines whether user has provided a valid master key.
        /// </summary>
        public bool CanOpenDatabase
        {
            get { return _password.IsValid; }
        }

        /// <summary>
        /// Gets or sets the database ID.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Gets the visibility of the Keyfile group
        /// </summary>
        public Visibility KeyfileGroupVisibility
        {
            get
            {
                return CanClearKeyfile
                    ? Visibility.Visible
                    : Visibility.Collapsed;
            }
        }

        /// <summary>
        /// Gets or sets name of the file used as keyfile.
        /// </summary>
        public string KeyfileName
        {
            get { return _keyfileName; }
            set
            {
                _keyfileName = value;
                NotifyOfPropertyChange(() => KeyfileName);
            }
        }

        /// <summary>
        /// NFCTag Stuff
        /// Gets or sets keyfile contents.
        /// (Using hex encoding because Caliburn Micro doesn't seem to like passing of byte arrays)
        /// </summary>
        public string KeyfileContentsAsHex
        {
            get { return _keyfileContentsAsHex; }
            set
            {
                _keyfileContentsAsHex = value;
                _password.SetKeyFile(Windows.Security.Cryptography.CryptographicBuffer.DecodeFromHexString(value));
                NotifyOfPropertyChange(() => KeyfileContentsAsHex);
            }
        }

        /// <summary>
        /// Gets or sets the master password.
        /// </summary>
        public string Password
        {
            get { return _password.Password; }
            set
            {
                _password.Password = value;
                NotifyOfPropertyChange(() => Password);
                NotifyOfPropertyChange(() => CanOpenDatabase);
            }
        }

        public PasswordViewModel(IFilePickerService picker,
            IRegisteredDbsService registrations, ICacheService cache,
            INavigationService navigation, IEventAggregator events)
        {
            if (picker == null) throw new ArgumentNullException("picker");
            if (registrations == null) throw new ArgumentNullException("registrations");
            if (cache == null) throw new ArgumentNullException("cache");
            if (navigation == null) throw new ArgumentNullException("navigation");
            if (events == null) throw new ArgumentNullException("events");

            _cache = cache;
            _picker = picker;
            _events = events;
            _navigation = navigation;
            _registrations = registrations;
            _password = new PasswordData();
        }

        public async Task AddKeyFile(IStorageFile file)
        {
            KeyfileName = file.Name;
            using (var input = await file.OpenReadAsync())
                await _password.AddKeyFile(input);

            NotifyOfPropertyChange(() => CanOpenDatabase);
            NotifyOfPropertyChange(() => CanClearKeyfile);
            NotifyOfPropertyChange(() => KeyfileGroupVisibility);
        }

        public async void CheckEnterKey(KeyRoutedEventArgs args)
        {
            if (args.Key == VirtualKey.Enter)
                await OpenDatabase();
        }

        /// <summary>
        /// Removes the keyfile.
        /// </summary>
        public void ClearKeyfile()
        {
            KeyfileName = null;
            _password.ClearKeyfile();

            NotifyOfPropertyChange(() => CanOpenDatabase);
            NotifyOfPropertyChange(() => CanClearKeyfile);
            NotifyOfPropertyChange(() => KeyfileGroupVisibility);
        }

        public async Task OpenDatabase()
        {
            var database = await OpenFileAsync();

            using (var fs = await database.OpenReadAsync())
            {
                // TODO: handle errors & display transformation progress
                var result = await FileFormat.Headers(fs);
                var headers = result.Headers;

                var masterKey = await _password
                    .GetMasterKey(headers);

                using (var decrypted = await FileFormat
                    .Decrypt(fs, masterKey, headers))
                {
                    // TODO: verify start bytes
                    await FileFormat.VerifyStartBytes(
                        decrypted, headers);

                    // Parse content
                    var doc = await FileFormat.ParseContent(
                        decrypted, headers.UseGZip, headers);

                    // TODO: verify headers integrity

                    _cache.Cache(new CachedDatabase
                    {
                        Id = Id,
                        Document = doc,
                        Name = DisplayName,
                        Headers = headers,
                    });

                    _navigation
                        .UriFor<GroupViewModel>()
                        .Navigate();

                    _navigation.BackStack.Remove(
                        _navigation.BackStack.Last());
                }
            }
        }

        public async Task PickKeyfile()
        {
            await _picker.PickAsync(
                FilePickTargets.KeyFile);
        }
        public void WriteTag()
        //NFCTag stuff
        {
            byte[] keyFileContents;
            Windows.Security.Cryptography.CryptographicBuffer.CopyToByteArray(_password.GetKeyFile(), out keyFileContents);
            byte[] theRecord;
           
            theRecord = theNFC.makeKeePassNFCRecord(DisplayName, Id, KeyfileName, keyFileContents, null); 
            if (theRecord!=null)
            {
                int response = theNFC.PublishAsync(published, theRecord);
                //if (response != 0)
                //    ;
                //    //error
            }
        }
        //NFCTag stuff
        private async void published(int callbackmsg)
        {
            string announce="";
            if (callbackmsg > 0)
                announce = "Tag written";
            else if (callbackmsg < 0)
                announce = "Tag capacity too small. It only has " + (callbackmsg * -1).ToString() + " bytes";
            else
                announce = "Tag write error";
            var messageDialog = new Windows.UI.Popups.MessageDialog(announce);
            await messageDialog.ShowAsync();
        }

        private async Task<IStorageFile> OpenFileAsync()
        {
            try
            {
                return await _registrations
                    .RetrieveAsync(Id);
            }
            catch (IOException) {}

            var cached = await _registrations
                .RetrieveCachedAsync(Id);
            await _events.PublishOnUIThreadAsync(
                new CachedFileAccessMessage
                {
                    Name = cached.Name,
                });

            return cached;
        }
    }
}