﻿using System;
using System.Linq;
using System.Threading.Tasks;
using Caliburn.Micro;
using SevenPass.Models;
using SevenPass.Services.Cache;

namespace SevenPass.ViewModels
{
    /// <summary>
    /// ViewModel to display database data.
    /// </summary>
    public class DatabaseViewModel : Screen
    {
        private readonly ICacheService _cache;
        private readonly BindableCollection<object> _items;
        private readonly INavigationService _navigation;

        private object _selectedItem;

        /// <summary>
        /// Gets or sets the database name.
        /// </summary>
        public string DatabaseName { get; private set; }

        /// <summary>
        /// Gets or sets the UUID of the group to be displayed.
        /// </summary>
        public string Group { get; set; }

        /// <summary>
        /// Gets or sets the group items.
        /// </summary>
        public BindableCollection<object> Items
        {
            get { return _items; }
        }

        /// <summary>
        /// Gets or sets the selected item.
        /// </summary>
        public object SelectedItem
        {
            get { return _selectedItem; }
            set
            {
                _selectedItem = value;
                NotifyOfPropertyChange(() => SelectedItem);

                if (value == null)
                    return;

                Open(value);
                SelectedItem = null;
            }
        }

        public DatabaseViewModel(ICacheService cache,
            INavigationService navigation)
        {
            if (cache == null) throw new ArgumentNullException("cache");
            if (navigation == null) throw new ArgumentNullException("navigation");

            _cache = cache;
            _navigation = navigation;
            DatabaseName = _cache.Database.Name;
            _items = new BindableCollection<object>();
        }

        /// <summary>
        /// Initializes the page.
        /// </summary>
        /// <returns></returns>
        public Task Initialize()
        {
            return Task.Run(() =>
            {
                var element = _cache.GetGroup(Group);
                // TODO: handle group not found

                var group = new GroupItemModel(element);
                base.DisplayName = group.Name;

                var groups = group
                    .ListGroups()
                    .Select(x => new GroupItemViewModel(x))
                    .Cast<object>();

                var entries = group
                    .ListEntries()
                    .Select(x => new EntryItemViewModel(x))
                    .Cast<object>();

                _items.AddRange(groups.Concat(entries));
            });
        }

        protected override void OnInitialize()
        {
            Initialize();
        }

        /// <summary>
        /// Opens the specified item.
        /// </summary>
        /// <param name="item">The item to open.</param>
        private void Open(object item)
        {
            var group = item as GroupItemViewModel;
            if (group == null)
                return;

            _navigation
                .UriFor<DatabaseViewModel>()
                .WithParam(x => x.Group, group.Id)
                .Navigate();
        }
    }
}