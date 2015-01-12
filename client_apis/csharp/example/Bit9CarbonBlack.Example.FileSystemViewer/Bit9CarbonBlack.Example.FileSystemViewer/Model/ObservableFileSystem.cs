using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;

namespace Bit9CarbonBlack.Example.FileSystemViewer.Model
{
    public class ObservableFileSystem : ObservableCollection<PathComponent>
    {
        private int fileCount;

        public int FileCount
        { 
            get
            {
                return this.fileCount;
            }
            private set
            {
                this.fileCount = value;
                this.OnPropertyChanged(new PropertyChangedEventArgs("FileCount"));
            }
        }

        protected override void ClearItems()
        {
            base.ClearItems();
            this.FileCount = 0;
        }

        public void AddFileSystemItem(string path, string timestamp, int action)
        {
            var pathParts = path.Split(new string[] { @"\", @"\\", "/" }, System.StringSplitOptions.RemoveEmptyEntries);
            var pathPartsLength = pathParts.Length;
            if (pathParts.Length == 0)
            {
                return;
            }

            FilePathFolder currentPath = (FilePathFolder)this.FirstOrDefault(x => x is FilePathFolder && String.Compare(x.Name, pathParts[0], true) == 0);
            if (currentPath == null)
            {
                currentPath = new FilePathFolder() { Name = pathParts[0] };
                this.Add(currentPath);
            }

            for (int i = 1; i < pathPartsLength - 1; i++)
            {
                var tempcurrentPath = (FilePathFolder)currentPath.Children.FirstOrDefault(x => x is FilePathFolder && String.Compare(x.Name, pathParts[i], true) == 0);
                if (tempcurrentPath == null)
                {
                    tempcurrentPath = new FilePathFolder() { Name = pathParts[i] };
                    currentPath.Children.Add(tempcurrentPath);
                }

                currentPath = tempcurrentPath;
            }

            FilePathItem item = (FilePathItem)currentPath.Children.FirstOrDefault(x => x is FilePathItem && String.Compare(x.Name, pathParts[pathPartsLength - 1], true) == 0);
            if (item == null)
            {
                item = new FilePathItem() { Name = pathParts[pathPartsLength - 1] };
                currentPath.Children.Add(item);
                FileCount++;
            }

            item.Details.Add(new FilePathItemDetails() { Action = (FileItemAction)action, TimeStamp = timestamp } );
        }
    }
}
