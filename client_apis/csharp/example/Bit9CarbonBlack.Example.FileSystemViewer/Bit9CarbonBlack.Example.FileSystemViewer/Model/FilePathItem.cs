
using System.Collections.ObjectModel;

namespace Bit9CarbonBlack.Example.FileSystemViewer.Model
{
    public class FilePathItem : PathComponent
    {
        public FilePathItem()
        {
            this.Details = new ObservableCollection<FilePathItemDetails>();
        }

        public ObservableCollection<FilePathItemDetails> Details { get; set; }
    }
}
