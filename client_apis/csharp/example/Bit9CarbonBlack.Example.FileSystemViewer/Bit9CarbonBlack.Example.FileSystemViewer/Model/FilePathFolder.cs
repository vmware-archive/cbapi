using System.Collections.ObjectModel;

namespace Bit9CarbonBlack.Example.FileSystemViewer.Model
{
    public class FilePathFolder : PathComponent
    {
        public FilePathFolder()
        {
            this.Children = new ObservableCollection<PathComponent>();
        }

        public ObservableCollection<PathComponent> Children { get; set; }
    }
}
