using Bit9CarbonBlack.Example.FileSystemViewer.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Bit9CarbonBlack.Example.FileSystemViewer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly ObservableFileSystem filesystem = new ObservableFileSystem();
        private readonly Client.CarbonBlack cb = new Client.CarbonBlack();
        private CancellationTokenSource cancelSource;

        public MainWindow()
        {
            InitializeComponent();

            this.DataContext = filesystem;
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (String.IsNullOrWhiteSpace(this.serverUriText.Text) || String.IsNullOrWhiteSpace(this.apiTokenText.Text) || String.IsNullOrWhiteSpace(this.sensorHostnameText.Text))
                {
                    MessageBox.Show("CB Server Uri, CB Api Token, and Sensor Hostname must be populated!");
                    return;
                }

                cb.ServerUri = this.serverUriText.Text;
                cb.ApiToken = this.apiTokenText.Text;

                var sensorId = await cb.GetSensorIdForHost(this.sensorHostnameText.Text);
                if (sensorId == -1)
                {
                    MessageBox.Show(String.Format("A matching sensor could not be found for the Sensor Hostname: '{0}'", this.sensorHostnameText.Text));
                    return;
                }

                this.loadButton.IsEnabled = false;
                this.stopButton.IsEnabled = true;

                using (this.cancelSource = new CancellationTokenSource())
                {
                    var resultCount = 0;
                    var totalCount = 0;
                    do
                    {
                        resultCount = await cb.UpdateFilesBatch(this.filesystem, sensorId, totalCount, 100, cancelSource.Token);
                        if (resultCount < 0)
                        {
                            return;
                        }
                        totalCount += resultCount;
                    }
                    while (resultCount > 0);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(String.Format("An error occured: {0}", ex.ToString()));
            }
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            this.filesystem.Clear();;
            this.clearButton.IsEnabled = false;
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            this.cancelSource.Cancel(false);
            this.loadButton.IsEnabled = true;
            this.clearButton.IsEnabled = true;
            this.stopButton.IsEnabled = false;
        }
    }
}
