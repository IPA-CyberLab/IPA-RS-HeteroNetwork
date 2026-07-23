using System.ComponentModel;
using System.Drawing;
using System.Windows;
using HeteroNetwork.Core;
using Forms = System.Windows.Forms;

namespace HeteroNetwork.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel viewModel;
    private readonly Forms.NotifyIcon trayIcon;
    private readonly Forms.ToolStripMenuItem connectionMenuItem;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        this.viewModel = viewModel;
        DataContext = viewModel;
        viewModel.ActivationAccepted += ViewModel_ActivationAccepted;
        viewModel.PropertyChanged += ViewModel_PropertyChanged;

        connectionMenuItem = new Forms.ToolStripMenuItem("Connect");
        connectionMenuItem.Click += async (_, _) => await Dispatcher.InvokeAsync(
            async () => await ToggleConnectionAsync());
        var showItem = new Forms.ToolStripMenuItem("Open HeteroNetwork");
        showItem.Click += (_, _) => Dispatcher.Invoke(ShowAndActivate);
        var webUiItem = new Forms.ToolStripMenuItem("Open Web UI");
        webUiItem.Click += (_, _) => Dispatcher.Invoke(viewModel.OpenWebUi);
        var exitItem = new Forms.ToolStripMenuItem("Quit");
        exitItem.Click += (_, _) => Dispatcher.Invoke(
            () => ((App)System.Windows.Application.Current).ExitApplication());
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(showItem);
        menu.Items.Add(connectionMenuItem);
        menu.Items.Add(webUiItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(exitItem);
        trayIcon = new Forms.NotifyIcon
        {
            Text = "HeteroNetwork",
            Icon = SystemIcons.Application,
            Visible = true,
            ContextMenuStrip = menu,
        };
        trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowAndActivate);
        Closing += MainWindow_Closing;
        UpdateTrayState();
    }

    public void ShowAndActivate()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    public void DisposeTrayIcon()
    {
        viewModel.ActivationAccepted -= ViewModel_ActivationAccepted;
        viewModel.PropertyChanged -= ViewModel_PropertyChanged;
        trayIcon.Visible = false;
        trayIcon.Dispose();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!((App)System.Windows.Application.Current).IsExiting)
        {
            e.Cancel = true;
            Hide();
        }
    }

    private void ViewModel_ActivationAccepted(object? sender, string activation)
    {
        EnrollmentLink.Password = activation;
        ShowAndActivate();
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.StatusDisplay)
            or nameof(MainViewModel.IsConnected))
        {
            UpdateTrayState();
        }
    }

    private void UpdateTrayState()
    {
        trayIcon.Text = $"HeteroNetwork — {viewModel.StatusDisplay}";
        connectionMenuItem.Text = viewModel.IsConnected ? "Disconnect" : "Connect";
        connectionMenuItem.Enabled = viewModel.IsConfigured && !viewModel.IsBusy;
    }

    private void EnrollmentLink_PasswordChanged(object sender, RoutedEventArgs e) =>
        viewModel.SetEnrollmentInput(EnrollmentLink.Password);

    private async void Enroll_Click(object sender, RoutedEventArgs e)
    {
        await viewModel.EnrollAsync();
        if (viewModel.IsConfigured)
        {
            EnrollmentLink.Clear();
        }
    }

    private async void Connection_Click(object sender, RoutedEventArgs e) =>
        await ToggleConnectionAsync();

    private async Task ToggleConnectionAsync()
    {
        if (viewModel.IsConnected)
        {
            await viewModel.DisconnectAsync();
        }
        else
        {
            await viewModel.ConnectAsync();
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) =>
        await viewModel.RefreshAsync();

    private void OpenWebUi_Click(object sender, RoutedEventArgs e) =>
        viewModel.OpenWebUi();

    private async void Remove_Click(object sender, RoutedEventArgs e)
    {
        var result = System.Windows.MessageBox.Show(
            this,
            "The VPN profile and local identity will be deleted.",
            "Remove this PC?",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning,
            MessageBoxResult.Cancel);
        if (result == MessageBoxResult.OK)
        {
            await viewModel.RemoveAsync();
        }
    }

    private void DismissError_Click(object sender, RoutedEventArgs e) =>
        viewModel.ClearError();

}
