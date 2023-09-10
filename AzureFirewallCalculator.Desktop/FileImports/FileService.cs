using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace AzureFirewallCalculator.Desktop.FileImports;

// Largely copied from https://github.com/AvaloniaUI/AvaloniaUI.QuickGuides/blob/main/IoCFileOps/Services/FilesService.cs
public class FileService
{
    public FileService(Func<Window> windowFactory)
    {
        Window = new(windowFactory);
    }

    private readonly Lazy<Window> Window;

    public async Task<IStorageFile?> OpenFileAsync(string prompt)
    {
        var files = await Window.Value.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions()
        {
            Title = prompt,
            AllowMultiple = false
        });

        return files.Count >= 1 ? files[0] : null;
    }

    public async Task SaveFileAsync(string prompt, string fileName, string extension, Stream fileStream)
    {
        var files = await Window.Value.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions()
        {
            Title = prompt,
            SuggestedFileName = fileName,
            DefaultExtension = extension
        });

        if (files == null)
        {
            return;
        }

        using var writer = await files.OpenWriteAsync();
        await fileStream.CopyToAsync(writer);
        await writer.FlushAsync();
    }
}