using System.IO;
using System.Text.Json;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class PacketInspectorSettingsService
{
    private static string SettingsPath
    {
        get
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(root, "WooklyDev", "NetLoom", "packet-inspector.json");
        }
    }

    public static PacketInspectorSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return new PacketInspectorSettings();
            return JsonSerializer.Deserialize<PacketInspectorSettings>(File.ReadAllText(SettingsPath)) ?? new PacketInspectorSettings();
        }
        catch
        {
            return new PacketInspectorSettings();
        }
    }

    public static void Save(PacketInspectorSettings settings)
    {
        string? directory = Path.GetDirectoryName(SettingsPath);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
    }
}
