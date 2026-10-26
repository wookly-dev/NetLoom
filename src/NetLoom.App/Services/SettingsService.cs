using System.IO;
using System.Text.Json;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class SettingsService
{
    private static readonly string SettingsDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WooklyDev",
        "NetLoom");

    private static readonly string SettingsPath = Path.Combine(SettingsDirectory, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
                return new AppSettings();

            var json = File.ReadAllText(SettingsPath);
            var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();

            // v0.7.3: the sensor-host topology exclusion is now the safe default.
            // Existing v0.7.2 settings already contain ExcludeSensorHostTopologyConnections=false,
            // so a property initializer alone would not update upgraded installations. Apply this
            // default exactly once, then preserve the user's explicit choice on later starts.
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty(nameof(AppSettings.SensorHostTopologyExclusionDefaultV073Applied), out _))
            {
                settings.ExcludeSensorHostTopologyConnections = true;
                settings.SensorHostTopologyExclusionDefaultV073Applied = true;
                Save(settings);
            }

            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(AppSettings settings)
    {
        Directory.CreateDirectory(SettingsDirectory);
        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(SettingsPath, json);
    }
}
