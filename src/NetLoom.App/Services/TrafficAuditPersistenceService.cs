using System.IO;
using System.Text.Json;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class TrafficAuditPersistenceService
{
    public static string AuditDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WooklyDev", "NetLoom", "traffic-audit");

    public static async Task<string> SaveJsonAsync(TrafficAuditSessionSnapshot snapshot)
    {
        Directory.CreateDirectory(AuditDirectory);
        string started = snapshot.StartedAtUtc == default ? DateTime.Now.ToString("yyyyMMdd_HHmmss") : snapshot.StartedAtUtc.ToLocalTime().ToString("yyyyMMdd_HHmmss");
        string path = Path.Combine(AuditDirectory, $"TrafficAudit_{started}.json");
        var options = new JsonSerializerOptions { WriteIndented = true };
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, options));
        return path;
    }
}
