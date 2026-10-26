using System.IO;
using System.Text;

namespace NetLoom.App.Services;

public static class CrashLogService
{
    private static readonly object Sync = new();

    public static string Write(string context, Exception exception)
    {
        try
        {
            string directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WooklyDev",
                "NetLoom",
                "logs");
            Directory.CreateDirectory(directory);

            string path = Path.Combine(directory, "NetLoom-crash.log");
            var sb = new StringBuilder();
            sb.AppendLine(new string('=', 78));
            sb.AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}  {context}");
            sb.AppendLine(exception.ToString());

            lock (Sync)
            {
                File.AppendAllText(path, sb.ToString(), new UTF8Encoding(false));
            }
            return path;
        }
        catch
        {
            return "로그 저장 실패";
        }
    }
}
