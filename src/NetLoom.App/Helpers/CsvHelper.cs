namespace NetLoom.App.Helpers;

public static class CsvHelper
{
    // Network names and packet hints are untrusted spreadsheet input.
    public static string Escape(string? value)
    {
        value ??= "";
        var content = value.AsSpan().TrimStart();
        if ((!content.IsEmpty && content[0] is '=' or '+' or '-' or '@') ||
            (value.Length > 0 && value[0] is '\t' or '\r' or '\n'))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
