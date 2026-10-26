namespace NetLoom.App.Services;

/// <summary>
/// Offline best-effort grouping based only on names passively exposed by TLS SNI / HTTP Host.
/// This is not an ASN or GeoIP verdict and deliberately performs no external lookup.
/// </summary>
public static class ExternalServiceClassifier
{
    private static readonly (string Group, string[] Suffixes)[] Rules =
    {
        ("Microsoft", new[] { "microsoft.com", "microsoftonline.com", "windowsupdate.com", "office.com", "office365.com", "live.com", "msedge.net", "azure.com", "azureedge.net", "windows.net", "skype.com", "teams.microsoft.com" }),
        ("Google", new[] { "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "ytimg.com", "android.com" }),
        ("Cloudflare", new[] { "cloudflare.com", "cloudflare-dns.com", "cloudflare.net" }),
        ("AWS", new[] { "amazonaws.com", "cloudfront.net", "aws.amazon.com" }),
        ("Apple", new[] { "apple.com", "icloud.com", "mzstatic.com" }),
        ("Meta", new[] { "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net" }),
        ("Naver", new[] { "naver.com", "naver.net", "pstatic.net" }),
        ("Kakao", new[] { "kakao.com", "kakaocdn.net", "daum.net" }),
        ("GitHub", new[] { "github.com", "githubusercontent.com", "githubassets.com" }),
        ("Akamai/CDN", new[] { "akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net" })
    };

    public static string ClassifyHost(string? host)
    {
        string normalized = NormalizeHost(host);
        if (string.IsNullOrWhiteSpace(normalized)) return "Unknown";
        foreach (var rule in Rules)
        {
            if (rule.Suffixes.Any(s => normalized.Equals(s, StringComparison.OrdinalIgnoreCase) || normalized.EndsWith("." + s, StringComparison.OrdinalIgnoreCase)))
                return rule.Group;
        }
        return "기타 도메인";
    }

    public static string ExtractObservedHost(string? applicationSummary)
    {
        if (string.IsNullOrWhiteSpace(applicationSummary)) return "";
        const string sniMarker = "SNI ";
        int sni = applicationSummary.IndexOf(sniMarker, StringComparison.OrdinalIgnoreCase);
        if (sni >= 0)
            return NormalizeHost(applicationSummary[(sni + sniMarker.Length)..]);

        const string hostMarker = "Host ";
        int host = applicationSummary.LastIndexOf(hostMarker, StringComparison.OrdinalIgnoreCase);
        if (host >= 0)
            return NormalizeHost(applicationSummary[(host + hostMarker.Length)..]);
        return "";
    }

    private static string NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return "";
        string value = host.Trim().TrimEnd('.');
        int separator = value.IndexOfAny(new[] { ' ', '·', '/', '\\', '\r', '\n' });
        if (separator > 0) value = value[..separator];
        int colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon) value = value[..colon];
        return value.Trim().ToLowerInvariant();
    }
}
