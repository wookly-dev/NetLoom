namespace NetLoom.App.Models;

public sealed class SecurityPolicyDocument
{
    public int SchemaVersion { get; set; } = 1;
    public DateTime UpdatedUtc { get; set; }
    public List<string> TrustedInternalAddresses { get; set; } = new();
    public List<string> AllowedExternalAddresses { get; set; } = new();
    public List<string> AllowedDomains { get; set; } = new();
    public List<string> AllowedServiceGroups { get; set; } = new();
    public List<int> AllowedExternalPorts { get; set; } = new();
    public int DnsMinimumQueries { get; set; } = 20;
    public int DnsNxDomainRatioPercent { get; set; } = 50;
    public int DnsLongQueryLength { get; set; } = 80;
    public int DnsLongQueryCount { get; set; } = 5;
}

public sealed class ExternalIntelligenceRecord
{
    public string Cidr { get; init; } = "";
    public string Country { get; init; } = "";
    public string Asn { get; init; } = "";
    public string Provider { get; init; } = "";
    public string Classification { get; init; } = "UNKNOWN";
    public int PrefixLength { get; init; }
    public uint Network { get; init; }
    public uint Mask { get; init; }

    public string Summary
    {
        get
        {
            var parts = new[] { Country, Asn, Provider, Classification }
                .Where(v => !string.IsNullOrWhiteSpace(v) && !string.Equals(v, "UNKNOWN", StringComparison.OrdinalIgnoreCase));
            return string.Join(" · ", parts);
        }
    }
}
