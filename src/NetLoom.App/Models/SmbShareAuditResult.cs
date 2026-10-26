namespace NetLoom.App.Models;

public sealed class SmbShareAuditResult
{
    public bool Attempted { get; init; }
    public bool SmbDetected { get; init; }
    public bool GuestSessionEstablished { get; init; }
    public string Status { get; init; } = "";
    public IReadOnlyList<string> EnumeratedShares { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> GuestAccessibleShares { get; init; } = Array.Empty<string>();

    public bool HasGuestAccessibleShare => GuestAccessibleShares.Count > 0;

    public string Summary
    {
        get
        {
            if (!SmbDetected) return "-";
            if (!Attempted) return "SMB 감지";
            if (HasGuestAccessibleShare)
                return $"공유 {EnumeratedShares.Count:N0} · 게스트 {GuestAccessibleShares.Count:N0}";
            if (GuestSessionEstablished)
                return EnumeratedShares.Count > 0 ? $"공유 {EnumeratedShares.Count:N0} · 게스트 차단" : "게스트 세션 허용 · 공유 미확인";
            return string.IsNullOrWhiteSpace(Status) ? "SMB · 인증 필요" : Status;
        }
    }
}
