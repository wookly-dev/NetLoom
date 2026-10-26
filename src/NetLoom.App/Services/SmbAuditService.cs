using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class SmbAuditService
{
    private const int ResourceTypeDisk = 1;
    private const int ConnectTemporary = 0x00000004;
    private const int MaxPreferredLength = -1;
    private const int NerrSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int ErrorSessionCredentialConflict = 1219;
    private const uint StypeDiskTree = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        public string? lpLocalName;
        public string? lpRemoteName;
        public string? lpComment;
        public string? lpProvider;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHARE_INFO_1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string shi1_netname;
        public uint shi1_type;
        [MarshalAs(UnmanagedType.LPWStr)] public string shi1_remark;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE lpNetResource, string? lpPassword, string? lpUserName, int dwFlags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string lpName, int dwFlags, bool fForce);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetShareEnum(
        string servername,
        int level,
        out IntPtr bufptr,
        int prefmaxlen,
        out int entriesread,
        out int totalentries,
        ref int resume_handle);

    [DllImport("Netapi32.dll", SetLastError = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);

    public static async Task<SmbShareAuditResult> AuditAsync(IPAddress ip, bool testGuestAccess, int timeoutMs, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SmbShareAuditResult
            {
                Attempted = false,
                SmbDetected = true,
                Status = "SMB 감사는 Windows에서만 지원"
            };
        }

        var task = Task.Run(() => AuditCore(ip, testGuestAccess), CancellationToken.None);
        var waitMs = Math.Clamp(timeoutMs * 5, 1800, 6500);
        var completed = await Task.WhenAny(task, Task.Delay(waitMs, cancellationToken));
        cancellationToken.ThrowIfCancellationRequested();
        if (completed != task)
        {
            return new SmbShareAuditResult
            {
                Attempted = true,
                SmbDetected = true,
                Status = "SMB 게스트 감사 시간 초과"
            };
        }

        return await task;
    }

    private static SmbShareAuditResult AuditCore(IPAddress ip, bool testGuestAccess)
    {
        string server = ip.ToString();
        string ipc = $@"\\{server}\IPC$";
        bool connectedByUs = false;

        try
        {
            var resource = new NETRESOURCE
            {
                dwType = ResourceTypeDisk,
                lpRemoteName = ipc
            };

            // 명시적인 Guest + 빈 암호만 시험한다. 패스워드 추측/반복 시도는 하지 않는다.
            int connectResult = WNetAddConnection2(ref resource, "", "Guest", ConnectTemporary);
            if (connectResult != 0)
            {
                string status = connectResult == ErrorSessionCredentialConflict
                    ? "기존 SMB 세션 충돌 · 게스트 미확인"
                    : "SMB · 인증 필요/게스트 차단";

                return new SmbShareAuditResult
                {
                    Attempted = true,
                    SmbDetected = true,
                    GuestSessionEstablished = false,
                    Status = status
                };
            }

            connectedByUs = true;
            var shares = EnumerateShares(server);
            var guestAccessible = new List<string>();

            if (testGuestAccess)
            {
                foreach (var share in shares.Where(s => !s.EndsWith('$')).Take(32))
                {
                    string path = $@"\\{server}\{share}";
                    try
                    {
                        // 루트 목록을 1개만 요청해 실제 Guest 읽기 가능 여부를 최소한으로 확인한다.
                        _ = Directory.EnumerateFileSystemEntries(path).Take(1).ToArray();
                        guestAccessible.Add(share);
                    }
                    catch (UnauthorizedAccessException)
                    {
                    }
                    catch (IOException)
                    {
                    }
                    catch
                    {
                    }
                }
            }

            return new SmbShareAuditResult
            {
                Attempted = true,
                SmbDetected = true,
                GuestSessionEstablished = true,
                EnumeratedShares = shares,
                GuestAccessibleShares = guestAccessible,
                Status = guestAccessible.Count > 0
                    ? "게스트 접근 가능 공유 발견"
                    : (shares.Count > 0 ? "공유 열거됨 · 게스트 루트 접근 차단" : "게스트 세션 허용 · 공유 미확인")
            };
        }
        catch (Exception ex)
        {
            return new SmbShareAuditResult
            {
                Attempted = true,
                SmbDetected = true,
                GuestSessionEstablished = connectedByUs,
                Status = $"SMB 감사 오류 · {ex.GetType().Name}"
            };
        }
        finally
        {
            if (connectedByUs)
            {
                try { _ = WNetCancelConnection2(ipc, 0, true); } catch { }
            }
        }
    }

    private static IReadOnlyList<string> EnumerateShares(string server)
    {
        var result = new List<string>();
        int resume = 0;

        while (true)
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int rc = NetShareEnum($@"\\{server}", 1, out buffer, MaxPreferredLength, out int read, out _, ref resume);
                if (rc != NerrSuccess && rc != ErrorMoreData)
                    break;

                if (buffer != IntPtr.Zero && read > 0)
                {
                    int size = Marshal.SizeOf<SHARE_INFO_1>();
                    var current = buffer;
                    for (int i = 0; i < read; i++)
                    {
                        var info = Marshal.PtrToStructure<SHARE_INFO_1>(current);
                        if ((info.shi1_type & 0xFFFF) == StypeDiskTree && !string.IsNullOrWhiteSpace(info.shi1_netname))
                            result.Add(info.shi1_netname);
                        current = IntPtr.Add(current, size);
                    }
                }

                if (rc != ErrorMoreData)
                    break;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    _ = NetApiBufferFree(buffer);
            }
        }

        return result.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
