using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public sealed class NetworkScanner
{
    private static readonly int[] IdentityProbePorts =
    {
        515, 548, 631, 873, 902, 903, 2049, 3260, 5000, 5001, 6281, 6690, 8006, 9100, 9443
    };
    public async Task ScanAsync(
        IReadOnlyList<IPAddress> hosts,
        IReadOnlyCollection<int> ports,
        int timeoutMs,
        int concurrency,
        ScanOptions options,
        IProgress<ScanResult> resultProgress,
        IProgress<(int Done, int Total)> scanProgress,
        IProgress<string>? startedProgress,
        IProgress<EngineTraceEntry>? traceProgress,
        CancellationToken cancellationToken)
    {
        int total = hosts.Count;
        int done = 0;

        using var gate = new SemaphoreSlim(concurrency, concurrency);
        var tasks = new List<Task>(total);

        foreach (var ip in hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await gate.WaitAsync(cancellationToken);

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    startedProgress?.Report(ip.ToString());
                    Trace(traceProgress, options, EngineTraceVerbosity.Raw, "HOST", ip, "worker start");
                    var result = await ScanHostAsync(ip, ports, timeoutMs, options, traceProgress, cancellationToken);
                    resultProgress.Report(result);
                }
                finally
                {
                    gate.Release();
                    int current = Interlocked.Increment(ref done);
                    scanProgress.Report((current, total));
                }
            }, CancellationToken.None));
        }

        await Task.WhenAll(tasks);
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static async Task<ScanResult> ScanHostAsync(
        IPAddress ip,
        IReadOnlyCollection<int> ports,
        int timeoutMs,
        ScanOptions options,
        IProgress<EngineTraceEntry>? traceProgress,
        CancellationToken cancellationToken)
    {
        bool pingOk = false;
        long? rtt = null;

        Trace(traceProgress, options, EngineTraceVerbosity.Raw, "ICMP", ip, $"CALL Ping.SendPingAsync(timeout={timeoutMs})");
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeoutMs);
            pingOk = reply.Status == IPStatus.Success;
            if (pingOk)
            {
                rtt = reply.RoundtripTime;
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "ICMP", ip, $"reply {rtt.Value} ms");
            }
            else
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "ICMP", ip, $"no reply · {reply.Status}");
            }
        }
        catch (Exception ex)
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Raw, "ICMP", ip, $"error · {ex.GetType().Name}");
        }

        var openPorts = new HashSet<int>();

        foreach (var port in ports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Trace(traceProgress, options, EngineTraceVerbosity.Raw, "TCP", ip, $"CALL TcpClient.ConnectAsync(:{port})");
            bool open = await IsTcpPortOpenAsync(ip, port, timeoutMs, cancellationToken);
            if (open)
            {
                openPorts.Add(port);
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "TCP", ip, $":{port} OPEN");
            }
            else
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "TCP", ip, $":{port} closed/filtered");
            }
        }

        bool preliminaryOnline = pingOk || openPorts.Count > 0;
        if (preliminaryOnline && options.ProbeDeviceIdentity)
        {
            var probePorts = IdentityProbePorts
                .Where(port => !ports.Contains(port) && !openPorts.Contains(port))
                .ToArray();

            if (probePorts.Length > 0)
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "IDENT", ip,
                    $"device identity probe · {probePorts.Length} ports");

                var probeTasks = probePorts.Select(async port =>
                {
                    bool isOpen = await IsTcpPortOpenAsync(ip, port, timeoutMs, cancellationToken);
                    return (Port: port, IsOpen: isOpen);
                }).ToArray();

                var probeResults = await Task.WhenAll(probeTasks);
                foreach (var probe in probeResults)
                {
                    if (probe.IsOpen)
                    {
                        openPorts.Add(probe.Port);
                        Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "IDENT", ip,
                            $":{probe.Port} OPEN · classification signal");
                    }
                    else
                    {
                        Trace(traceProgress, options, EngineTraceVerbosity.Raw, "IDENT", ip,
                            $":{probe.Port} closed/filtered");
                    }
                }
            }
        }

        bool smbDetected = openPorts.Contains(445) || openPorts.Contains(139);
        if (options.AuditSmbShares && !smbDetected)
        {
            if (!ports.Contains(445))
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "TCP", ip, "SMB probe · :445");
                if (await IsTcpPortOpenAsync(ip, 445, timeoutMs, cancellationToken))
                {
                    openPorts.Add(445);
                    smbDetected = true;
                    Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "TCP", ip, ":445 OPEN · SMB detected");
                }
            }

            if (!smbDetected && !ports.Contains(139))
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "TCP", ip, "SMB probe · :139");
                if (await IsTcpPortOpenAsync(ip, 139, timeoutMs, cancellationToken))
                {
                    openPorts.Add(139);
                    smbDetected = true;
                    Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "TCP", ip, ":139 OPEN · SMB detected");
                }
            }
        }

        bool online = pingOk || openPorts.Count > 0;
        string hostName = "";
        string mac = "";

        if (online && options.ResolveDns)
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Raw, "DNS", ip, "CALL Dns.GetHostEntryAsync()");
            try
            {
                var dnsTask = Dns.GetHostEntryAsync(ip);
                var completed = await Task.WhenAny(dnsTask, Task.Delay(Math.Max(250, timeoutMs), cancellationToken));
                if (completed == dnsTask)
                {
                    hostName = (await dnsTask).HostName;
                    if (!string.IsNullOrWhiteSpace(hostName))
                        Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "DNS", ip, hostName);
                }
                else
                {
                    Trace(traceProgress, options, EngineTraceVerbosity.Raw, "DNS", ip, "timeout");
                }
            }
            catch (Exception ex)
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "DNS", ip, $"error · {ex.GetType().Name}");
            }
        }

        if (online && options.ResolveMac)
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Raw, "ARP", ip, "CALL SendARP()");
            mac = NativeArpService.TryGetMacAddress(ip);
            if (!string.IsNullOrWhiteSpace(mac))
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "ARP", ip, mac);
            else
                Trace(traceProgress, options, EngineTraceVerbosity.Raw, "ARP", ip, "not resolved · routed subnet may be expected");
        }

        SmbShareAuditResult shareAudit = smbDetected
            ? new SmbShareAuditResult { SmbDetected = true, Attempted = false, Status = "SMB 감지" }
            : new SmbShareAuditResult();

        if (online && smbDetected && options.AuditSmbShares)
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SMB", ip, "share audit start");
            try
            {
                shareAudit = await SmbAuditService.AuditAsync(ip, options.TestGuestShareAccess, timeoutMs, cancellationToken);
                string shareSummary = shareAudit.EnumeratedShares.Count > 0
                    ? $"{shareAudit.Status} · shares {shareAudit.EnumeratedShares.Count}"
                    : shareAudit.Status;
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SMB", ip, shareSummary);

                if (shareAudit.GuestAccessibleShares.Count > 0)
                {
                    Trace(traceProgress, options, EngineTraceVerbosity.General, "ALERT", ip,
                        $"Guest access · {string.Join(", ", shareAudit.GuestAccessibleShares)}");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                shareAudit = new SmbShareAuditResult
                {
                    Attempted = true,
                    SmbDetected = true,
                    Status = "SMB 감사 오류"
                };
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SMB", ip, $"audit error · {ex.GetType().Name}");
            }
        }

        IppPrinterInfo ippInfo = new();
        if (online && options.QueryIppPrinterInfo && openPorts.Contains(631))
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "IPP", ip, "Get-Printer-Attributes start");
            try
            {
                ippInfo = await IppQueryService.QueryAsync(ip, timeoutMs, cancellationToken);
                Trace(traceProgress, options, ippInfo.Success ? EngineTraceVerbosity.General : EngineTraceVerbosity.Detailed,
                    "IPP", ip, ippInfo.Success ? $"identified · {ippInfo.Summary}" : ippInfo.Status);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                ippInfo = new IppPrinterInfo { Attempted = true, Success = false, Status = $"IPP 오류 · {ex.GetType().Name}" };
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "IPP", ip, ippInfo.Status);
            }
        }

        SnmpDeviceInfo snmpInfo = new();
        if (online && options.QuerySnmpDeviceInfo && !string.IsNullOrWhiteSpace(options.SnmpCommunity))
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SNMP", ip, "SNMP v2c read-only identity query start");
            try
            {
                snmpInfo = await SnmpQueryService.QueryAsync(ip, options.SnmpCommunity, timeoutMs, cancellationToken);
                Trace(traceProgress, options, snmpInfo.Success ? EngineTraceVerbosity.General : EngineTraceVerbosity.Detailed,
                    "SNMP", ip, snmpInfo.Success ? $"identified · {snmpInfo.Summary}" : snmpInfo.Status);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                snmpInfo = new SnmpDeviceInfo { Attempted = true, Success = false, Status = $"SNMP 오류 · {ex.GetType().Name}" };
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SNMP", ip, snmpInfo.Status);
            }
        }

        bool isGateway = !string.IsNullOrWhiteSpace(options.GatewayAddress) &&
                         string.Equals(ip.ToString(), options.GatewayAddress, StringComparison.OrdinalIgnoreCase);
        var classification = online
            ? DeviceTypeDetector.Analyze(ip, hostName, openPorts, options.GatewayAddress, shareAudit, ippInfo, snmpInfo)
            : new DeviceClassification { Type = DeviceType.Unknown, Confidence = 0 };

        bool routeCapableCandidate = isGateway || string.Equals(snmpInfo.IpForwarding, "1", StringComparison.Ordinal) || classification.Type is
            DeviceType.Router or DeviceType.Firewall or DeviceType.Switch or DeviceType.AccessPoint or DeviceType.WifiExtender;

        if (online && snmpInfo.Success && options.DiscoverNestedNetworks && routeCapableCandidate)
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SNMP", ip,
                "IPv4 interface / route table discovery start");
            try
            {
                snmpInfo = await SnmpQueryService.QueryNetworkTablesAsync(
                    ip, options.SnmpCommunity, timeoutMs, snmpInfo, cancellationToken);
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SNMP", ip,
                    snmpInfo.NetworkTablesStatus);
                classification = DeviceTypeDetector.Analyze(
                    ip, hostName, openPorts, options.GatewayAddress, shareAudit, ippInfo, snmpInfo);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "SNMP", ip,
                    $"network table discovery error · {ex.GetType().Name}");
            }
        }

        var deviceType = classification.Type;

        if (online)
        {
            string portsText = openPorts.Count > 0 ? string.Join(",", openPorts.OrderBy(p => p)) : "none";
            string evidenceText = classification.Evidence.Count > 0 ? $" · {classification.Evidence[0]}" : string.Empty;
            Trace(traceProgress, options, EngineTraceVerbosity.Detailed, "CLASSIFY", ip,
                $"{deviceType.ToDisplayName()} {classification.Confidence}% · ports {portsText}{evidenceText}");
            Trace(traceProgress, options, EngineTraceVerbosity.General, "ONLINE", ip,
                $"{deviceType.ToDisplayName()} · {(string.IsNullOrWhiteSpace(hostName) ? "host" : hostName)} · open {openPorts.Count}");
        }
        else
        {
            Trace(traceProgress, options, EngineTraceVerbosity.Raw, "OFFLINE", ip, "no ICMP/TCP response");
        }

        return new ScanResult
        {
            IsOnline = online,
            IpAddress = ip.ToString(),
            HostName = hostName,
            MacAddress = mac,
            RoundTripMs = rtt,
            OpenPortNumbers = openPorts.OrderBy(p => p).ToArray(),
            DeviceType = deviceType,
            ClassificationConfidence = classification.Confidence,
            ClassificationEvidence = classification.Evidence,
            IsGateway = isGateway,
            ShareAudit = shareAudit,
            IppInfo = ippInfo,
            SnmpInfo = snmpInfo
        };
    }

    private static void Trace(
        IProgress<EngineTraceEntry>? traceProgress,
        ScanOptions options,
        EngineTraceVerbosity minimumVerbosity,
        string category,
        IPAddress ip,
        string message)
    {
        // 모든 Trace 레벨을 수집하고, 화면에서 General/Detailed/RAW를 재필터링한다.
        // 그래야 스캔 중/완료 후 모드를 바꿔도 이전 이벤트를 즉시 다시 볼 수 있다.
        if (traceProgress is null)
            return;

        traceProgress.Report(new EngineTraceEntry
        {
            Timestamp = DateTime.Now,
            Category = category,
            IpAddress = ip.ToString(),
            Message = message,
            Verbosity = minimumVerbosity
        });
    }

    private static async Task<bool> IsTcpPortOpenAsync(
        IPAddress ip,
        int port,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient(ip.AddressFamily);
            var connectTask = client.ConnectAsync(ip, port);
            var timeoutTask = Task.Delay(timeoutMs, cancellationToken);
            var completed = await Task.WhenAny(connectTask, timeoutTask);

            if (completed != connectTask)
                return false;

            await connectTask;
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }
}
