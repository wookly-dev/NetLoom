using System.IO;
using System.Net;
using System.Text;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class AuditReportService
{
    private static readonly HashSet<int> DatabasePorts = new() { 1433, 1521, 3306, 5432, 6379, 9200, 27017 };

    public static IReadOnlyList<AuditFinding> BuildFindings(IEnumerable<ScanResult> results)
    {
        var findings = new List<AuditFinding>();

        foreach (var r in results.Where(x => x.IsOnline))
        {
            var ports = r.OpenPortNumbers.ToHashSet();

            if (r.ShareAudit.HasGuestAccessibleShare)
            {
                findings.Add(new AuditFinding
                {
                    Severity = "HIGH",
                    Category = "공유폴더",
                    IpAddress = r.IpAddress,
                    Title = "게스트 무자격 접근 가능 공유폴더 발견",
                    Evidence = string.Join(", ", r.ShareAudit.GuestAccessibleShares),
                    Recommendation = "Guest/Everyone 권한과 공유 ACL을 재검토하고 인증 사용자만 접근하도록 제한"
                });
            }

            if (ports.Contains(23))
            {
                findings.Add(new AuditFinding
                {
                    Severity = "HIGH",
                    Category = "원격관리",
                    IpAddress = r.IpAddress,
                    Title = "Telnet 서비스 노출",
                    Evidence = "TCP/23 OPEN",
                    Recommendation = "Telnet을 비활성화하고 SSH 또는 관리망 전용 접근으로 전환"
                });
            }

            if (ports.Contains(21))
            {
                findings.Add(new AuditFinding
                {
                    Severity = "MEDIUM",
                    Category = "파일전송",
                    IpAddress = r.IpAddress,
                    Title = "FTP 서비스 노출",
                    Evidence = "TCP/21 OPEN",
                    Recommendation = "평문 FTP 사용 여부를 확인하고 SFTP/FTPS 등 암호화 전송 방식 검토"
                });
            }

            if (ports.Contains(3389))
            {
                findings.Add(new AuditFinding
                {
                    Severity = "MEDIUM",
                    Category = "원격관리",
                    IpAddress = r.IpAddress,
                    Title = "RDP 서비스 노출",
                    Evidence = "TCP/3389 OPEN",
                    Recommendation = "관리망/방화벽 허용 대역 제한, NLA 및 계정 정책 확인"
                });
            }

            var db = ports.Where(DatabasePorts.Contains).OrderBy(x => x).ToArray();
            if (db.Length > 0)
            {
                findings.Add(new AuditFinding
                {
                    Severity = "MEDIUM",
                    Category = "데이터베이스",
                    IpAddress = r.IpAddress,
                    Title = "데이터베이스 서비스 포트 노출",
                    Evidence = string.Join(", ", db.Select(p => $"TCP/{p}")),
                    Recommendation = "업무상 필요한 서버/대역만 접근 가능하도록 방화벽과 DB bind 정책 확인"
                });
            }

            if (ports.Contains(445) && !r.ShareAudit.HasGuestAccessibleShare)
            {
                findings.Add(new AuditFinding
                {
                    Severity = "LOW",
                    Category = "SMB",
                    IpAddress = r.IpAddress,
                    Title = "SMB 서비스 노출",
                    Evidence = $"TCP/445 OPEN · {r.ShareAudit.Summary}",
                    Recommendation = "불필요한 장비의 SMB 비활성화 및 파일서버 접근 대역 제한 검토"
                });
            }

            if (ports.Contains(9100) && r.DeviceType == DeviceType.Printer)
            {
                findings.Add(new AuditFinding
                {
                    Severity = "LOW",
                    Category = "프린터",
                    IpAddress = r.IpAddress,
                    Title = "RAW Printing 포트 노출",
                    Evidence = "TCP/9100 OPEN",
                    Recommendation = "프린터 VLAN/ACL 적용 및 관리 페이지/출력 포트 접근 범위 확인"
                });
            }

            if (ports.Contains(5060) || ports.Contains(5061))
            {
                findings.Add(new AuditFinding
                {
                    Severity = "INFO",
                    Category = "VoIP",
                    IpAddress = r.IpAddress,
                    Title = "SIP 서비스 감지",
                    Evidence = string.Join(", ", ports.Where(p => p is 5060 or 5061).OrderBy(p => p).Select(p => $"TCP/{p}")),
                    Recommendation = "전화기/PBX 전용 VLAN, 관리 인터페이스 접근제어 및 기본 계정 사용 여부 확인"
                });
            }
        }

        return findings
            .OrderBy(f => SeverityOrder(f.Severity))
            .ThenBy(f => f.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Category, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    public static async Task GenerateHtmlAsync(
        string path,
        IReadOnlyList<ScanResult> results,
        AuditReportContext context,
        byte[]? topologyPng)
    {
        var findings = BuildFindings(results);
        var coverage = context.CaptureCoverage ?? CaptureCoverageSnapshot.Empty;
        var topologySignificance = TopologySignificanceService.Build(
            context.ExternalObservation ?? ExternalObservationSnapshot.Empty,
            context.SecurityRelationship ?? SecurityRelationshipSnapshot.Empty,
            coverage,
            context.IncludeLowSignificanceExternalTopology,
            context.ExcludeSensorHostTopologyConnections);
        int online = results.Count(r => r.IsOnline);
        int guestExposure = results.Count(r => r.ShareAudit.HasGuestAccessibleShare);
        int high = findings.Count(f => f.Severity == "HIGH") + (context.WifiAudit?.HighCount ?? 0) + (context.SecurityRelationship?.HighCount ?? 0);
        int medium = findings.Count(f => f.Severity == "MEDIUM") + (context.WifiAudit?.MediumCount ?? 0) + (context.SecurityRelationship?.MediumCount ?? 0);
        int low = findings.Count(f => f.Severity == "LOW");

        var deviceGroups = results.Where(r => r.IsOnline)
            .GroupBy(r => r.DeviceLabel)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();

        var rangeGroups = results
            .GroupBy(r => new
            {
                Label = string.IsNullOrWhiteSpace(r.AuditGroupLabel) ? "대역 A" : r.AuditGroupLabel,
                Expression = r.AuditGroupExpression ?? string.Empty
            })
            .OrderBy(g => g.Key.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();

        var resultByIp = results
            .GroupBy(r => r.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        string topologyHtml = topologyPng is { Length: > 0 }
            ? $"<img class='topology' alt='NetLoom network topology' src='data:image/png;base64,{Convert.ToBase64String(topologyPng)}'>"
            : "<div class='empty'>관계도 이미지 없음</div>";

        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang='ko'><head><meta charset='utf-8'>")
          .Append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
          .Append("<title>네트워크 감사 보고서</title>")
          .Append("<style>")
          .Append("body{font-family:'Segoe UI','Malgun Gothic',sans-serif;background:#f4f5f7;color:#202124;margin:0;padding:28px}")
          .Append(".page{max-width:1180px;margin:0 auto;background:#fff;border:1px solid #ddd}")
          .Append("header{background:#111;color:#fff;padding:24px 28px;border-bottom:4px solid #FAD83B;display:flex;align-items:flex-start;justify-content:space-between;gap:18px}")
          .Append("h1{font-size:23px;margin:0 0 6px}header p{margin:0;color:#bbb;font-size:13px}.report-actions{display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap;justify-content:flex-end}.company-editor{display:flex;flex-direction:column;gap:4px}.company-editor label{font-size:9px;color:#999}.company-input{width:210px;box-sizing:border-box;border:1px solid #555;background:#1b1b1b;color:#fff;border-radius:5px;padding:8px 10px;font-size:12px;outline:none}.company-input:focus{border-color:#FAD83B}.print-btn{appearance:none;border:1px solid #FAD83B;background:#FAD83B;color:#171717;border-radius:5px;padding:9px 14px;font-weight:700;font-size:12px;cursor:pointer}.print-btn:hover{background:#ffe469}")
          .Append("main{padding:26px 28px}.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 24px;font-size:12px;color:#555;margin-bottom:20px}.meta div{white-space:pre-line}")
          .Append(".cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:14px 0 26px}")
          .Append(".card{border:1px solid #ddd;padding:13px;background:#fafafa}.card b{display:block;font-size:22px;color:#111}.card span{font-size:11px;color:#666}")
          .Append("h2{font-size:16px;margin:28px 0 10px;border-left:4px solid #FAD83B;padding-left:9px}h3{font-size:12px;margin:18px 0 7px;color:#333}.range-badge{display:inline-block;background:#2a2616;color:#665812;border:1px solid #c7ad34;border-radius:4px;padding:3px 7px;margin-right:7px;font-size:10px}.range-expression{color:#666;font-weight:400}")
          .Append("table{border-collapse:collapse;width:100%;font-size:11px}th,td{border:1px solid #ddd;padding:7px 8px;text-align:left;vertical-align:top}th{background:#f0f1f2;white-space:nowrap}.ip-main{font-weight:600;color:#222}.ip-host{display:block;margin-top:2px;color:#777;font-size:9.5px;max-width:180px;overflow-wrap:anywhere}.wifi-ok{color:#16794b;font-weight:700}.wifi-high{color:#b91c1c;font-weight:700}.wifi-medium{color:#b45309;font-weight:700}")
          .Append(".sev{font-weight:700}.HIGH{color:#b91c1c}.MEDIUM{color:#b45309}.WATCH{color:#92730a}.NORMAL{color:#475569}.LOW{color:#475569}.INFO{color:#0369a1}")
          .Append(".topology{width:100%;height:auto;border:1px solid #ddd;background:#171717}.empty{padding:28px;border:1px dashed #bbb;color:#777;text-align:center}")
          .Append(".nested-ok{color:#16794b;font-weight:700}.nested-warn{color:#9a6b00;font-weight:700}.traffic-live{color:#16794b;font-weight:700}.note{background:#fff9df;border:1px solid #e6d47e;padding:12px;font-size:11px;line-height:1.55;margin-top:22px}")
          .Append("footer{padding:18px 28px;color:#777;font-size:10px;border-top:1px solid #ddd}")
          .Append("@media print{body{background:#fff;padding:0}.page{border:0;max-width:none}header{-webkit-print-color-adjust:exact;print-color-adjust:exact}.report-actions{display:none!important}.cards{break-inside:avoid}table{font-size:9px}}")
          .Append("</style></head><body><div class='page'>")
          .Append("<header><div><h1 id='reportCompanyTitle'>감사 대상 업체</h1><p>네트워크 전산 감사 보고서 · 자산 및 서비스 노출 점검</p></div><div class='report-actions'><div class='company-editor'><label for='companyNameInput'>출력 업체명</label><input id='companyNameInput' class='company-input' type='text' value='감사 대상 업체' maxlength='80' placeholder='업체명 입력'></div><button class='print-btn' type='button' onclick='window.print()'>인쇄 / PDF</button></div></header><main>");

        sb.Append("<div class='meta'>")
          .Append(Meta("스캔 시작", context.ScanStartedAt == default ? "-" : context.ScanStartedAt.ToString("yyyy-MM-dd HH:mm:ss")))
          .Append(Meta("소요 시간", $"{context.ScanDuration.TotalSeconds:0.0} sec"))
          .Append(Meta("어댑터", context.AdapterDisplay))
          .Append(Meta("Gateway", context.GatewayAddress))
          .Append(Meta("검색 범위", context.TargetExpression))
          .Append(Meta("선택 TCP 포트", string.Join(", ", context.SelectedPorts)))
          .Append(Meta("패킷 센서", coverage.ModeText))
          .Append(Meta("관측 상태", coverage.CoverageStateText))
          .Append("</div>");

        sb.Append("<div class='cards'>")
          .Append(Card(online, "ONLINE 장비"))
          .Append(Card(high, "HIGH"))
          .Append(Card(medium, "MEDIUM"))
          .Append(Card(low, "LOW"))
          .Append(Card(guestExposure, "게스트 공유 노출"))
          .Append(Card(results.Count, "처리 주소"))
          .Append("</div>");

        sb.Append("<div class='note'>").Append(H(BuildCaptureCoverageReportNote(coverage))).Append("</div>");

        sb.Append("<h2>감사 대역별 요약</h2><table><thead><tr><th>그룹</th><th>감사 대역</th><th>처리 IP</th><th>ONLINE</th><th>포트 노출 장비</th><th>게스트 공유</th></tr></thead><tbody>");
        foreach (var g in rangeGroups)
        {
            sb.Append("<tr><td><span class='range-badge'>").Append(H(g.Key.Label)).Append("</span></td>")
              .Append("<td>").Append(H(g.Key.Expression)).Append("</td>")
              .Append("<td>").Append(g.Count()).Append("</td>")
              .Append("<td>").Append(g.Count(r => r.IsOnline)).Append("</td>")
              .Append("<td>").Append(g.Count(r => r.OpenPortNumbers.Count > 0)).Append("</td>")
              .Append("<td>").Append(g.Count(r => r.HasGuestShareExposure)).Append("</td></tr>");
        }
        sb.Append("</tbody></table>");

        if (context.NestedNetworks.Count > 0)
        {
            sb.Append("<h2>하위 네트워크 자동 발견</h2>")
              .Append("<div class='note' style='margin-top:0'>SNMP가 허용된 라우팅 장비의 IPv4 인터페이스/라우팅 테이블과 Windows 라우팅 정보를 비교한 결과입니다. 대역이 발견되었다고 해서 현재 감사 PC에서 반드시 접근 가능한 것은 아닙니다.</div>")
              .Append("<table><thead><tr><th>상위 장비</th><th>하위 대역</th><th>상태</th><th>인터페이스/Next Hop</th><th>발견 근거</th></tr></thead><tbody>");
            foreach (var n in context.NestedNetworks.OrderBy(n => ParseIp(n.ParentIp)).ThenBy(n => n.Cidr, StringComparer.OrdinalIgnoreCase))
            {
                string cls = n.IsRouteConfirmed ? "nested-ok" : "nested-warn";
                string routePath = !string.IsNullOrWhiteSpace(n.InterfaceAddress)
                    ? $"Interface {n.InterfaceAddress}"
                    : !string.IsNullOrWhiteSpace(n.NextHop) ? $"Next Hop {n.NextHop}" : "-";
                sb.Append("<tr><td><span class='ip-main'>").Append(H(n.ParentIp)).Append("</span>")
                  .Append(string.IsNullOrWhiteSpace(n.ParentHost) ? "" : $"<span class='ip-host'>{H(n.ParentHost)}</span>")
                  .Append("</td><td>").Append(H(n.Cidr)).Append("</td><td class='").Append(cls).Append("'>").Append(H(n.ReachabilityText)).Append("</td>")
                  .Append("<td>").Append(H(routePath)).Append("</td><td>").Append(H(n.Reason)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        if (context.TrafficSnapshot is { TotalCapturedPackets: > 0 } traffic)
        {
            sb.Append("<h2>실시간 통신 캡처 스냅샷</h2>")
              .Append("<div class='meta'>")
              .Append("<div><b>누적 관찰 패킷</b><br>").Append(traffic.TotalCapturedPackets.ToString("N0")).Append("</div>")
              .Append("<div><b>누적 관찰 바이트</b><br>").Append(H(FormatBytes(traffic.TotalCapturedBytes))).Append("</div>")
              .Append("<div><b>생성 시점 속도</b><br><span class='traffic-live'>").Append(H(traffic.CurrentRateText)).Append(" · ").Append(traffic.CurrentPacketsPerSecond.ToString("0.#")).Append(" pkt/s</span></div>")
              .Append("<div><b>활성 IP</b><br>").Append(traffic.Nodes.Count(n => n.Value.IsActive)).Append("</div></div>");

            var active = traffic.Nodes.Values.Where(n => n.IsActive).OrderByDescending(n => n.TotalBytesPerSecond).Take(20).ToArray();
            if (active.Length > 0)
            {
                sb.Append("<table><thead><tr><th>IP</th><th>Rx</th><th>Tx</th><th>Packets/s</th><th>최근 프로토콜</th></tr></thead><tbody>");
                foreach (var n in active)
                {
                    sb.Append("<tr><td>").Append(H(n.IpAddress)).Append("</td><td>").Append(H(FormatRate(n.RxBytesPerSecond))).Append("</td>")
                      .Append("<td>").Append(H(FormatRate(n.TxBytesPerSecond))).Append("</td><td>").Append(n.TotalPacketsPerSecond.ToString("0.#")).Append("</td>")
                      .Append("<td>").Append(H(string.IsNullOrWhiteSpace(n.LastProtocol) ? "-" : n.LastProtocol + (n.LastPort.HasValue ? $"/{n.LastPort.Value}" : ""))).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }
            sb.Append("<div class='note'>").Append(H(BuildCaptureCoverageReportNote(coverage))).Append(" 패킷 본문은 저장하지 않습니다.</div>");
        }

        if (context.TrafficAuditSession is { HasData: true } auditSession)
        {
            sb.Append("<h2>통신 감사 기록</h2>")
              .Append("<div class='note' style='margin-top:0'>기록 시작/종료 구간에 관찰된 IPv4 헤더 기반 통신 메타데이터입니다. '누가'는 사용자 계정이 아니라 관찰된 IP/스캔 호스트명을 의미하며 패킷 본문은 저장하지 않습니다.</div>")
              .Append("<div class='meta'>")
              .Append("<div><b>시작</b><br>").Append(H(auditSession.StartedText)).Append("</div>")
              .Append("<div><b>종료</b><br>").Append(H(auditSession.EndedText)).Append("</div>")
              .Append("<div><b>지속시간</b><br>").Append(H(auditSession.DurationText)).Append("</div>")
              .Append("<div><b>패킷 / 데이터</b><br>").Append(auditSession.TotalPackets.ToString("N0")).Append(" / ").Append(H(auditSession.TotalBytesText)).Append("</div>")
              .Append("<div><b>고유 흐름 / IP</b><br>").Append(auditSession.UniqueFlowCount.ToString("N0")).Append(" / ").Append(auditSession.UniqueNodeCount.ToString("N0")).Append("</div></div>");

            var auditFlows = auditSession.Flows.OrderByDescending(f => f.Bytes).ThenByDescending(f => f.Packets).Take(100).ToArray();
            if (auditFlows.Length > 0)
            {
                sb.Append("<table><thead><tr><th>최초</th><th>최근</th><th>출발지</th><th>목적지</th><th>서비스</th><th>연결시도</th><th>패킷</th><th>데이터</th></tr></thead><tbody>");
                foreach (var f in auditFlows)
                {
                    resultByIp.TryGetValue(f.SourceIp, out var srcResult);
                    resultByIp.TryGetValue(f.DestinationIp, out var dstResult);
                    string src = string.IsNullOrWhiteSpace(srcResult?.HostName) ? f.SourceIp : $"{f.SourceIp} · {srcResult!.HostName}";
                    string dst = string.IsNullOrWhiteSpace(dstResult?.HostName) ? f.DestinationIp : $"{f.DestinationIp} · {dstResult!.HostName}";
                    sb.Append("<tr><td>").Append(H(f.FirstSeenText)).Append("</td><td>").Append(H(f.LastSeenText)).Append("</td>")
                      .Append("<td>").Append(H(src)).Append("</td><td>").Append(H(dst)).Append("</td>")
                      .Append("<td>").Append(H(f.ServiceText)).Append("</td><td>").Append(f.ConnectionStarts.ToString("N0")).Append("</td><td>").Append(f.Packets.ToString("N0")).Append("</td><td>").Append(H(f.BytesText)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }
            sb.Append("<div class='note'>").Append(H(BuildCaptureCoverageReportNote(coverage))).Append(" 통신 감사 기록은 이 관측 범위에서 실제로 수집된 패킷만 포함합니다.</div>");
        }

        if (context.SecurityRelationship is { HasData: true } security)
        {
            sb.Append("<h2>관계도 보안 감사</h2>")
              .Append("<div class='note' style='margin-top:0'>패킷 트레이서와 동일한 수동 관찰 메타데이터를 이용해 외부 Fan-out, 신규 목적지, 장시간 흐름, 외부 주의 포트, Host/Port Sweep과 함께 장비별 시간대 Baseline 편차, 주기적 Beaconing 후보, 내부 관리포트 확산(횡적 이동 후보), DNS 이상 패턴, 로컬 정책/Offline CIDR intelligence, 송신 편중을 평가합니다. HIGH/MEDIUM/WATCH는 악성 판정이 아니라 조사 대상 선별용 휴리스틱입니다.</div>")
              .Append("<div class='meta'>")
              .Append("<div><b>분석 패킷 / 데이터</b><br>").Append(security.TotalPackets.ToString("N0")).Append(" / ").Append(H(FormatBytes(security.TotalBytes))).Append("</div>")
              .Append("<div><b>의심 노드</b><br>").Append(security.SuspiciousNodeCount.ToString("N0")).Append("개</div>")
              .Append("<div><b>위험 등급</b><br>HIGH ").Append(security.HighCount).Append(" · MEDIUM ").Append(security.MediumCount).Append(" · WATCH ").Append(security.WatchCount).Append("</div>")
              .Append("<div><b>의심 관계 / 발견사항</b><br>").Append(security.SuspiciousFlows.Count.ToString("N0")).Append(" / ").Append(security.Findings.Count.ToString("N0")).Append("</div>")
              .Append("<div><b>Baseline 준비 / 이탈</b><br>").Append(security.BaselineReadyCount.ToString("N0")).Append(" / ").Append(security.BaselineAnomalyCount.ToString("N0")).Append("</div>")
              .Append("<div><b>Beacon / 횡적 이동 후보</b><br>").Append(security.BeaconNodeCount.ToString("N0")).Append(" / ").Append(security.LateralMovementNodeCount.ToString("N0")).Append("</div>")
              .Append("<div><b>DNS 이상 / Intel Suspicious</b><br>").Append(security.DnsAnomalyNodeCount.ToString("N0")).Append(" / ").Append(security.IntelSuspiciousNodeCount.ToString("N0")).Append("</div></div>");

            var suspiciousNodes = security.Nodes
                .Where(n => n.RiskScore >= 25)
                .OrderByDescending(n => n.RiskScore)
                .ThenByDescending(n => n.ExternalBytes)
                .Take(60)
                .ToArray();
            if (suspiciousNodes.Length > 0)
            {
                sb.Append("<h3>조사 우선 노드</h3><table><thead><tr><th>등급</th><th>IP</th><th>외부 Peer / Fan-out</th><th>5분 외부 데이터</th><th>Baseline</th><th>DNS</th><th>정책 / Intel</th><th>Beacon</th><th>내부 확산</th><th>Host/Port Sweep</th><th>판단 근거</th></tr></thead><tbody>");
                foreach (var n in suspiciousNodes)
                {
                    resultByIp.TryGetValue(n.IpAddress, out var matchedResult);
                    sb.Append("<tr><td class='sev ").Append(H(n.RiskLevel)).Append("'>").Append(H(n.RiskLevel)).Append(" ").Append(n.RiskScore).Append("</td>")
                      .Append("<td><span class='ip-main'>").Append(H(n.IpAddress)).Append("</span>")
                      .Append(string.IsNullOrWhiteSpace(matchedResult?.HostName) ? "" : $"<span class='ip-host'>{H(matchedResult!.HostName)}</span>")
                      .Append("</td><td>").Append(n.ExternalPeerCount).Append(" peer · ").Append(n.FanOutExternalCount).Append(" fan-out · 신규 ").Append(n.RecentNewExternalCount).Append("</td>")
                      .Append("<td>").Append(H(FormatBytes(n.ExternalBytes5m))).Append(" · 송신 ").Append(n.UploadRatioPercent.ToString("0.0")).Append("%</td>")
                      .Append("<td>").Append(H(n.BaselineText)).Append("</td>")
                      .Append("<td>").Append(H(n.DnsAnomalyText)).Append("</td>")
                      .Append("<td>").Append(H($"{n.PolicyText} · Intel S {n.ExternalIntelSuspiciousCount} / W {n.ExternalIntelWatchCount}")).Append("</td>")
                      .Append("<td>").Append(H(n.BeaconCandidateCount > 0 ? $"{n.BeaconText} · {n.BeaconConfidenceScore}/100" : "-")).Append("</td>")
                      .Append("<td>").Append(n.LateralMovementTargetCount).Append(" targets</td>")
                      .Append("<td>").Append(n.HostSweepTargetCount).Append(" hosts / ").Append(n.PortSweepPortCount).Append(" ports</td>")
                      .Append("<td>").Append(H(string.Join(" · ", n.Reasons))).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }
            else
            {
                sb.Append("<div class='empty'>현재 누적 구간에서 WATCH 이상으로 분류된 내부 노드가 없습니다.</div>");
            }

            if (security.Findings.Count > 0)
            {
                sb.Append("<h3>보안 관계 발견사항</h3><table><thead><tr><th>등급</th><th>IP</th><th>탐지 항목</th><th>근거</th><th>권고</th></tr></thead><tbody>");
                foreach (var f in security.Findings.Take(100))
                {
                    resultByIp.TryGetValue(f.IpAddress, out var matchedResult);
                    sb.Append("<tr><td class='sev ").Append(H(f.Severity)).Append("'>").Append(H(f.Severity)).Append("</td>")
                      .Append("<td><span class='ip-main'>").Append(H(f.IpAddress)).Append("</span>")
                      .Append(string.IsNullOrWhiteSpace(matchedResult?.HostName) ? "" : $"<span class='ip-host'>{H(matchedResult!.HostName)}</span>")
                      .Append("</td><td>").Append(H(f.Title)).Append("</td><td>").Append(H(f.Evidence)).Append("</td><td>").Append(H(f.Recommendation)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }

            if (security.BeaconCandidates.Count > 0)
            {
                sb.Append("<h3>주기적 Beaconing 후보</h3><table><thead><tr><th>내부 장비</th><th>외부 목적지</th><th>서비스</th><th>관측</th><th>주기</th><th>Jitter</th><th>Confidence</th><th>관측 구간</th></tr></thead><tbody>");
                foreach (var b in security.BeaconCandidates.Take(100))
                {
                    resultByIp.TryGetValue(b.InternalIp, out var matchedResult);
                    string internalLabel = string.IsNullOrWhiteSpace(matchedResult?.HostName) ? b.InternalIp : $"{b.InternalIp} · {matchedResult!.HostName}";
                    sb.Append("<tr><td>").Append(H(internalLabel)).Append("</td><td>").Append(H(b.ExternalIp)).Append(":").Append(b.DestinationPort?.ToString() ?? "-").Append("</td>")
                      .Append("<td>").Append(H(b.ServiceText)).Append("</td><td>").Append(b.ObservationCount.ToString("N0")).Append("</td><td>").Append(H(b.IntervalText)).Append("</td>")
                      .Append("<td>").Append(b.JitterPercent.ToString("0.0")).Append("%</td><td>").Append(b.ConfidenceScore).Append("/100</td>")
                      .Append("<td>").Append(H(b.FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"))).Append(" ~ ").Append(H(b.LastSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"))).Append("</td></tr>");
                }
                sb.Append("</tbody></table><div class='note'>주기적 통신은 정상 에이전트, 업데이트, 모니터링 heartbeat에서도 발생합니다. 후보는 TCP 연결 시작 시각의 반복성과 jitter를 기준으로 한 감사용 신호이며 C2 판정이 아닙니다.</div>");
            }

            var suspiciousFlows = security.SuspiciousFlows
                .OrderByDescending(f => f.RiskScore)
                .ThenByDescending(f => f.Bytes)
                .Take(100)
                .ToArray();
            if (suspiciousFlows.Length > 0)
            {
                sb.Append("<h3>의심 통신 관계</h3><table><thead><tr><th>등급</th><th>출발지</th><th>목적지</th><th>서비스</th><th>지속</th><th>연결시도</th><th>패킷</th><th>데이터</th><th>근거</th></tr></thead><tbody>");
                foreach (var f in suspiciousFlows)
                {
                    resultByIp.TryGetValue(f.SourceIp, out var srcResult);
                    resultByIp.TryGetValue(f.DestinationIp, out var dstResult);
                    string src = string.IsNullOrWhiteSpace(srcResult?.HostName) ? f.SourceIp : $"{f.SourceIp} · {srcResult!.HostName}";
                    string dst = string.IsNullOrWhiteSpace(dstResult?.HostName) ? f.DestinationIp : $"{f.DestinationIp} · {dstResult!.HostName}";
                    sb.Append("<tr><td class='sev ").Append(H(f.RiskLevel)).Append("'>").Append(H(f.RiskLevel)).Append(" ").Append(f.RiskScore).Append("</td>")
                      .Append("<td>").Append(H(src)).Append("</td><td>").Append(H(dst)).Append("</td><td>").Append(H(f.ServiceText)).Append("</td>")
                      .Append("<td>").Append(H(f.DurationText)).Append("</td><td>").Append(f.ConnectionStarts.ToString("N0")).Append("</td><td>").Append(f.Packets.ToString("N0")).Append("</td>")
                      .Append("<td>").Append(H(f.BytesText)).Append("</td><td>").Append(H(f.Reason)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }

            sb.Append("<div class='note'>").Append(H(BuildCaptureCoverageReportNote(coverage))).Append(" Baseline은 위험 징후가 낮은 관찰 구간을 장비/IP 및 로컬 시간대별로 학습합니다. Allowlist와 Offline intelligence는 분석가가 관리하는 로컬 자료이므로 범위/출처/갱신 시점을 함께 감사하십시오.</div>");
        }

        if (context.ExternalObservation is { } externalObservation && externalObservation.Nodes.Count > 0)
        {
            var groups = externalObservation.Nodes
                .GroupBy(n => string.IsNullOrWhiteSpace(n.ServiceGroup) ? "Unknown" : n.ServiceGroup, StringComparer.CurrentCultureIgnoreCase)
                .OrderBy(g => string.Equals(g.Key, "Unknown", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
                .ThenByDescending(g => g.Sum(n => n.Bytes))
                .ToArray();

            sb.Append("<h2>외부 통신 서비스 그룹 (관측 이력)</h2>")
              .Append("<div class='note' style='margin-top:0'>").Append(H(BuildExternalObservationReportNote(coverage)))
              .Append(" 관계도는 Significant Flow Rendering을 적용하여 중요 ").Append(topologySignificance.RenderedNodeCount.ToString("N0"))
              .Append(" / 관측 ").Append(topologySignificance.ObservedNodeCount.ToString("N0"))
              .Append(" 외부 노드를 표시하고 저중요 ").Append(topologySignificance.SuppressedNodeCount.ToString("N0"))
              .Append("개를 화면에서만 억제합니다. ")
              .Append(context.ExcludeSensorHostTopologyConnections
                  ? $"관계도 표시 옵션에 따라 NetLoom 실행 PC의 passive External/Public 연결 {topologySignificance.SensorHostSuppressedFlowCount:N0} Flow를 시각화에서 제외했습니다. "
                  : "")
              .Append("아래 관측 이력 표와 보안 분석 데이터는 억제된 Flow까지 원본 메타데이터를 유지합니다. 패킷에서 수동으로 관찰된 TLS SNI 또는 HTTP Host 이름으로 Microsoft/Google/AWS/Cloudflare 등 서비스 그룹을 분류합니다. 국가/ASN/Provider는 자동 인터넷 조회하지 않으며, 분석가가 로컬 external-intelligence.csv에 제공한 CIDR 레코드가 있을 때만 보강됩니다.</div>")
              .Append("<table><thead><tr><th>서비스 그룹</th><th>외부 IP</th><th>패킷</th><th>데이터</th><th>관찰 Host 예시</th></tr></thead><tbody>");
            foreach (var group in groups)
            {
                string hosts = string.Join(", ", group.Select(n => n.ObservedHost).Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8));
                sb.Append("<tr><td>").Append(H(group.Key)).Append("</td><td>").Append(group.Count().ToString("N0")).Append("</td><td>").Append(group.Sum(n => n.Packets).ToString("N0")).Append("</td>")
                  .Append("<td>").Append(H(FormatBytes(group.Sum(n => n.Bytes)))).Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(hosts) ? "-" : hosts)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");

            if (topologySignificance.ExternalNodes.Count > 0)
            {
                sb.Append("<h3>관계도 중요 External Flow</h3><table><thead><tr><th>중요도</th><th>외부 IP</th><th>서비스</th><th>대표 내부 Peer</th><th>내부 Peer 수</th><th>데이터</th><th>표시 근거</th></tr></thead><tbody>");
                foreach (var d in topologySignificance.ExternalNodes.Take(80))
                {
                    string level = d.ForceVisible ? "SECURITY" : d.Score >= 55 ? "HIGH SIGNAL" : "SIGNIFICANT";
                    sb.Append("<tr><td>").Append(H(level)).Append(" ").Append(d.Score).Append("</td><td>").Append(H(d.Node.IpAddress)).Append("</td>")
                      .Append("<td>").Append(H(string.IsNullOrWhiteSpace(d.Node.ObservedHost) ? d.Node.ServiceGroup : $"{d.Node.ServiceGroup} · {d.Node.ObservedHost}")).Append("</td>")
                      .Append("<td>").Append(H(string.IsNullOrWhiteSpace(d.PrimaryPeerIp) ? "-" : d.PrimaryPeerIp)).Append("</td><td>").Append(d.InternalPeerCount.ToString("N0")).Append("</td>")
                      .Append("<td>").Append(H(d.Node.BytesText)).Append("</td><td>").Append(H(d.Reason)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }

            var intelNodes = externalObservation.Nodes
                .Where(n => !string.IsNullOrWhiteSpace(n.Country) || !string.IsNullOrWhiteSpace(n.Asn) || !string.IsNullOrWhiteSpace(n.Provider) ||
                            !string.Equals(n.IntelligenceClassification, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(n => string.Equals(n.IntelligenceClassification, "SUSPICIOUS", StringComparison.OrdinalIgnoreCase) ? 2 : string.Equals(n.IntelligenceClassification, "WATCH", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
                .ThenByDescending(n => n.Bytes)
                .Take(100)
                .ToArray();
            if (intelNodes.Length > 0)
            {
                sb.Append("<h3>Offline External Intelligence</h3><table><thead><tr><th>외부 IP</th><th>국가</th><th>ASN</th><th>Provider</th><th>분류</th><th>서비스/Host</th><th>데이터</th></tr></thead><tbody>");
                foreach (var n in intelNodes)
                {
                    sb.Append("<tr><td>").Append(H(n.IpAddress)).Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(n.Country) ? "-" : n.Country)).Append("</td>")
                      .Append("<td>").Append(H(string.IsNullOrWhiteSpace(n.Asn) ? "-" : n.Asn)).Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(n.Provider) ? "-" : n.Provider)).Append("</td>")
                      .Append("<td>").Append(H(n.IntelligenceClassification)).Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(n.ObservedHost) ? n.ServiceGroup : $"{n.ServiceGroup} · {n.ObservedHost}")).Append("</td>")
                      .Append("<td>").Append(H(n.BytesText)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }
        }

        sb.Append("<h2>감사 주요 발견사항</h2>");
        if (findings.Count == 0)
        {
            sb.Append("<div class='empty'>현재 선택한 감사 항목에서는 주요 발견사항이 없습니다.</div>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>등급</th><th>대역</th><th>분류</th><th>IP</th><th>발견사항</th><th>근거</th><th>권고</th></tr></thead><tbody>");
            foreach (var f in findings)
            {
                resultByIp.TryGetValue(f.IpAddress, out var matchedResult);
                sb.Append("<tr><td class='sev ").Append(H(f.Severity)).Append("'>").Append(H(f.Severity)).Append("</td>")
                  .Append("<td>").Append(H(matchedResult?.AuditGroupLabel ?? "-")).Append("</td>")
                  .Append("<td>").Append(H(f.Category)).Append("</td><td><span class='ip-main'>").Append(H(f.IpAddress)).Append("</span>")
                  .Append(string.IsNullOrWhiteSpace(matchedResult?.HostName) ? "" : $"<span class='ip-host'>{H(matchedResult!.HostName)}</span>")
                  .Append("</td><td>").Append(H(f.Title)).Append("</td><td>").Append(H(f.Evidence)).Append("</td><td>").Append(H(f.Recommendation)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        if (context.WifiAudit is { Supported: true } wifi)
        {
            sb.Append("<h2>Wi-Fi 보안 점검</h2>")
              .Append("<div class='meta'>")
              .Append("<div><b>어댑터</b><br>").Append(H(wifi.AdapterName)).Append(" · ").Append(H(wifi.AdapterDescription)).Append("</div>")
              .Append("<div><b>점검 시각</b><br>").Append(H(wifi.AuditedAt.ToString("yyyy-MM-dd HH:mm:ss"))).Append("</div>")
              .Append("<div><b>현재 연결</b><br>").Append(H(wifi.CurrentNetwork is null ? "연결 정보 없음" : $"{wifi.CurrentNetwork.Ssid} · {wifi.CurrentNetwork.Authentication}/{wifi.CurrentNetwork.Cipher} · {wifi.CurrentNetwork.SignalQuality}%")).Append("</div>")
              .Append("<div><b>주변 SSID</b><br>").Append(wifi.Networks.Count).Append("개 · HIGH ").Append(wifi.HighCount).Append(" · MEDIUM ").Append(wifi.MediumCount).Append("</div>")
              .Append("</div>");

            sb.Append("<table><thead><tr><th>연결</th><th>SSID</th><th>신호</th><th>인증</th><th>암호화</th><th>평가</th></tr></thead><tbody>");
            foreach (var network in wifi.Networks)
            {
                var gradeClass = network.SecurityGrade == "HIGH" ? "wifi-high" : network.SecurityGrade == "MEDIUM" ? "wifi-medium" : "wifi-ok";
                sb.Append("<tr><td>").Append(network.IsConnected ? "현재" : "").Append("</td><td>").Append(H(network.Ssid)).Append("</td>")
                  .Append("<td>").Append(network.SignalQuality).Append("%</td><td>").Append(H(network.Authentication)).Append("</td><td>").Append(H(network.Cipher)).Append("</td>")
                  .Append("<td class='").Append(gradeClass).Append("'>").Append(H(network.SecurityGrade)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");

            if (wifi.Findings.Count > 0)
            {
                sb.Append("<h3>Wi-Fi 발견사항</h3><table><thead><tr><th>등급</th><th>SSID</th><th>발견사항</th><th>근거</th><th>권고</th></tr></thead><tbody>");
                foreach (var wf in wifi.Findings)
                {
                    sb.Append("<tr><td class='sev ").Append(H(wf.Severity)).Append("'>").Append(H(wf.Severity)).Append("</td><td>").Append(H(wf.Ssid)).Append("</td>")
                      .Append("<td>").Append(H(wf.Title)).Append("</td><td>").Append(H(wf.Evidence)).Append("</td><td>").Append(H(wf.Recommendation)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }

            sb.Append("<div class='note'>Wi-Fi 점검은 Windows WLAN API가 제공하는 주변 SSID, 인증 방식, 암호화 방식, 신호 정보만 사용합니다. 비밀번호 추측, 핸드셰이크 캡처, 인증 우회 또는 침투 시험은 수행하지 않습니다.</div>");
        }

        sb.Append("<h2>장치 유형 분포</h2><table><thead><tr><th>장치 유형</th><th>수량</th></tr></thead><tbody>");
        foreach (var g in deviceGroups)
            sb.Append("<tr><td>").Append(H(g.Key)).Append("</td><td>").Append(g.Count()).Append("</td></tr>");
        sb.Append("</tbody></table>");

        var identified = results.Where(r => r.IsOnline && r.HasProtocolIdentity).OrderBy(r => r.AuditGroupLabel).ThenBy(r => ParseIp(r.IpAddress)).ToArray();
        sb.Append("<h2>프로토콜 장비 식별</h2>");
        if (identified.Length == 0)
        {
            sb.Append("<div class='empty'>IPP/SNMP로 확인된 장비 정보가 없습니다.</div>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>대역</th><th>IP / 호스트</th><th>분류</th><th>확인 소스</th><th>식별 정보</th><th>위치/상태</th></tr></thead><tbody>");
            foreach (var r in identified)
            {
                var sources = new List<string>();
                if (r.IppInfo.Success) sources.Add("IPP");
                if (r.SnmpInfo.Success) sources.Add("SNMP");
                string identity = r.IppInfo.Success && !string.IsNullOrWhiteSpace(r.IppInfo.MakeAndModel)
                    ? r.IppInfo.MakeAndModel
                    : r.SnmpInfo.Success && !string.IsNullOrWhiteSpace(r.SnmpInfo.SysDescr) ? r.SnmpInfo.SysDescr : r.ProtocolIdentitySummary;
                var detail = new List<string>();
                if (!string.IsNullOrWhiteSpace(r.IppInfo.Location)) detail.Add($"IPP Location: {r.IppInfo.Location}");
                if (!string.IsNullOrWhiteSpace(r.IppInfo.PrinterState)) detail.Add($"Printer: {r.IppInfo.PrinterState}");
                if (!string.IsNullOrWhiteSpace(r.SnmpInfo.SysLocation)) detail.Add($"SNMP Location: {r.SnmpInfo.SysLocation}");
                if (!string.IsNullOrWhiteSpace(r.SnmpInfo.SysUptime)) detail.Add($"Uptime: {r.SnmpInfo.SysUptime}");
                sb.Append("<tr><td>").Append(H(r.AuditGroupLabel)).Append("</td><td><span class='ip-main'>").Append(H(r.IpAddress)).Append("</span>")
                  .Append(string.IsNullOrWhiteSpace(r.HostName) ? "" : $"<span class='ip-host'>{H(r.HostName)}</span>")
                  .Append("</td><td>").Append(H(r.ClassificationDisplay)).Append("</td><td>").Append(H(string.Join(" + ", sources))).Append("</td><td>")
                  .Append(H(identity)).Append("</td><td>").Append(H(string.Join(" · ", detail))).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        sb.Append("<h2>SMB 공유폴더 감사</h2><table><thead><tr><th>대역</th><th>IP</th><th>호스트</th><th>장치</th><th>상태</th><th>열거된 공유</th><th>게스트 접근 가능</th></tr></thead><tbody>");
        foreach (var r in results.Where(r => r.ShareAudit.SmbDetected || r.OpenPortNumbers.Contains(445) || r.OpenPortNumbers.Contains(139)))
        {
            sb.Append("<tr><td>").Append(H(r.AuditGroupLabel)).Append("</td><td>").Append(H(r.IpAddress)).Append("</td><td>").Append(H(r.HostName)).Append("</td><td>").Append(H(r.DeviceLabel)).Append("</td>")
              .Append("<td>").Append(H(r.ShareAudit.Summary)).Append("</td><td>").Append(H(string.Join(", ", r.ShareAudit.EnumeratedShares))).Append("</td>")
              .Append("<td>").Append(H(string.Join(", ", r.ShareAudit.GuestAccessibleShares))).Append("</td></tr>");
        }
        sb.Append("</tbody></table>");

        sb.Append("<h2>자산 및 서비스 목록</h2>");
        foreach (var group in rangeGroups)
        {
            sb.Append("<h3><span class='range-badge'>").Append(H(group.Key.Label)).Append("</span><span class='range-expression'>")
              .Append(H(group.Key.Expression)).Append("</span></h3>")
              .Append("<table><thead><tr><th>상태</th><th>장치</th><th>IP</th><th>호스트명</th><th>MAC</th><th>RTT</th><th>열린 TCP 포트</th><th>프로토콜 식별</th><th>공유 감사</th></tr></thead><tbody>");

            foreach (var r in group.OrderByDescending(r => r.IsOnline).ThenBy(r => ParseIp(r.IpAddress)))
            {
                sb.Append("<tr><td>").Append(H(r.Status)).Append("</td><td>").Append(H(r.DeviceLabel)).Append("</td><td>").Append(H(r.IpAddress)).Append("</td>")
                  .Append("<td>").Append(H(r.HostName)).Append("</td><td>").Append(H(r.MacAddress)).Append("</td><td>").Append(H(r.RoundTripDisplay)).Append("</td>")
                  .Append("<td>").Append(H(r.OpenPorts)).Append("</td><td>").Append(H(r.ProtocolIdentitySummary)).Append("</td><td>").Append(H(r.ShareAudit.Summary)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        sb.Append("<h2>추정 네트워크 관계도</h2>").Append(topologyHtml)
          .Append("<div class='note'><b>판정 주의</b><br>")
          .Append("본 보고서는 ICMP, TCP Connect, DNS, ARP, IPP, 선택적 SNMP v2c 및 제한적인 SMB Guest 접근 확인 결과를 기반으로 한 감사 보조자료입니다. 열린 포트만으로 취약점이 확정되는 것은 아니며, 장치 유형과 관계도는 휴리스틱 추정입니다. ")
          .Append("특히 실제 L2 배선/스위치 포트 관계는 SNMP·LLDP·CDP·MAC Address Table 연동 전에는 확정하지 않습니다. SNMP 인터페이스/라우팅 테이블에서 하위 대역을 발견할 수 있지만, 현재 감사 PC의 경로가 확인되지 않은 대역은 존재 확인과 실제 스캔 가능 여부를 구분합니다. 라우팅이 허용된 다른 서브넷은 TCP/DNS/SMB 감사가 가능하지만, 원격 서브넷의 MAC/ARP 정보는 직접 확인되지 않거나 신뢰할 수 없을 수 있습니다. 실시간 통신은 수동적인 IP 헤더 관찰이며 패킷 본문을 저장하지 않습니다. SMB 검사는 비밀번호 추측을 하지 않고 명시적인 Guest + 빈 암호 접근만 1회 확인합니다.</div>")
          .Append("</main><footer>© 2026 <span id='reportCompanyFooter'>감사 대상 업체</span> · Internal Network Audit Report</footer></div>")
          .Append("<script>(function(){const input=document.getElementById('companyNameInput');const title=document.getElementById('reportCompanyTitle');const footer=document.getElementById('reportCompanyFooter');function apply(){const name=(input.value||'').trim()||'감사 대상 업체';title.textContent=name;footer.textContent=name;document.title=name+' 네트워크 감사 보고서';}input.addEventListener('input',apply);window.addEventListener('beforeprint',apply);apply();})();</script></body></html>");

        await File.WriteAllTextAsync(path, sb.ToString(), new UTF8Encoding(false));
    }

    private static string BuildCaptureCoverageReportNote(CaptureCoverageSnapshot coverage)
    {
        if (coverage.Mode == PacketCaptureScopeMode.LocalHost)
        {
            return coverage.AllowLocalExternalTopology
                ? "관측 범위: LOCAL HOST. 실행 PC 기준 외부 통신을 제한적으로 표시하도록 사용자가 예외 옵션을 켰습니다. 다른 사내 장비의 외부 연결이 0으로 보이더라도 안전 또는 미통신으로 해석하면 안 됩니다."
                : "관측 범위: LOCAL HOST. 일반 스위칭 환경에서 실행 PC 외 다른 장비의 외부 Unicast 전체를 관측하지 못하므로 passive External/Public 관계도 상세를 숨겼습니다. 외부 연결 0은 안전 판정이 아니라 미관측일 수 있습니다.";
        }

        if (coverage.IsSpanVerified)
            return $"관측 범위: SPAN/TAP 확인. 실행 PC와 무관한 Transit {coverage.TransitPackets:N0}개, 외부 Transit {coverage.TransitExternalPackets:N0}개, 내부 호스트 {coverage.TransitInternalHostCount:N0}개가 실제로 관찰되어 passive External/Public 관계도 표시가 활성화되었습니다.";

        return $"관측 범위: SPAN/TAP 설정 상태이나 Transit 검증이 완료되지 않았습니다(Transit {coverage.TransitPackets:N0}개). 미러링이 확인되기 전까지 passive External/Public 관계도 상세를 숨기며, 외부 연결 0을 안전 판정으로 해석하면 안 됩니다.";
    }

    private static string BuildExternalObservationReportNote(CaptureCoverageSnapshot coverage)
    {
        if (coverage.CanRenderObservedExternalTopology)
            return "아래 표는 센서가 실제로 관찰해 세션 이력에 남긴 외부 통신입니다. 관계도에서도 현재 관측 정책에 따라 표시할 수 있습니다.";

        return "아래 표는 세션에 수집된 원시 외부 관측 이력이며, 현재 센서 관측 범위가 전체망 외부 관계를 대표하지 않으므로 2D/3D 관계도에서는 passive 외부 노드를 숨긴 상태입니다.";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024 * 1024) return $"{bytes / (1024d * 1024 * 1024):0.00} GB";
        if (bytes >= 1024L * 1024) return $"{bytes / (1024d * 1024):0.00} MB";
        if (bytes >= 1024) return $"{bytes / 1024d:0.0} KB";
        return $"{bytes:N0} B";
    }

    private static string FormatRate(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024d * 1024) return $"{bytesPerSecond / (1024d * 1024):0.0} MB/s";
        if (bytesPerSecond >= 1024d) return $"{bytesPerSecond / 1024d:0.0} KB/s";
        return $"{bytesPerSecond:0} B/s";
    }

    private static int SeverityOrder(string value) => value switch
    {
        "HIGH" => 0,
        "MEDIUM" => 1,
        "LOW" => 2,
        _ => 3
    };

    private static string Meta(string label, string value) => $"<div><b>{H(label)}</b> · {H(string.IsNullOrWhiteSpace(value) ? "-" : value)}</div>";
    private static string Card(int value, string label) => $"<div class='card'><b>{value:N0}</b><span>{H(label)}</span></div>";
    private static string H(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static uint ParseIp(string value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return uint.MaxValue;
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return uint.MaxValue;
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
