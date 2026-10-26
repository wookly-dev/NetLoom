<p align="center">
  <img src="docs/assets/netloom-banner.svg" alt="NetLoom — Windows IPv4 network auditing" width="960">
</p>

<p align="center">
  <strong>내 네트워크의 장비와 연결을 한눈에 확인합니다.</strong><br>
  Windows용 네트워크 점검 · 2D/3D 관계도 · 통신 관찰 · 보고서
</p>

<p align="center">
  <a href="https://wookly.dev/products/netloom/">제품 안내 및 무료 다운로드</a> ·
  <a href="#시작하기">시작하기</a> ·
  <a href="#소스에서-빌드">소스에서 빌드</a> ·
  <a href="https://github.com/wookly-dev/NetLoom/issues">버그 제보</a>
</p>

---

## NetLoom

NetLoom은 Windows에서 관리 대상 IPv4 네트워크를 살펴보는 데스크톱 도구입니다.
장비 검색부터 점검 결과 정리까지 하나의 한국어 화면에서 진행할 수 있습니다.

| 기능 | 할 수 있는 일 |
|---|---|
| 장비 검색 | 네트워크의 IPv4 장비를 찾아 목록으로 확인합니다. |
| 서비스 점검 | 포트·SMB·Wi-Fi 관련 점검 정보를 확인합니다. |
| 관계도 | 장비와 통신 관계를 2D/3D로 살펴봅니다. |
| 통신 관찰 | 실행 PC에 노출되는 IPv4 통신을 관찰합니다. |
| 보고서 | 결과를 HTML·CSV·JSON으로 내보냅니다. |

**현재 배포: 0.7.5 무료 베타 · Windows 10/11 x64 · .NET 8 WPF**

## 시작하기

1. [제품 페이지](https://wookly.dev/products/netloom/)에서 Windows ZIP을 받습니다.
2. ZIP을 별도 폴더에 풀고, 함께 제공되는 안내와 사용권을 확인합니다.
3. `NetLoom.exe`를 실행합니다. 프로그램은 관리자 권한을 요청합니다.
4. 본인이 관리하거나 점검 권한을 받은 네트워크에서 사용합니다.

배포본은 .NET 런타임을 포함합니다. 코드 서명은 아직 적용되지 않았습니다.

### 관찰 결과를 해석할 때

- Windows Raw Socket은 실행 PC에 노출된 IPv4 트래픽만 관찰합니다.
- SPAN/TAP 관측은 실제 미러링 및 Transit 패킷 확인이 필요하며 NIC/드라이버에 따라 지원되지 않을 수 있습니다.
- 관계도와 위험 점수는 추정과 점검 근거입니다. 물리 배선이나 악성 여부를 확정하지 않습니다.
- HTTPS 본문 복호화·암호 추측·Wi-Fi 공격 기능은 없습니다.
- 실제 SPAN/TAP·다중 어댑터·다양한 PC를 대상으로 한 전체 검증은 완료되지 않았습니다.

## 개인정보와 제보

설정·감사 기록은 `%LOCALAPPDATA%\WooklyDev\NetLoom`에 저장됩니다.
일반적인 인증값 패턴을 마스킹하지만 모든 민감정보를 제거한다고 보장하지는 않습니다.

공개 이슈에는 **합성 예제와 재현 순서**를 사용해 주세요. 실제 패킷, 인증정보, 개인 이름,
사용자 폴더 경로, 내부 장비명·주소, 고객 자료가 담긴 로그나 화면은 첨부하지 마세요.
취약점 제보는 [보안 안내](SECURITY.md)를 확인해 주세요.

## 소스에서 빌드

Windows에 .NET 8 SDK를 설치한 뒤 저장소 루트에서 실행합니다.

```powershell
git clone https://github.com/wookly-dev/NetLoom.git
cd NetLoom
dotnet build src/NetLoom.App/NetLoom.App.csproj -c Release
dotnet publish src/NetLoom.App/NetLoom.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

빌드 결과는 `publish/NetLoom.exe`입니다. `build_release.bat`도 사용할 수 있습니다.
이 도우미는 SDK가 없으면 Microsoft의 설치 스크립트로 사용자 캐시에 SDK를 받습니다.

### 합성 회귀 검사

```powershell
dotnet run --project tests/NetLoom.Regression -c Release
dotnet run --project tests/NetLoom.WindowSmoke -c Release
```

검사는 합성 패킷·임시 CSV와 별도 WPF 테스트 창을 사용합니다. 네트워크 스캔이나 실제 패킷
수집은 수행하지 않습니다. 0.7.5에는 JSON 인증값 마스킹, HTTP 헤더 경계 유지와 CSV 수식 방지가 포함됩니다.

`SOURCE_MANIFEST.sha256`는 Git에 저장된 원본 바이트의 체크섬입니다. GitHub ZIP과 Windows
체크아웃은 `.bat` 파일을 CRLF로 변환할 수 있습니다. 비교할 때는 `git cat-file blob HEAD:파일경로`
출력이나 `.bat`의 줄바꿈을 LF로 정규화한 바이트를 사용하세요.

## 공개 범위와 저작권

Copyright © 2026 WooklyDev. All rights reserved.

이 저장소는 제품 소스를 열람할 수 있도록 공개합니다. 별도의 오픈소스 라이선스를 부여하지 않으며,
기존 저작권을 유지합니다. 배포 프로그램의 무료 사용 조건은 다운로드 ZIP의 `LICENSE.txt`를 확인하세요.
개발자가 제공하는 Windows 배포본과 안내는 [공식 제품 페이지](https://wookly.dev/products/netloom/)에서 확인할 수 있습니다.

## English

NetLoom is a Windows IPv4 network auditing tool with a Korean interface. Discover devices,
review port/SMB/Wi-Fi findings, explore 2D/3D topology, inspect visible traffic and export reports.

The current release is a **free 0.7.5 beta for Windows 10/11 x64**. Audit only authorized networks.
Raw Socket coverage, inferred topology and heuristic findings have the limits described above.
Code signing and comprehensive physical SPAN/TAP validation are pending.

Use synthetic examples in public reports; do not attach captures, credentials or personal/customer data.
This public source retains its existing copyright; no additional open source license is granted.
