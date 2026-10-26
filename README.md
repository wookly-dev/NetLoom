# NetLoom

Windows용 IPv4 네트워크 감사 도구입니다. 장비 검색, 포트·SMB·Wi-Fi 점검, 2D/3D 관계도,
통신 관찰과 HTML·CSV·JSON 보고서를 제공합니다. 프로그램 UI는 한국어입니다.

- 현재 버전: **0.7.5 무료 베타**
- [프로그램 안내 및 다운로드](https://wookly.dev/products/netloom/)
- [GitHub 저장소](https://github.com/wookly-dev/netloom)
- 대상: Windows 10 / 11 x64, .NET 8 WPF

## 빌드

Windows에 .NET 8 SDK를 설치한 뒤 실행합니다.

```powershell
dotnet build src/NetLoom.App/NetLoom.App.csproj -c Release
dotnet publish src/NetLoom.App/NetLoom.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

빌드 도우미 `build_release.bat`도 사용할 수 있습니다. SDK가 없으면 Microsoft의 설치 스크립트로
사용자 캐시에 SDK를 받습니다. 배포 결과는 `publish/NetLoom.exe`입니다. 앱은 관리자 권한을 요청합니다.

`SOURCE_MANIFEST.sha256`는 Git에 저장된 원본 바이트의 체크섬입니다. GitHub ZIP과 Windows
체크아웃은 `.bat` 파일을 CRLF로 변환할 수 있습니다. 체크섬을 비교할 때는 `git cat-file blob HEAD:파일경로`
출력이나 `.bat`의 줄바꿈을 LF로 정규화한 바이트를 사용하세요.

## 합성 회귀 검사

```powershell
dotnet run --project tests/NetLoom.Regression -c Release
dotnet run --project tests/NetLoom.WindowSmoke -c Release
```

회귀 검사는 합성 패킷·임시 CSV와 별도 WPF 테스트 창을 사용합니다. 네트워크 스캔이나 실제 패킷
수집은 수행하지 않습니다. 0.7.5에는 JSON 인증값 마스킹, HTTP 헤더 경계 유지와 CSV 수식 방지가 포함됩니다.

## 사용 범위

본인이 관리하거나 점검 권한을 받은 시스템에서만 사용하세요. Windows Raw Socket은 실행 PC에
노출된 IPv4 트래픽만 관찰합니다. HTTPS 본문 복호화·암호 추측·Wi-Fi 공격 기능은 없습니다.
SPAN/TAP 관측은 실제 미러링 및 Transit 패킷 확인이 필요하며 NIC/드라이버에 따라 지원되지 않을 수 있습니다.
관계도와 위험 점수는 추정과 점검 근거이며 물리 배선이나 악성 여부를 확정하지 않습니다.

설정·감사 기록은 `%LOCALAPPDATA%\WooklyDev\NetLoom`에 저장됩니다. 일반적인 인증값 패턴을
마스킹하지만 임의 형식의 모든 민감정보를 제거하지는 못합니다. 기록을 공유하기 전에 확인하세요.

코드 서명과 실제 SPAN/TAP·다중 어댑터·다양한 PC의 전체 회귀 검증은 완료되지 않았습니다.

## 저작권

Copyright © 2026 WooklyDev. All rights reserved.

소스 공개에 따라 별도의 오픈 소스 라이선스를 부여하지는 않습니다. 기존 저작권을 유지합니다.
배포 프로그램의 무료 사용 조건은 다운로드 ZIP의 `LICENSE.txt`를 확인하세요.

## English

NetLoom is a Windows IPv4 network auditing tool with a Korean interface. It includes device discovery,
port and SMB/Wi-Fi checks, 2D/3D topology, visible packet inspection and report exports.
Build on Windows with the .NET 8 SDK using the commands above. Audit only authorized networks.
Raw Socket coverage, inferred topology and heuristic risk findings have the limits described above.
This public source snapshot retains its existing copyright; no additional open source license is granted.
