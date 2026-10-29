# VAJRA Windows Agent (`apps/windows-agent`)

**Status:** Foundation implementation (Prompt 0014)  
**Target:** .NET 8 Windows Worker Service (`net8.0-windows`)  
**Service name:** `VajraGuardService` (display: VAJRA Personal Security Guard)

This agent enrolls a Windows PC with the existing VAJRA backend using **ECDSA P-256**, signs Plane-2 requests with the same transcript format as `packages/security` (`VAJRA-DEVICE-AUTH-V1`), and supports heartbeat, pending-command polling, limited command execution (`REQUEST_DEVICE_STATUS`), and bounded event-log collection.

## Prerequisites

- Windows 10 22H2+ or Windows 11 (x64 or ARM64)
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build
- Reachable VAJRA API (`ServerBaseUrl`)
- Owner account in the web console to **initiate** and **confirm** enrollment

Optional for broader event logs: membership in **Event Log Readers** (Security log is not required for the initial collector).

## Build

```powershell
cd apps/windows-agent
dotnet restore
dotnet build -c Release
```

## Configuration

`appsettings.json` section `VajraAgent`, or environment:

| Variable | Purpose |
| :--- | :--- |
| `VAJRA_SERVER_BASE_URL` | Backend origin (e.g. `https://vajra.example.com`) |
| `VAJRA_DATA_DIRECTORY` | Override data dir (default `%ProgramData%\VAJRA\WindowsAgent`) |

**Private keys** are stored as DPAPI-protected PKCS#8 under the data directory (`device-key.bin`). They are never uploaded.

## Enrollment (manual, explicit)

1. In the web console: start enrollment for a **WINDOWS** device (Plane 1).
2. Note `deviceId`, `enrollmentToken`, and `challengeNonce` from the initiate response (token shown once).
3. On the Windows PC:

```powershell
dotnet run -- enroll --token <TOKEN> --device-id <UUID> --challenge-nonce <HEX>
```

4. In the console: **confirm** enrollment (Plane 1) so lifecycle becomes `TRUSTED`.
5. Run the agent; successful heartbeats mark the device online on the server.

```powershell
dotnet run -- status
dotnet run
```

## Install as a Windows Service (explicit)

Run elevated only when the owner chooses to install:

```powershell
sc.exe create VajraGuardService binPath= "C:\Path\To\Vajra.WindowsAgent.exe" start= demand
sc.exe description VajraGuardService "VAJRA Personal Security Guard — endpoint agent"
sc.exe start VajraGuardService
```

Uninstall:

```powershell
sc.exe stop VajraGuardService
sc.exe delete VajraGuardService
```

Do **not** use silent installers that hide the service. Stopping/uninstall uses standard SCM tools.

## Command capability matrix

| Action | Agent behavior |
| :--- | :--- |
| `REQUEST_DEVICE_STATUS` | **Supported** — returns OS/agent metadata via signed result |
| `REQUEST_LOCATION` | Rejected — no GPS claim |
| `RING_DEVICE` | Rejected — not applicable to PC in this version |
| `DISPLAY_RECOVERY_MESSAGE` | Rejected — no desktop lock UI yet |
| `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` | Rejected locally — server-side lifecycle only |
| Arbitrary shell / PowerShell from server | **Never implemented** |

## Event collection

- Allowlisted logs: **Application**, **System** (bounded query + checkpoint file)
- Types: agent start/stop, Windows event-log summaries
- Does **not** collect keystrokes, passwords, cookies, screenshots, mic/camera, or personal files
- Does **not** silently enable audit policies

## Network behavior

- All Plane-2 calls: headers `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`
- Fresh nonce per request; TLS validation **enabled** (default `HttpClient`)
- Server base URL comes from config/identity only — **not** from remote commands
- Backoff on failures; no tight spin loop

## Limitations

- Not built/run in CI environments without .NET Windows SDK
- Ed25519 not used (ECDSA P-256 matches backend `ECDSA_P256`)
- Full TPM non-exportable CNG keys are a documented enhancement path; current store uses DPAPI LocalMachine
- Android lost-mode / ring semantics are out of scope for this agent

## Protocol alignment (Prompt 0016)

- ECDSA signatures are converted from IEEE P1363 to **DER** before Base64 (Node `crypto.verify` compatibility).
- Request bodies are **canonical JSON** (sorted keys) before SHA-256, matching `canonicalJsonSerialize`.
- See `docs/architecture/device-protocol-matrix.md`.
