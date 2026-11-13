# WinRM-PtH-BOF

A standalone, C2-agnostic Beacon Object File (BOF) for executing commands over WinRM using NTLMv2 pass-the-hash authentication.

The BOF handles NTLM authentication, session signing and sealing, and encrypted WSMan communication directly in memory. No Mimikatz, SSPI, credential injection, or external executable is required.

An optional AxScript extension is included for AdaptixC2.

> For authorized security testing and research only.

## Features

- Native NTLMv2 pass-the-hash authentication using a supplied NT hash.
- NTLM MIC generation when required.
- Session signing, sealing, and encrypted WSMan communication.
- Remote command execution with output retrieval.
- No local process spawning or LSASS credential modification.
- Standalone x64 and x86 BOF builds.
- Optional AdaptixC2 integration supporting Beacon, Gopher, and Kharon agents.

## Requirements

- A C2 framework with a compatible BOF loader.
- MinGW-w64 (`x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`) for compilation.
- A target with WinRM enabled over HTTP (TCP 5985 by default).
- A valid NT hash for an account authorized to execute commands through WinRM.

**Note:** HTTPS/5986 is not currently supported.

## Build

Compile both architectures:

```bash
make
```

The compiled BOFs are generated in the `bin/` directory.

These objects are designed to work with compatible BOF loaders. Framework-specific argument handling may vary.

## AdaptixC2 Integration

AdaptixC2 support is provided through the included `winrm_pth.axs` script. This integration is optional and is not required by the BOF itself.

1. Compile the project using `make`.
2. Load `winrm_pth.axs` through **AxScript → Script Manager**.
3. Run `help winrm_pth` in your Windows agent console.

The script automatically selects the appropriate BOF for the agent architecture and registers `winrm_pth` as a standalone command without conflicting with the Extension Kit's `invoke` command.

## Usage

```text
winrm_pth <target> "<command>" DOMAIN\username <NT_HASH> [-t milliseconds] [-P port]
```

Example:

<img width="1141" height="390" alt="image" src="https://github.com/user-attachments/assets/4033f8d5-032e-4be3-91f7-29b8e60561d8" />

For local accounts, use the target computer name instead of the domain, such as `SERVER01\Administrator`.

The command shown above uses the optional AdaptixC2 integration. Other compatible C2 frameworks can execute the compiled BOF using their supported argument-packing and execution mechanisms.

## How It Works

The BOF performs the NTLMv2 authentication exchange using the supplied NT hash, then derives the session keys needed to protect WinRM communication.

WSMan requests are encrypted and signed using NTLM session security. Responses are decrypted and verified before processing.

Commands execute remotely through `cmd.exe /c`, with output returned to the agent. Response buffering is limited to 256 KiB.

WinHTTP automatic authentication and redirects are disabled for each request to avoid unintended credential use.

## Roadmap

###  PowerShell Remoting Fallback (PSRP)

- [ ] Automatically fall back to PowerShell when a verified `w:AccessDenied` SOAP fault occurs.
- [ ] Reuse existing NTLM authentication, signing/sealing, and WSMan transport.
- [ ] Implement PSRP runspace, pipeline execution, output handling, and cleanup.
- [ ] Preserve existing `cmd.exe /c` command behavior during fallback.
- [ ] Display which backend (CMD or PowerShell) executed the command.
- [ ] Prevent fallback on authentication (401), signature validation, or connection failures.

## References

- [MS-NLMP: NT LAN Manager Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-WSMV: Encrypted Data Layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/3fc54d8b-b087-486e-9f50-8253e9e30b43)
