# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SoftwareComplianceChecker — a Windows desktop app (C# / .NET 8 / WPF / MVVM) that audits a workstation against a configurable software compliance policy and produces a report. Fully offline, no installation, self-contained single executable, MIT.

**Status: greenfield.** At the time this file was written the repo contains only `.gitignore`, `README.md`, and this file. The specification below is the design contract; nothing is implemented yet.

**The path is misleading.** This lives under `~/UnityProjects/` but is **not** a Unity project. Global Unity/DOTS rules (asmdef, ECS, UnityMCP, `refresh_unity`, domain reload) do **not** apply here. Use the .NET toolchain.

## Commands

Development happens on Windows; the repo may be edited from Linux, but build/test/run require Windows (WPF + registry + WMI).

```powershell
dotnet restore
dotnet build -c Debug
dotnet run --project src/SoftwareComplianceChecker

dotnet test                                            # all tests
dotnet test --filter "FullyQualifiedName~RuleMatching" # one class / namespace
dotnet test --filter "Name=Matches_ContainsRule_IsCaseInsensitive"  # one test

# Single-file self-contained executable (primary deliverable)
dotnet publish src/SoftwareComplianceChecker -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

## Architecture

Clean Architecture + MVVM. Layering: `Views` → `ViewModels` → `Services` → `Core`. Dependencies point inward; `Core` (models, rule abstractions) references nothing outward. Composition happens once via `Microsoft.Extensions.DependencyInjection` in the `DependencyInjection` folder — services are constructor-injected, never resolved from a static locator.

Four modules, each behind an interface so it can be scanned, tested, and extended independently:

1. **Windows License Scanner** — WMI (`SoftwareLicensingProduct`, `SoftwareLicensingService`) + registry (`SoftwareProtectionPlatform`).
2. **Installed Software Scanner** — registry uninstall keys under `HKLM`, `HKCU`, and `WOW6432Node`.
3. **Portable Software Scanner** — depth-limited filesystem walk over folders from `portableFolders.json`.
4. **Report Generator** — HTML / CSV / JSON exporters behind one export abstraction.

Scanners produce raw findings; the **rule engine** — not the scanners — assigns PASS/FAIL. Keep detection and policy separate: a scanner that decides compliance is a design error.

### Rule engine (the core constraint)

Software policy is **data, never code**. All rules live in `rules.json`; adding or changing prohibited software must require only editing that file, with no recompilation. A hardcoded product name, publisher string, or executable name anywhere in C# is a defect.

Rules support: `Category`, match type (`Contains` / `StartsWith` / `EndsWith` / `Regex`), `Publisher`, executable name, folder name, multiple aliases, `Priority`, `Status`, `Reason`. **All matching is case-insensitive.** `Priority` resolves conflicts when several rules match one item.

### Compliance semantics

- **Exactly two states: PASS and FAIL. There is no warning state.** Do not introduce one.
- Presence alone fails. The app must **not** attempt to determine licensing, ownership, piracy, trial vs. paid, or educational vs. commercial status — and must not imply it in UI strings, reasons, or reports.
- Anything matching no rule **passes**. Default-allow, not default-deny.
- Default-prohibited categories: Adobe (all), JetBrains (all), Autodesk, Marmoset, Microsoft Office (all editions), WinRAR.

### Windows license detection — why this is more than an activation check

The naive check is wrong: **KMS-activated Windows reports itself as activated.** The scanner must gather corroborating evidence and weigh it, not read a single status flag:

- License status, activation channel, license description, partial product key
- Activation type: Retail / OEM / OEM_DM / OEM_COA / MAK / Volume / KMS
- Presence of an OEM BIOS key
- KMS server configuration (`KeyManagementServiceName`, `KeyManagementServicePort`)
- Activation expiry — an expiry near ~180 days is KMS evidence
- Traces of activation tools (KMSPico, AutoKMS, KMSAuto, AAct, KMSELDI) across services, scheduled tasks, registry, and typical install folders

KMS evidence → FAIL. Retail/OEM with no KMS evidence → PASS. Surface the collected evidence in the UI and reports, not just the verdict.

### Known pitfalls

- **Never use `Win32_Product`** for installed-software enumeration — it triggers MSI reconfiguration and is pathologically slow. Read the registry uninstall keys.
- Registry and filesystem access must be async and off the UI thread; the whole scan targets **under 10 seconds**. Portable scanning is the main risk — keep recursion depth bounded.
- Both 32- and 64-bit registry views must be read, or 32-bit installs on 64-bit Windows go undetected.
- FAIL rows sort before PASS rows in every view and export.

## Configuration

`appsettings.json`, `rules.json`, `portableFolders.json` ship alongside the executable and are user-editable. Treat them as a public contract: changing their schema is a breaking change and needs the sample files updated in the same commit.

Logs are written to `logs/yyyy-MM-dd.log` (scan duration, detected software, errors, performance metrics). The `logs/` directory is gitignored.

## Conventions

- XML documentation comments on all public APIs.
- Unit tests are mandatory for rule matching — it is the component where a silent regression changes compliance verdicts.
- Commits are authored by the repository owner only; do not add `Co-Authored-By` trailers.
