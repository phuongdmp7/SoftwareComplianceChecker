# Implementation Plan

Plan of record for building SoftwareComplianceChecker per the specification in [CLAUDE.md](../CLAUDE.md).

## Environment findings (verified, not assumed)

Measured on this machine before planning:

| Question | Result |
| --- | --- |
| .NET SDK | 9.0.316 only — no .NET 8 SDK installed |
| Can SDK 9 target `net8.0-windows`? | Yes |
| Can WPF **compile** on Linux? | **Yes**, with `<EnableWindowsTargeting>true</EnableWindowsTargeting>`. XAML compilation succeeds. |
| Can WPF **run** on Linux? | No. Runtime and live scanning require Windows. |
| Registry (`Microsoft.Win32.Registry`) + WMI (`System.Management`) on `net8.0-windows` | Compile on Linux; throw at runtime off-Windows |
| MaterialDesignThemes / HandyControl restore | Both succeed (5.3.2 / 3.5.1) |

**Consequence:** every project compiles and every unit test runs on this Linux machine. Only UI rendering and live scans need Windows, deferred to a single validation pass at the end.

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Target framework | `net8.0-windows` | Spec requires .NET 8. SDK 9 targets it fine. |
| Project layout | Multi-project solution | The spec lists folders; separate projects make the Clean Architecture boundary *enforced* by the compiler rather than conventional, and let the domain be tested without WPF. Spec folder names become folders inside these projects. |
| UI library | MaterialDesignThemes 5.3.2 (MIT) | Dark theme, cards, chips, DataGrid styling out of the box. HandyControl is the fallback. |
| MVVM plumbing | CommunityToolkit.Mvvm (MIT) | Source-generated `ObservableProperty` / `RelayCommand`; avoids hand-rolled `INotifyPropertyChanged` across dozens of view models. |
| Test framework | xUnit + Shouldly (both MIT) | **Not FluentAssertions** — v8+ requires a paid commercial license, which violates the no-commercial-dependencies constraint. |
| Logging | Microsoft.Extensions.Logging + small custom file provider | The `logs/yyyy-MM-dd.log` requirement is ~60 lines; avoids taking a logging framework dependency. |
| Trimming | Off | WPF does not trim reliably. Single-file + self-contained only. |

## Solution layout

```
SoftwareComplianceChecker.sln
src/
  SoftwareComplianceChecker.Core/        Models, enums, abstractions. No dependencies.
  SoftwareComplianceChecker.Rules/       Rule engine, rules.json loading + validation.
  SoftwareComplianceChecker.Scanning/    Windows license, installed, portable scanners.
  SoftwareComplianceChecker.Export/      HTML / CSV / JSON exporters.
  SoftwareComplianceChecker.App/         WPF: Views, ViewModels, DI composition root.
tests/
  SoftwareComplianceChecker.Tests/       xUnit.
config/                                  appsettings.json, rules.json, portableFolders.json
```

Dependency direction: `App → Export, Scanning, Rules → Core`. `Core` references nothing. Nothing but `App` references WPF.

## Phases

### Phase 1 — Foundation
Solution and projects, `Directory.Build.props` (nullable enable, warnings-as-errors, `EnableWindowsTargeting`), DI composition root, configuration binding, file logger, `.editorconfig`.

**Verify:** `dotnet build` clean.

### Phase 2 — Core + rule engine
Domain models (`ComplianceStatus` with exactly `Pass`/`Fail`, `SoftwareItem`, `ScanFinding`, `WindowsLicenseInfo`, `ComplianceReport`), scanner/engine/exporter interfaces. Rule model and matcher: contains / starts-with / ends-with / regex, publisher, executable name, folder name, aliases, priority, status, reason. Case-insensitive throughout. Highest priority wins; no match yields Pass.

`rules.json` is validated on load and fails loudly with actionable messages — a malformed policy file must never silently degrade into "everything passes".

User-supplied regex runs with `RegexOptions.NonBacktracking` or an explicit timeout to prevent a catastrophic-backtracking hang from a bad rule.

Author the default `rules.json` covering Adobe, JetBrains, Autodesk, Marmoset, Microsoft Office, WinRAR.

**Verify:** unit tests — every match type, case-insensitivity, priority resolution, aliases, unmatched-passes, malformed-file rejection.

### Phase 3 — Scanners
All Windows API access sits behind thin interfaces (`IRegistryReader`, `IWmiQuery`, `IFileSystem`) so decision logic is testable with fakes on Linux.

- **Installed** — uninstall keys across `HKLM`/`HKCU` × 32/64-bit views. Skip system components and update entries. Deduplicate by name+version+publisher. Never `Win32_Product`.
- **Portable** — bounded-depth enumeration of configured folders, `IgnoreInaccessible`, matched against executable-name rules.
- **Windows license** — evidence aggregation, not a status flag read: `SoftwareLicensingProduct` (filtered to the Windows application ID, non-null partial key) and `SoftwareLicensingService` via WMI; `SoftwareProtectionPlatform` registry; KMS server name/port; grace period near ~180 days; activation-tool traces across services, scheduled tasks, registry, and install folders. Verdict is a pure function over collected evidence — directly unit-testable.

Scanners run concurrently via `Task.WhenAll` against the under-10-second budget. Missing permissions degrade to a logged partial result rather than a crash.

**Verify:** unit tests over fakes for each scanner's decision logic; concurrency and cancellation honored.

### Phase 4 — Export
`IReportExporter` per format. HTML is self-contained with inline dark CSS; CSV follows RFC 4180 quoting; JSON via `System.Text.Json`. Every report carries computer name, user, OS, scan time, license details, both software sections, summary counts, and final result.

Sample reports are generated from a fixture dataset by a test, so the committed samples are real output rather than hand-written approximations.

### Phase 5 — WPF UI
Dark dashboard: summary cards (overall result, total checks, pass, fail), three sections, rows showing status icon, name, publisher, version, location, reason, expandable for detail. Search plus pass/fail/category/publisher filters via `ICollectionView`. FAIL sorts before PASS everywhere. Scanning is async off the UI thread with progress and cancellation.

### Phase 6 — Packaging and docs
`win-x64` publish profile (single file, self-contained, `IncludeNativeLibrariesForSelfExtract`). Config JSON files copy next to the executable rather than embedding, since they are meant to be user-edited. README updated from "in development" to real usage.

### Phase 7 — Windows validation
Run on Windows 10/11: verify UI renders, bindings resolve, scan completes under 10 seconds, license detection is correct on a known-Retail and a known-KMS machine, exports open correctly, single-file executable runs on a clean machine.

## Risks

| Risk | Mitigation |
| --- | --- |
| XAML binding errors only appear at runtime — invisible on Linux | Keep bindings simple and view models flat; budget real time for Phase 7 |
| WMI/registry behavior can't be exercised here | Windows access behind interfaces; logic tested with fakes; real data confirmed in Phase 7 |
| Activation-tool detection risks false positives (e.g. a file merely *named* like a tool) | Require corroboration, record every evidence item in the report, keep detection patterns in `rules.json` |
| Some reads (scheduled tasks) may need elevation | Degrade to a logged partial result; surface reduced confidence rather than a wrong PASS |
| 10-second budget dominated by WMI | Run scanners concurrently; measure per-scanner timings into the log from day one |

## Out of scope

Determining licensing, ownership, piracy, or trial status — explicitly excluded by the spec. Presence alone decides the verdict.
