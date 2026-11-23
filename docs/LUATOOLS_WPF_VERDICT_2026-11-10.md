# LuaTools 1.3.3 on Linux — WINS triage verdict (2026-11-10)

Target: `~/Descargas/LuaTools-win-Setup.exe`
SHA-256: `af22542a9d62d67c09bf2ba737bb3d2717ef87ca5f23af94324656952f81c49b`
Size: 11,978,370 bytes · PE32 (GUI) i386

## What the installer is

Not Inno, not NSIS, not WiX: a **Velopack 1.2.0** setup (Rust, `velopack_bins::commands::install`).
The application payload is a NuGet package (nupkg = ZIP) appended after the PE image:

| Fact | Value | How it was measured |
|---|---|---|
| ZIP overlay offset | 4,570,624 | `wins-native velopack-inspect` |
| Overlay size | 7,407,746 bytes | same |
| Entries | 83 | same |
| nuspec id / version | `LuaTools` / `1.3.3` | same |
| nuspec rid / channel | `win-x64` / `win` | same |
| nuspec runtimeDependencies | `net8-x64-desktop` | same |
| mainExe | `LuaTools.exe` | same |

The native extractor and an independent Python implementation agree byte for byte
(`diff -r` over both extracted trees: identical). Regression: `tests/test_velopack.py`.

## What the application is

.NET 8 **WPF** — `Microsoft.NETCore.App` + `Microsoft.WindowsDesktop.App`, `Wpf.Ui.dll`,
`Markdig.Wpf.dll`, `CommunityToolkit.Mvvm`, 30 satellite language folders.

Upstream publishes Windows assets only (verified against the GitHub releases API for
`madoiscool/LuaTools` v1.3.3): `LuaTools-win-Setup.exe`, `LuaTools-win-Portable.zip`,
`LuaTools-1.3.3-full.nupkg`, `releases.win.json`, `RELEASES`. There is no Linux build.

## Verdict

`wins probe` now reports:

```
envelope: velopack (NuGet nupkg payload)
runtime:  dotnet — Microsoft.NETCore.App, Microsoft.WindowsDesktop.App
gui:      WPF (Windows Presentation Foundation)
feasibility: REQUIRES_UI_REWRITE
recipe:   recipe_dotnet
```

The .NET recipe extracts the payload, finds `LuaTools.dll`, and then **fails closed**
instead of generating a launcher that would die on the first WPF type: there is no Linux
implementation of `Microsoft.WindowsDesktop.App`.

Measured, not assumed:

```
$ dotnet LuaTools.dll
Framework: 'Microsoft.WindowsDesktop.App', version '8.0.0' (x64)
No frameworks were found.
```

## What that means for the port

| Layer | Linux | Evidence |
|---|---|---|
| Installer envelope (Velopack/nupkg) | portable | this branch: native extractor, triage, recipe |
| VDF parsing (`appinfo.vdf`, `localconfig.vdf`, `libraryfolders.vdf`, `appmanifest_*.acf`) | portable | same binary formats on Linux Steam |
| `depotcache/*.manifest` (protobuf) | portable | same format under `~/.local/share/Steam/depotcache` |
| Managed service layer (~70 classes: Steam paths, depot/manifest jobs, Lua vault, HTTP bridge on `127.0.0.1:6767`, download queue) | portable | plain IO + HTTP; WPF only leaks into a handful of view models |
| WPF views (15 XAML screens) + `Wpf.Ui` | **not portable** | `Microsoft.WindowsDesktop.App` has no Linux build |
| `Microsoft.Win32.Registry` Steam discovery | replace | Linux Steam exposes no such keys; `libraryfolders.vdf` + well-known roots do |
| `netsh http add urlacl`, `cmd /c mklink /j`, `explorer /select` | replace | `HttpListener` managed socket, symlink, `xdg-open` |
| DLL injection modes (`dwmapi.dll`, `xinput1_4.dll`, `winmm.dll` proxy, `cloud_redirect.dll`) | Windows-only | PE side-loading into `steam.exe`; the Linux equivalent is `LD_PRELOAD` of a `.so`, i.e. a different artifact |
| `SAM.API` achievements/stats (kernel32 `LoadLibrary` into Steam) | Windows-only | needs a Windows Steam client |
| Millennium plugin loader (`madoiscool/LTSP` ships `winmm.dll`) | Windows-only | release assets: `plugin.zip` + `winmm.dll` only |

The plugin *frontend* (`plugin.zip`, JavaScript) is portable and the desktop app already
serves it over `http://127.0.0.1:6767/` with CORS headers — on Linux the frontend can
call that bridge directly over HTTP and the Windows DLL proxy is not needed.

## Route that follows from the evidence

1. Port the managed core to a cross-platform .NET host (Steam discovery by VDF, depot
   cache, manifest/depot jobs, Lua vault, HTTP bridge) — this is the part that gives a
   Steam Deck user a working tool.
2. Replace the WPF surface with a cross-platform UI (Avalonia) over the same core.
3. Keep the Windows binary as the behavioural oracle, not as the product.

Not demonstrated yet: any part of the above running on Linux. Everything in this document
is either a measurement of the Windows artifact or a static reading of its managed code.
