# Plan — WINS e2e: FalloutNV arranca hasta CreateDevice sin concesiones de sonda

## Estado
READY — 7 milestones (M0–M6). Lease activo: `wins/e2e-blocker-fixes` (holder `opencode_wins_resume_1026062`).

## Objetivo
Corregir en el código real de WINS (no en probes de /tmp) la cadena de salidas tempranas
encontrada con la sonda, para que FalloutNV.exe llegue a `IDirect3D9::CreateDevice` y más allá
en el ensayo aislado. Criterio de éxito final observable: el log del ensayo e2e muestra
`CreateDevice` OK y consulta de caps del device respondida, sin ninguna concesión de sonda.

## Evidencia inspeccionada
- `native/winrun32.zig:1144` — `RaiseException` hace `linux.exit_group(1)` con cualquier código; el juego muere con `0x406d1388` (nombrar hilo). Despachado en `native/winrun32.zig:4704`. Copia espejo en `native/winrun_kernel32.zig:69`.
- `native/winrun32.zig:4359-4362` — `ShellExecuteA` devuelve 42 (éxito) sin ejecutar nada; en el mismatch de nombre de GPU el juego sale en silencio.
- `native/winrun32.zig:4641-4645` — `DirectInput8Create` pone `ppvOut = null` y devuelve `DI_OK`; el juego dereferencia NULL en `0xa25309` (SIGSEGV).
- `native/wins_d3d9.zig:1253-1275` — `d3d9_GetDeviceCaps` hace memset a 0: `DevCaps = 0` (sin `D3DDEVCAPS_HWTRANSFORMLIGHT`), el juego aborta antes de `CreateDevice` (`[caps] transform bit available=0`).
- `native/wins_d3d9.zig:1297-1299` — `isRenderTargetFormat` acepta 21 (A8R8G8B8) y 22 (X8R8G8B8); Proton acepta además 23 (A8B8G8R8). Falta la constante 23.
- `native/wins_d3d9.zig` (sin commitear) — ya corrige `DeviceType = dev_type` y delega `dev9_GetDeviceCaps` (líneas 1257, 1835-1837); `zig test native/wins_d3d9.zig` pasa 3/3 hoy.
- Logs de sonda en `/tmp/wins-resume/sandbox-output/probe-*.log` (hashes en sesión anterior): cadena confirmada mismatch→ShellExecuteA→RaiseException→DirectInput→caps→CreateDevice.

## Alcance
- `native/winrun32.zig`, `native/winrun_kernel32.zig`, `native/wins_d3d9.zig` únicamente.
- Un commit por milestone; `zig test` como gate de cada uno.
- M6: rebuild del loader real y corrida del ensayo aislado (`/tmp/wins-resume/run_isolated.py`).

## No objetivos
- No cerrar ni editar Steam; no tocar `steamapps/` ni archivos de Steam.
- No publicar nada de `native/probe/` ni de `/tmp/wins-resume` como producto.
- No implementar todavía `Present`/rasterización real ni el resto de la vida del device (eso es post-M6).
- No tocar otros archivos modificados del repo (`core/triage.py`, `tests/`, `tools/patch_probe_abort.py`).

## Milestones

### M0 — Baseline verificado y commit base
- **Objetivo:** Persistir los fixes ya validados de `wins_d3d9.zig` (DeviceType + device caps) como commit base.
- **Rutas:** `native/wins_d3d9.zig`.
- **Pasos:**
  1. `env ZIG_GLOBAL_CACHE_DIR=/tmp/wins-resume-zig-cache zig test native/wins_d3d9.zig -target x86-linux-gnu.2.39 -mcpu=i386 -lc` → 3/3 OK (ya verificado hoy).
  2. `git commit -- native/wins_d3d9.zig -m "D3D9: report the requested device type and answer device GetDeviceCaps"`.
- **Aceptación:** `git log --oneline -1` muestra el commit; tests siguen en verde.
- **Prueba:** comando de paso 1 + `git log --oneline -1`.
- **Rollback:** `git revert <sha>`.

### M1 — RaiseException(0x406d1388) no termina el proceso
- **Objetivo:** La excepción MS de nombrar hilo (`0x406d1388`, `MS_VC_EXCEPTION`) se traga y la ejecución continúa; el resto sigue terminando.
- **Rutas:** `native/winrun32.zig:1144`, `native/winrun_kernel32.zig:69`.
- **Pasos:**
  1. Añadir helper puro `fn isThreadNamingException(code: u32) bool { return code == 0x406d1388; }`.
  2. En ambos `RaiseException`: si `isThreadNamingException`, imprimir y retornar (cambiar `noreturn` a `void`).
  3. Test en `winrun32.zig`: `isThreadNamingException(0x406d1388) == true`, `isThreadNamingException(0xc0000005) == false`.
- **Aceptación:** `zig test native/winrun32.zig` pasa; el loader compila.
- **Prueba:** `env ZIG_GLOBAL_CACHE_DIR=/tmp/wins-resume-zig-cache zig test native/winrun32.zig -target x86-linux-gnu.2.39 -mcpu=i386 -lc`.
- **Rollback:** `git revert <sha>`.

### M2 — ShellExecuteA devuelve fallo real
- **Objetivo:** Como no se ejecuta nada, devolver código de error ≤ 32 (p. ej. `SE_ERR_FNF = 2`) en vez de 42.
- **Rutas:** `native/winrun32.zig:4359`.
- **Pasos:**
  1. Cambiar `return 42` por `return 2; // SE_ERR_FNF: nothing was executed`.
  2. Test: llamar `ShellExecuteA(0, null, "no-existe.exe", null, null, 1)` → resultado ≤ 32.
- **Aceptación:** test pasa; firma intacta.
- **Prueba:** `zig test native/winrun32.zig` (mismo comando que M1).
- **Rollback:** `git revert <sha>`.

### M3 — DirectInput8Create entrega un objeto mínimo válido
- **Objetivo:** Devolver `DI_OK` con un `IDirectInput8` real (vtbl con IUnknown + 8 métodos), no NULL.
- **Rutas:** `native/winrun32.zig:4641`.
- **Pasos:**
  1. Definir `WinsDirectInput8` con vtbl: `QueryInterface/AddRef/Release/CreateDevice/EnumDevices/GetDeviceInfo/RunControlPanel/Initialize/FindDevice/EnumDevicesBySemantics`.
  2. `EnumDevices` sin callback → `DI_OK` (0 dispositivos); `CreateDevice` → `DIERR_GENERIC` (`0x80004005`); `Initialize` → `DI_OK`.
  3. Test: `DirectInput8Create(...)` → 0 y `ppvOut != null`; `Release` baja refcount; `EnumDevices(null)` → 0.
- **Aceptación:** test pasa; el objeto no es NULL con DI_OK.
- **Prueba:** `zig test native/winrun32.zig`.
- **Rollback:** `git revert <sha>`.

### M4 — DevCaps honestas en GetDeviceCaps (adapter)
- **Objetivo:** Anunciar `D3DDEVCAPS_HWTRANSFORMLIGHT` (WINS hace T&L en software: el bit es honesto para un emulador), sin anunciar nada más no implementado.
- **Rutas:** `native/wins_d3d9.zig:1253`.
- **Pasos:**
  1. Añadir `pub const D3DDEVCAPS_HWTRANSFORMLIGHT: u32 = 0x00010000;`.
  2. En `d3d9_GetDeviceCaps`: `caps.DevCaps = D3DDEVCAPS_HWTRANSFORMLIGHT;`.
  3. Test: `caps.DevCaps & 0x00010000 != 0` para HAL y REF.
- **Aceptación:** `zig test native/wins_d3d9.zig` pasa (incluido el test nuevo).
- **Prueba:** `zig test native/wins_d3d9.zig -target x86-linux-gnu.2.39 -mcpu=i386 -lc`.
- **Rollback:** `git revert <sha>`.

### M5 — Aceptar formato 23 (A8B8G8R8) como render target
- **Objetivo:** Paridad con Proton (acepta 22 y 23): el back buffer software es 32-bit, ambos órdenes son soportables.
- **Rutas:** `native/wins_d3d9.zig:28-33`, `1297-1299`, `1227`, `1237`.
- **Pasos:**
  1. Añadir `pub const D3DFMT_A8B8G8R8: u32 = 23;`.
  2. `isRenderTargetFormat` incluye 23.
  3. `GetAdapterModeCount`/`EnumAdapterModes` aceptan cualquier `isRenderTargetFormat`.
  4. Test: `CheckDeviceFormat(0, HAL, 22, D3DUSAGE_RENDERTARGET, D3DRTYPE_SURFACE, 23) == D3D_OK`; `CheckDeviceType(0, HAL, 22, 23, 1) == D3D_OK`.
- **Aceptación:** `zig test native/wins_d3d9.zig` pasa con los tests nuevos.
- **Prueba:** `zig test native/wins_d3d9.zig ...`.
- **Rollback:** `git revert <sha>`.

### M6 — Ensayo e2e real (sin concesiones de sonda)
- **Objetivo:** Medir hasta dónde llega el binario real con todos los fixes.
- **Rutas:** build del loader + `/tmp/wins-resume/run_real.py` (bwrap aislado + `WINS_STEAM_PID`/`WINS_STEAM_EXE`).
- **Pasos:**
  1. Rebuild del loader winrun32 real con los fixes (sin `native/probe/`).
  2. Correr el ensayo aislado contra la copia de `/tmp/wins-resume/game` con el Steam real.
  3. Leer el log, registrar el siguiente obstáculo real y su SHA-256.
- **Aceptación:** el log muestra `CreateDevice` OK y caps del device respondidas sin probes; commit final con todos los fixes.
- **Prueba:** corrida del ensayo + `sha256sum` del log.
- **Rollback:** `git revert` de los commits M1–M5.
- **Estado medido (2026-11-12 ~11:40):**
  - Run directo en host: el handshake Steam OK (`ISteamClient010 rc=0`, ticket 238 bytes), pero crash nondeterminista en guest `0xaa10a0` y a veces `malloc(): invalid size (unsorted)` — causa raíz: el heap brk del loader (randomizado) cae dentro de la ventana de la imagen `0x00400000..` y el MAP_FIXED la destruye. **Corregido en commit 11ce203** (re-exec con `ADDR_NO_RANDOMIZE` + reserva PROT_NONE de `[0x00400000,+64MB)`); los aborts de heap desaparecieron.
  - Run bajo bwrap: con `WINS_STEAM_PID`/`WINS_STEAM_EXE` (commiteado en d25d6dd) el loader localiza al cliente (`/proc/<pid>/exe` no es legible dentro del user-ns), pero `CreateSteamPipe() -> pipe=0` porque **el proceso Steam ya no está corriendo** (`ps` no muestra ningún proceso steam; `~/.steam/steam.pid` quedó stale). Falta reabrir Steam para seguir.
  - `/proc` dentro del sandbox: `comm` se lee, `readlink /proc/<pid>/exe` falla por el user-ns → por eso existe el override de entorno.

## Dependencias
- `M0` → `M1`, `M2`, `M3`, `M4`, `M5` (independientes entre sí) → `M6`.
- Entorno: zig 0.16 en `/home/danny/.local/opt/zig-x86_64-linux-0.16.0/zig`, cache `/tmp/wins-resume-zig-cache`.

## Riesgos
- **Riesgo:** `zig test native/winrun32.zig` puede ser pesado o fallar por imports del loader.
  - **Mitigación:** correr baseline de test antes de editar; si falla, aislar los helpers puros en tests igualmente (el archivo ya compila como binario de sonda).
- **Riesgo:** `ShellExecuteA` devolviendo fallo cambia el comportamiento del juego (puede mostrar error en vez de salir en silencio).
  - **Mitigación:** es el comportamiento honesto de Windows; el objetivo e2e es alinear el nombre del adaptador en el INI aislado, no mentirle al juego.
- **Riesgo:** anunciar DevCaps que no se sostienen.
  - **Mitigación:** solo `HWTRANSFORMLIGHT`, que WINS sí ejecuta (rasterizador software); nada más.

## Rollback global
`git revert` en orden inverso de los commits M0..M5 (cada uno toca un archivo acotado), o `git reset --soft` al commit base si todo falla: el blast radius es solo 3 archivos de `native/`.

## Próximo paso
- **Primer paso:** ejecutar M0 — correr el test de `wins_d3d9.zig` y commitear solo ese archivo.
- **Comando inicial:** `cd '/home/danny/Development/ISyCo Git/WINS' && env ZIG_GLOBAL_CACHE_DIR=/tmp/wins-resume-zig-cache /home/danny/.local/opt/zig-x86_64-linux-0.16.0/zig test native/wins_d3d9.zig -target x86-linux-gnu.2.39 -mcpu=i386 -lc && git commit -- native/wins_d3d9.zig -m "D3D9: report the requested device type and answer device GetDeviceCaps"`
