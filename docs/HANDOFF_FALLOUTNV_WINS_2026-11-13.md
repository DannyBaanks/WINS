# Handoff: Fallout New Vegas desde Steam con WINS

Fecha: 2026-11-13  
De: Codex  
Para: Qwen4 / siguiente agente  
Repo de trabajo: `/home/danny/Development/ISyCo Git/WINS`

## Objetivo del usuario

Al pulsar **Jugar** en Steam, Fallout: New Vegas debe ejecutarse con **WINS** (loader Linux nativo), no con Wine ni Proton. El resultado buscado es que el juego llegue a una ventana y renderice una imagen. Danny autorizó continuar y usar el Steam real que ya está abierto con sesión.

Danny explicó que Steam intentó descargar Vulkan en una ejecución anterior porque estaba intentando entrar por Proton. No instalar Vulkan para resolver este caso: el tool de compatibilidad WINS ya está seleccionado y el último ensayo demuestra que Steam sí llegó al loader WINS.

## Lectura obligatoria antes de retomar

Volver a leer `README.md` y `AGENTS.md` de este repo. Resumen relevante del README: WINS busca rehosting nativo Linux sin Wine; para un PE Win32 nativo el resultado se debe reportar con evidencia y límites, y una compilación o inventario de imports no prueba que el juego funcione. El AGENTS local pide loader/superficie en Zig, oráculo Wine dentro de bubblewrap para diferencias Win32, aislamiento, preservación de originales/saves y no publicar archivos del juego.

No tocar los saves ni modificar la instalación original del juego. El launcher actual prepara una copia temporal bajo `/tmp`, monta `Data` de solo lectura y monta el perfil aislado de WINS.

## Estado comprobado de Steam → WINS

La herramienta está instalada en:

- `/home/danny/.steam/root/compatibilitytools.d/WINS-FalloutNV`
- Script: `launch-falloutnv`
- Manifest: `toolmanifest.vdf`

El manifest registra el comando WINS. El script valida `STEAM_COMPAT_APP_ID=22380`, identifica el proceso de Steam con IPC real y ejecuta en bubblewrap:

```bash
bwrap ... -- /tmp/wins-tool/dist/winrun32 --run /tmp/wins-workspace/game/FalloutNV.exe
```

Por tanto, la ejecución actual desde el botón **Jugar** sí va por Steam → WINS → `FalloutNV.exe`. El log registra `SteamAPI_Init` con cliente real, `BLoggedOn() -> 1` y AppID `22380`. No hay evidencia de que el último intento haya pasado por Proton o Wine.

## Último intento y resultado

Log más reciente:

`/home/danny/.local/state/wins/falloutnv/logs/20261113T120719Z-559959.log`

También hay un intento prácticamente idéntico en `20261113T120716Z-559876.log`.

El log del más reciente muestra:

- El juego carga `D3D9.DLL`, llama `Direct3DCreate9`, enumera modos y consulta caps/tipos.
- Aún **no** llama `CreateDevice` ni crea una ventana.
- Consulta `Software\\Bethesda Softworks\\Fallout` → `sBasePath` y `Software\\Bethesda Softworks\\FalloutNV` → `Installed Path`; WINS contesta con el directorio de la copia temporal.
- Luego llama:
  `ShellExecuteA(file="/tmp/wins-workspace/game/FalloutNVLauncher.exe", params="", dir="")`
- WINS actualmente devuelve `SE_ERR_FNF` (2) en `ShellExecuteA`; el juego limpia memoria y termina con código 0.
- `pgrep` no mostró el juego activo y el árbol X11 no tuvo ventana de Fallout.

La condición que manda al launcher sigue sin identificarse. Cambiar la identidad D3D9 y añadir el archivo de preferencias no bastó.

## Hipótesis de mayor prioridad

El perfil aislado contiene:

`/home/danny/.local/share/wins/falloutnv/profile/Documents/My Games/FalloutNV/FalloutPrefs.ini`

El archivo se copió desde el prefijo Proton existente (no se modificó el original). SHA-256: `29d3742f2b817783f30f9746245352f5ee716006fb84399bb13eafceb33f5308`. Contiene:

```ini
[Display]
sD3DDevice="AMD Radeon 760M Graphics (RADV PHOENIX)"
```

La interfaz actual de WINS anuncia exactamente `AMD Radeon 760M Graphics (RADV PHOENIX)`, pero el parser local `iniLookup` devuelve el valor crudo con las comillas incluidas. Eso puede hacer que la comparación del juego no coincida. **Es una hipótesis, aún NOT_DEMONSTRATED.** Confirmar con REA y/o instrumentando el valor de retorno de `GetPrivateProfileStringA`; no cambiar la semántica a ciegas. Comprobar también qué archivo, sección, clave y variante A/W consulta realmente el ejecutable.

El log previo confirma que el juego puede encontrar `My Games/FalloutNV/FALLOUT.INI` por su ruta relativa; el launcher monta el perfil en `/tmp/wins-workspace/home` y enlaza `My Games` hacia él. La ruta debería resolver bajo el cwd, pero hay que verificarla con llamadas instrumentadas.

## REA

REA abrió el ejecutable principal con Hopper/Ghidra disponible:

- Archivo: `/home/danny/.local/share/Steam/steamapps/common/Fallout New Vegas/FalloutNV.exe`
- SHA-256: `3a87f92f011e5dc9179ddf733cf08be2b39ea6e5b7a8a9e3a9a72dafcc1b104d`
- Arquitectura: x86 PE

La llamada de REA `search_procedures("ShellExecuteA")` se quedó ejecutando y Danny interrumpió el turno; no se obtuvo resultado. Continuar desde el ejecutable ya abierto (o volverlo a abrir), usando Hopper/Ghidra para seguir la importación/xref de `ShellExecuteA` hacia el llamador y descubrir la condición de fallback. Si una consulta amplia se cuelga, buscar la importación/xref puntual o inspeccionar el call site por dirección del log.

En una sesión previa se analizó `FalloutNVLauncher.exe`; al forzar el launcher como entrypoint, WINS lo rechazó por **186 imports sin resolver**. No activar `--ignore-missing-imports` a ciegas: entre ellos había APIs de User32W, perfil `W`, `steam_api`/RemoteStorage y MSVCP90. El entrypoint correcto que el script ejecuta sigue siendo `FalloutNV.exe`.

## Cambios de código ya guardados

Commit de esta continuación: `9929271 D3D9: correct Fallout formats and adapter identity`.

Incluye solo `native/winrun32.zig` y `native/wins_d3d9.zig`:

- Corrige `D3DFMT_A8B8G8R8` de 23 a 32 y devuelve el formato pedido por `EnumAdapterModes`.
- Publica una identidad de adaptador que coincide con el hardware/preferencias del equipo (AMD Radeon 760M, vendor `0x1002`, device `0x1900`).
- Añade trazas D3D9, `ShellExecuteA` y consultas del registro.
- Añade thunk real de `ISteamUser::BLoggedOn` a la interfaz del Steam client y reconoce `STEAMUSERSTATS_INTERFACE_VERSION007`.
- `sBasePath` ahora recibe el mismo path medido de la copia temporal que `Installed Path`.

El build completo de WINS terminó 4/4 correctamente con:

`tools/build_all.sh /tmp/wins-fnv-gpu-identity.en4Ocn`

Se instaló el loader compilado en `dist/winrun32`. SHA-256 instalado en el último ensayo: `52c38ff50705bc4a1cfde978a9324afa48e6bb92241e18a2da2a67c4828750cc`. El build no alcanzó `CreateDevice`; no afirmar que el juego ya funciona.

## Historial técnico útil

- Antes, el juego no leía los BSA porque WINS simulaba hilos con un único hilo; se implementaron hilos Linux/pthread y sincronización Win32. El loader empezó a leer datos del juego.
- Luego se corrigió la cadena de mipmaps D3D9, que faltaba para texturas DXT1 y permitía que el juego escribiera fuera del búfer.
- En un ensayo anterior el juego progresó hasta otro crash (`0x713eea`, lectura en NULL+0x34) después de ~5.133 líneas. No es el estado del último ensayo, que ahora cae al launcher antes de crear el dispositivo.
- Notas anteriores mencionan commits `8712aa1` y `6bbe43e`, pero el HEAD observado en este checkout antes de `9929271` era `478c682`. Verificar `git log` antes de depender de esos hashes.
- La prueba sintética Win32 de hilos dio salida idéntica a Wine: 34 líneas y código 0. No sustituye la prueba del juego.

## Siguiente secuencia recomendada

1. Releer README/AGENTS y confirmar `git status --short`; el árbol tiene cambios ajenos en `core/`, `tests/`, `tools/` y archivos no relacionados. No tocarlos ni incluirlos en commits.
2. Con REA, encontrar la condición que lleva al `ShellExecuteA(FalloutNVLauncher.exe)`. Comparar la lógica con los valores que WINS devuelve para `sD3DDevice`, rutas/registry e INI.
3. Añadir trazas temporales en Zig a `GetPrivateProfileStringA` / `GetPrivateProfileIntA` (y variantes W si el binario las usa), con filename, sección, clave, default y resultado. Contrastar la semántica INI con Wine en una prueba aislada si hace falta.
4. Si el juego logra pasar el fallback, seguir hasta `CreateDevice`, creación de ventana y primer frame; entonces evaluar el crash histórico de texturas/NULL con el log nuevo.
5. Recompilar en un directorio temporal nuevo, reinstalar solo el loader en el tool WINS, lanzar desde Steam y guardar el log nuevo con timestamp único. Mantener el perfil de WINS aislado y no modificar saves.
6. No hacer push ni publicar binarios/datos del juego.

## Evidencia

- Binario objetivo y hash: descritos en la sección REA.
- Último log raw: `/home/danny/.local/state/wins/falloutnv/logs/20261113T120719Z-559959.log`.
- El último `xwininfo -root -tree` no mostró ventana de Fallout; `pgrep` no mostró `FalloutNV.exe`/loader activos tras la salida.
- Límite de esta conclusión: demostrado que el click de Steam entra a WINS y que el juego redirige al launcher; la condición exacta de esa redirección y un frame visible aún no están demostrados.

## Continuación Qwen4 (2026-11-13) — commits 12648b7 y 24683df

### El fallback al launcher está resuelto (verificado de punta a punta)
La hipótesis de las comillas del INI era correcta. El commit 12648b7
("strip INI value quotes as Win32 does") hace que GetPrivateProfileStringA
devuelva sD3DDevice sin las comillas, coincida con el identificador del
adaptador D3D9, y el juego YA NO llama ShellExecuteA(FalloutNVLauncher.exe).
En el lanzamiento desde Steam posterior (log 20261113T133026Z-709299.log,
1823 líneas) el juego llega a CreateWindowExA("Game", 1280x720) y a
CreateDevice. Cero llamadas a ShellExecuteA en ese log.

### Nuevo bloqueo encontrado y resuelto: rutas case-sensitive (commit 24683df)
Con el launcher fuera del camino, el juego moría en SIGSEGV NULL+0x28
(EIP 0x00a087e5, EDI 0xfffffffe) justo después de buscar texturas sueltas.
Causa demostrada: lee sArchiveList y sondea cada BSA con
GetFileAttributesA("DATA/Fallout - Textures.bsa"); el directorio en disco
es "Data". El loader normalizaba separadores pero comparaba con case
sensitive -> los 6 BSA respondían "not found" -> no abría ningún archivo
(solo 7 CreateFileA en todo el log) -> deref NULL.

Fix: resolvePathCaseInsensitive (componente a componente, exacto primero,
luego scan getdents64 con fold ASCII), usado en GetFileAttributesA y
CreateFileA. Además GetFileAttributesA devuelve el bit de directorio
(0x10) vs archivo (0x20) vía statx, y distingue error 2 (falta archivo) de
3 (falta directorio padre).

Evidencia diferencial (oráculo Proton, tools/diff_wine.sh):
- native/testdata/filecase_probe.c: ANTES 13/14 líneas divergían; DESPUÉS
  14/14 byte-idénticas, exit 0.
- profile_probe.c: 29/29 idénticas (sin regresión del INI).
- zig test native/winrun32.zig -target x86-linux-gnu.2.39 -mcpu=i386 -lc:
  23/23 (incluye test nuevo del resolver).
- Build 4/4 (tools/build_all.sh), loader instalado en el tool de Steam.
  SHA-256 del winrun32 instalado:
  04878ba1d9d18aecba468442960ce387288eb04b2b1434737cda27107df26ac2
  (source winrun32.zig sha256
  a2761f552c7b50a396f5eab454dad87526bd28e4484306fc40a60ebf8edb62b5).

### Estado actual tras el fix (log 20261113T135513Z-754709.log)
Lanzado desde Steam (steam://rungameid/22380). El juego:
- Abre los 6 BSA: "SUCCESS [case-insensitive: Data/Fallout - Textures.bsa]"
  (Textures, Textures2, Meshes, Voices1, Sound, Misc).
- Llega a CreateWindowExA + CreateDevice (1280x720, windowed).
- Crea el directorio de Saves y sondea assets de menús/loading.
- Spawnea 16 hilos y YA NO crashea en NULL+0x28.

Nota: un lanzamiento intermedio (20261113T135352Z) murió con
"Application load error S:0000065432" (assert IsValidHSteamUserPipe del
cliente Steam) -> fue transitorio; el reintento inmediato entró bien. No
es regresión del fix (ocurre en el stub DRM de Steam, antes de tocar
archivos). Si reaparece, reintentar el lanzamiento.

### Nuevo bloqueo (NO resuelto): ventana y Present son stubs
El juego se queda colgado en la pantalla de carga, sin frame visible:
- CreateWindowExA devuelve un HWND falso (0x20001); NO crea ventana X11
  real (xwininfo -root -tree no muestra nada de Fallout).
- dev9_Present (native/wins_d3d9.zig:2031) solo incrementa frame_count y
  devuelve D3D_OK; no rasteriza ni presenta.
- Estado de hilos: el principal en hrtimer_nanosleep (bucle de Sleep) y
  los 15 workers en futex_do_wait. El proceso sigue vivo pero no avanza.

Esto es el trabajo post-M6 que el plan ya marcaba: ventana X11 real +
Present/rasterización real. Un frame visible TODAVÍA no está demostrado.

### Siguiente secuencia recomendada
1. Implementar ventana X11 real en CreateWindowExA (y ShowWindow/
   UpdateWindow + message loop PeekMessage/GetMessage) para que el juego
   tenga un destino de presentación y bombee mensajes.
2. Implementar Present/rasterización real en wins_d3d9.zig (o el camino de
   superficie que el plan defina) y verificar que el main thread sale del
   bucle de Sleep.
3. Reinstalar solo el loader, lanzar desde Steam, guardar log con
   timestamp único; confirmar primer frame visible con xwininfo/captura.
4. No tocar saves ni la instalación original; no publicar binarios/datos
   del juego; no push sin aprobación.

### Evidencia nueva
- Log con BSAs abiertos y CreateDevice:
  /home/danny/.local/state/wins/falloutnv/logs/20261113T135513Z-754709.log
- Probe diferencial: native/testdata/filecase_probe.c (rojo 13/14 ->
  verde 14/14). Work dirs: /tmp/wins-filecase.sYbfv1Wi/{red,green,iniregr}.
- Build final: /tmp/wins-fnv-filecase-final.wzLi2APB (MANIFEST.tsv).
- Límite: demostrado que el juego abre sus BSA y llega a CreateDevice sin
  crashear; un frame visible y la salida del cuelgue de carga NO están
  demostrados.

## Continuación Claude Code (2026-11-13 tarde) — commits 52804fb, 414d685, 42822f8

### Corrección al diagnóstico anterior
El cuelgue en la pantalla de carga NO se debía a la ventana X11 / Present.
Medido sobre el proceso colgado (754768, 7 h vivo): el hilo principal
despertaba ~20 veces/s en un bucle de Sleep y los 15 workers estaban
ociosos en futex. Es decir, esperaba datos, no una ventana. En el log no
había ni una apertura de `FalloutNV.esm`.

### Causa 1: FindFirstFileA era un stub (52804fb)
Ignoraba el patrón y respondía siempre "FalloutNV.exe" (0x80, tamaño 0).
El juego lista los plugins con `FindFirstFileA("DATA\\*.esm")` / `*.esp` y
llama FindFirstFileA sobre cada master/BSA antes de abrirlo (log relay de
Proton: 494 llamadas). Implementado de verdad: máscara `*`/`?` sin
distinguir mayúsculas, padre resuelto con el resolver de 24683df, "." y
"..", atributos 0x10/0x20, tamaño y FILETIME reales, errores 2/3/18/6.
GetFileType ahora mira el descriptor (antes CHAR para todo).
Probe: `native/testdata/find_probe.c`: rojo DIFFERENT → verde 46/46
idénticas con Proton.

### Causa 2: lstrcatA sobrescribía (414d685)
Con Find arreglado, el juego pedía `"*.esm"` en vez de `"DATA\\*.esm"`.
Call site leído de la imagen descifrada en memoria (el .text en disco está
cifrado por SteamStub `.bind`; `/proc/<pid>/mem` del juego vivo se puede
leer desde fuera del bwrap): `lstrcpyA(buf,"DATA\\")` + `lstrcatA(buf,"*.esm")`
(0x4625c4..0x46262c, IAT 0xfdf078/0xfdf074). `lstrcatA` calculaba siempre
una longitud de 0. El mismo patrón de bug, con `orelse 0 + 1`, estaba en
MultiByteToWideChar y LCMapStringA con cuenta -1: convertían 1 carácter.
Probe: `native/testdata/str_probe.c`: rojo reproduce "*.esm" → verde 11/11.
Regresiones idénticas: find 46, thread 34, filecase 14, profile 29.
zig test 26/26.

### Estado tras los fixes (log 20261113T213800Z-1168996.log)
Desde Steam: enumera y abre los 10 .esm (FalloutNV + DLC), procesa sus
registros (sondea texturas de nvdlc03), y llega a la música del menú
principal: abre `Data\Music\Special\MainTitle.mp3`, momento en que un
worker se cae: SIGSEGV en EIP 0x83101e, lectura de NULL, EAX=0.

### Causa 3 (NO resuelta): DirectShow
`CoCreateInstance` devolvía S_OK con `*ppv = NULL`. Ahora (42822f8)
devuelve REGDB_E_CLASSNOTREG y registra en el log la clase pedida:
`CLSID_FilterGraph {e436ebb3-524f-11ce-9f53-0020af0ba770}`,
`IID_IGraphBuilder {56a8689f-0ad4-11ce-b03a-0020af0ba770}`. En Wine,
quartz.dll se carga en el mismo punto. **El juego no comprueba el HRESULT**
y se cae igual en el mismo EIP (log 20261113T214131Z-1173584.log). Que la
causa sea ese puntero NULL es una inferencia (mismo EIP, EAX=0 justo
después de la llamada); el código en 0x83101e no se ha desensamblado.

Siguiente paso: un FilterGraph DirectShow nativo para reproducir MP3
(IGraphBuilder::RenderFile + IMediaControl / IMediaEventEx / IBasicAudio /
IMediaSeeking, lo que el juego use de verdad). Antes de diseñarlo, medir
la secuencia real de métodos con el oráculo (`WINEDEBUG=+quartz` en
`~/.cache/wins-oracle/run_oracle.sh`). wins_dsound.zig ya documenta que hoy
no sale PCM a ningún dispositivo. Un frame visible sigue NOT_DEMONSTRATED.

Loader instalado en el tool de Steam: sha256 8ad6b1fd…248f
(build `/tmp/wins-find.uCMKz1oy/build-com`). Backup del de Codex:
`dist/winrun32.prev-24683df` (04878ba1…6ac2).
