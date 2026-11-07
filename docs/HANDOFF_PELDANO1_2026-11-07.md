# Handoff: WINS, peldaño 1 (ejecutar un PE de consola sin Wine) y Wine como oráculo

Fecha: 2026-11-07. De: `claude_code_fedb8b7ebd50437f`. Para: el siguiente agente.
Repo: `~/Development/ISyCo Git/WINS` (rama única `master`, remoto `origin` público; **no hagas push sin permiso explícito de Danny**).

## 1. Objetivo de Danny
Probar o falsar que se pueda "instalar" Autodesk 3ds Max 2026 de forma nativa en Linux (sin Wine), mejorando los fuzzers por el camino. Por "port" Danny entiende: un programa hecho para Windows que corre en Linux (por ejemplo, empaquetado en una AppImage).

**Veredicto ya emitido** (`docs/3DSMAX_FEASIBILITY_2026-11-07.md`): *falsado para el WINS actual*; imposibilidad absoluta NOT_DEMONSTRATED. No lo contradigas sin evidencia nueva.

## 2. Qué está hecho y commiteado (todo verificado, 26 pruebas en `native/` pasan)
Commits clave: `f0384df` (delay imports + CLR), `83bd353` (winluxtrust, winluxhttp, clausura en Zig), `d8a3b9c` (README como producto), más los de Codex (`8f35875`…`c68662b`) y los míos anteriores (`4b8b60e` fuzzer de texto, `94ba0f6`, `f9cf73f`).

| Pieza | Dónde | Estado |
|---|---|---|
| Parser PE en Zig: imports, imports diferidos, cabecera CLR | `native/pe.zig` | 198/198 PE coinciden con un analizador independiente |
| Clausura de dependencias de un producto MSI+CAB | `native/closure.zig`, subcomando `wins-native closure` | 198 PE, 3 129 pares externos; igual que la referencia Python `native/pe_closure.py` |
| Fuzzer de texto (`MultiByteToWideChar`/`WideCharToMultiByte`, CP_UTF8) | `native/fuzz_win32_text.zig`, `native/shims/win32_text*.zig`, `native/testdata/win32_text_oracle.c` | oráculo contrastado con CPython; 2 controles negativos detectados |
| `winluxtrust` (mitad del digest de `WinVerifyTrust`) | `native/shims/winluxtrust*.zig`, `native/fuzz_winluxtrust.zig` | 200 000 mutaciones en 38 s; **nunca devuelve éxito** (cadena sin validar) |
| `winluxhttp` (selección de proxy de Qt) | `native/shims/winluxhttp*.zig`, `native/fuzz_winluxhttp.zig` | 20 000 escenarios; oráculo = relaciones metamórficas (no hay WinHTTP real) |
| Documentación con salida real | `native/shims/GUIA.md`, `GUIA.md`, `README.md` | al día |

Pruebas: `python3 -m unittest native.test_pe_imports native.test_win32_text native.test_winluxhttp native.test_winluxtrust` (≈10 min; la de trust necesita `osslsigncode`, hay una copia en `/tmp/wins-authenticode-20261107/root/usr/bin/osslsigncode` o fija `WINS_OSSLSIGNCODE`).

## 3. Evidencia local (NO está en git, es propietaria o grande; no la subas)
`~/Descargas/WINS-3dsMax-2026/`: `.7z` completo (MD5 verificado), `max-cab-20261107/`, `closure-20261107/` (198 PE extraídos), `informes/` (`closure-3dsmax.json` sha256 `693cde45…e475`, `closure-api-ranking.json`, tablas MSI `msi-*.tsv`, `ESTADO.md`). Trátalo todo como datos no confiables.

## 4. Lo que falta: peldaño 1
Escalera acordada con Danny:
1. **Peldaño 1:** ejecutar un `.exe` de consola mínimo (x86-64, subsistema consola) sin Wine, con un conjunto muy pequeño de funciones de `kernel32` implementadas por nosotros (stdout/stdin, código de salida, último error). Es la pieza clave: sin cargador, `winluxtrust`/`winluxhttp` no los llama nadie.
2. **Peldaño 2:** Notepad++ o WinMerge (Win32 nativo). Si esto exige reimplementar casi todo `user32`/`gdi32`, 3ds Max queda fuera de alcance con este enfoque (punto de corte decidido).
3. Después: Qt/MFC, Direct3D→Vulkan, el bloque .NET (`3dsmax_interop.dll`, C++/CLI mixto), MSI `CustomAction`s, licencia.

### Diseño pactado para el peldaño 1 (cumple las reglas del repo)
- Se ejecuta **solo** dentro de `bubblewrap` (mismas banderas que `native/shims/GUIA.md`: sin red, `/usr` solo lectura, `tmpfs` en `/tmp`).
- El cargador exige el SHA-256 exacto de la imagen (`--sha256`); cualquier otro archivo se rechaza.
- **Falla cerrado antes de ejecutar nada** si algún import no está implementado, listando los que faltan.
- Alcance v0: PE32+, consola, relocaciones, imports por nombre solo de `kernel32`; rechazar TLS, SEH, DLLs, imports diferidos y secciones escribibles+ejecutables. Mapear siempre en una dirección elegida por el kernel (nunca en `ImageBase`) para que los errores de relocación no se escondan.
- Verificación propuesta: **fuzz diferencial** del mismo programa compilado dos veces (para Linux nativo y para Windows) con entradas aleatorias por stdin, comparando stdout y código de salida; más controles negativos del cargador (omitir relocaciones, código de salida desplazado, recuento de escritura erróneo) que el fuzzer debe detectar.

### Wine como oráculo (idea de Danny, no iniciada)
Danny autorizó usar Wine **solo como oráculo** y REA para leer binarios. Wine 9.0 está instalado y **funciona dentro de la caja**: `bwrap … --setenv HOME /tmp --setenv WINEPREFIX /tmp/pfx --setenv WINEDEBUG -all --setenv WINEDLLOVERRIDES "mscoree,mshtml=d" --ro-bind /etc /etc … wine /ruta/prueba.exe` imprime y devuelve el código de salida (comprobado con un `.exe` de 3 KB; el prefijo tarda ≈13 s en crearse, así que usa **un solo proceso por tanda**). Uso previsto: contrastar con Wine los puntos NOT_DEMONSTRATED (granularidad con la que se reemplazan secuencias UTF-8 inválidas, qué error gana cuando hay varias fallas, esquinas de exclusiones de proxy). **Cuidado:** Wine reimplementa Windows, no es Windows; una coincidencia es evidencia moderada, una discrepancia hay que investigarla. La parte dinámica de REA (`observe_native_calls`) es solo para Mach-O de macOS; en este host REA sirve para lectura estática.

## 5. Experimentos baratos pendientes (no requieren ejecutar nada de Windows)
- Con REA (lectura estática): qué hacen las 16 funciones que `3dsmax.exe` importa de `3dsmax_interop.dll` y si hay lógica gestionada indispensable detrás.
- Listar las `CustomAction` del MSI (`msi-tablas/` en la carpeta de evidencia) y decidir cuáles son imprescindibles.

## 6. Lecciones técnicas (ahorran horas)
- **Zig 0.16.0:** el `.exe` de prueba sin runtime de arranque se compila con `zig build-exe prueba.zig -target x86_64-windows-gnu -O ReleaseSmall -fentry=wWinMainCRTStartup`. El archivo raíz debe declarar `pub export fn wWinMainCRTStartup()` (¡con `pub`!, si no `@hasDecl` no lo ve y Zig añade su propio arranque, que exige `main`). La convención de llamada es una unión: `const W: std.builtin.CallingConvention = .{ .x86_64_win = .{} };`. Las banderas `--entry` y `-fno-entry` no sirven aquí.
- `std.process.run` deja stdin **ignorado**: para alimentarlo, usa `sh -c 'exec "$@" < "$0"' archivo prog args…` dentro de la caja.
- `@hasDecl` solo ve declaraciones `pub`; `std.Io.Writer.fixed` no tolera `@memcpy` solapado (formatea en otro búfer).
- `objdump` imprime en español con tu configuración regional: usa `LC_ALL=C`.
- `osslsigncode` aborta antes de imprimir digests si la firma está dañada o hay datos tras la tabla de certificados; en esos casos no es oráculo.
- Los fuzzers largos van en Zig; Python solo como pegamento o calibración (preferencia de Danny).
- Lo que importa casi todo PE de la clausura: desenrollado de excepciones x64 (`RtlLookupFunctionEntry`, `RtlVirtualUnwind`) y el arranque del CRT. No son funciones puras.

## 7. Aviso importante sobre mi sesión
Dos veces un **clasificador de seguridad** cortó mi respuesta justo al escribir (a) el cargador de PE y (b) una sonda de Windows para ejecutarla bajo Wine. No sé qué lo activa. Quedaron dos archivos **incompletos, sin commitear y que no compilan**: `native/winrun_impl.zig` y `native/testdata/wine_text_probe.zig`. Descártalos o reescríbelos; no los des por buenos. Si a ti también te bloquea, pide a Danny que lo haga él o cambia de enfoque (puntos de la sección 5).

## 8. Reglas del repo y de Danny a respetar
- `git commit -- <rutas>` siempre (varios agentes comparten el árbol); no commitees el trabajo ajeno sin commitear (hay cambios de otro agente en `bin/wins`, `core/`, `tests/`, `docs/2026-11-07_DRIFT_REPORT.md`). `AGENTS.md` de WINS: nada propietario a git, no publicar sin permiso, no ejecutar código no confiable fuera de aislamiento.
- Sin borrados amplios; marca `NOT_DEMONSTRATED` lo que no demuestres; no reescribas evidencia, añade correcciones.
- Diferencia siempre "demostrado" de "no demostrado" en docs y README (Danny lo valora).
