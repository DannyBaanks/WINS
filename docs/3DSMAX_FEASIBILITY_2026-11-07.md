# ¿Se puede instalar 3ds Max 2026 de forma nativa en Linux con WINS? (2026-11-07)

**Veredicto: FALSADO para el estado actual de WINS; NO demostrado imposible en términos absolutos.**
Todo es análisis estático: no se ejecutó ningún binario de Windows. Reproducible con `native/pe_closure.py`.

## Método
1. `.7z` completo (MD5 verificado = `01768fdc8d6572d255a6eeb3ad4a4ab0`) → `x64/max/max.cab` → clausura de dependencias desde `3dsmax.exe` (miembro `fil965675F3D3F24E86CBB33BA5F0DD4753`, SHA-256 `a4cdd99b…aa7b`).
2. Para cada PE: imports, imports diferidos y cabecera CLR; las bibliotecas que no están en el CAB quedan como *externas*.
3. Contraste con lo que WINS implementa. El analizador de WINS (Zig) coincide con un analizador Python independiente en los 198 PE.

## Cifras (verificadas, `informes/closure-3dsmax.json`, SHA-256 `693cde45cb382b9ac5a8c7a3a086bb43b7fe9e71c2061695b4cdf7ee3e81e475`)
| Medida | Valor |
|---|---|
| PE en la clausura (todos x64) | 198 |
| Bibliotecas externas al CAB | 89 |
| Pares (biblioteca, función) externos únicos | 3 129 |
| De ellos, con candidato en WINS | 4 (`GetLastError`, `SetLastError`, `MultiByteToWideChar`, `WideCharToMultiByte`) = 0,13 % |
| Pares usados por ≥ 20 PE / por exactamente 1 | 257 / 1 450 |
| Imports diferidos (antes ignorados) | 925 en 34 bibliotecas |
| PE con código gestionado (CLR) | 1: `3dsmax_interop.dll` |

Los 4 candidatos existen como funciones de un protocolo de prueba (`wins_mb2wc`…), **no** como ABI de Windows: hoy no hay cargador de PE, así que ninguno es invocable por `3dsmax.exe`.

## Afirmaciones
| # | Afirmación | Estado | Evidencia / límite |
|---|---|---|---|
| C1 | WINS hoy puede ejecutar 3ds Max en Linux | **FALSADA** | Sin cargador PE; 4/3 129 funciones con candidato (y ninguna con ABI Win32). |
| C2 | Se puede depositar todo el contenido del instalador sin Windows | **DEMOSTRADA** | 7z → MSI (tablas) → `max.cab` (18 046 archivos, `7zz t` OK) → PE verificados por SHA-256. |
| C3 | Extraer = instalar | **FALSADA** | El MSI trae `CustomAction` con código de Windows (`Binary.AdskLicensingInstCA.dll`, `Binary.SingleClick.exe`) y tablas `Environment`, `FirewallFile`, etc. Instalar exige emular el motor MSI y esas acciones. |
| C4 | El enfoque de WINS (quitar la capa de runtime) aplica a 3ds Max | **FALSADA** | No es Electron/Python/.NET puro: 198 PE nativos x64 cerrados (`3dsmax.exe` importa 1 841 símbolos de `core.dll`, etc.). Sin código fuente no se recompila: solo cabe *cargar y reimplementar Win32*, es decir, un Wine propio. |
| C5 | Basta reimplementar Win32 de sistema | **FALSADA** | Dependen además de redistribuibles MSVC (`msvcp140`, `mfc140u`, ABI C++ de Microsoft: 24 bibliotecas, 1 472 funciones, no incluidas en este CAB), Direct3D 9/11 + DXGI (visor: `d3dgfx.drv`, `ogsextdevice.dll`, `graphicsdriver.dll`), COM/OLE, WinTrust/Crypt32 (10 PE). |
| C6 | El bloque CLR es portable | **FALSADA (por documentación)** | `3dsmax_interop.dll` tiene cabecera CLR **y** importa `KERNEL32` + `ijwhost.dll`: ensamblado mixto C++/CLI, y `3dsmax.exe` lo importa directamente. Microsoft documenta C++/CLI como solo Windows ([learn.microsoft.com](https://learn.microsoft.com/en-us/cpp/dotnet/dotnet-programming-with-cpp-cli-visual-cpp?view=msvc-170)). **NOT_DEMONSTRATED:** el comportamiento concreto de `ijwhost` en Linux; no se ejecutó nada. |
| C7 | Licencia/identidad funcionan sin Windows | **NOT_DEMONSTRATED** | `AdskIdentitySDK`, `AdskLicensing*` usan WinTrust/WinHTTP/WinINet; requeriría los servicios de Autodesk. No se probó. |
| C8 | Es *imposible* hacerlo | **NOT_DEMONSTRATED** | Solo se probó que no es alcanzable con la arquitectura y cobertura actuales de WINS. |

## Lo que mueve la aguja (objetivos del fuzzer, `informes/closure-api-ranking.json`)
- La barrera común es **desenrollado de excepciones x64**: `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlCaptureContext`, `UnhandledExceptionFilter` los importan 186 de 198 PE, junto con el arranque del CRT (`_initterm`, `_cexit`…, 183 PE). Ninguna de esas funciones es pura; requieren cargador PE, `.pdata` y contexto de CPU.
- 257 pares los usan ≥ 20 PE: es el conjunto con mejor rendimiento por esfuerzo. 1 450 pares los usa un solo PE (cola larga).

## NOT_DEMONSTRATED
Cargador PE; emulación del motor MSI y de sus `CustomAction`; ejecución de cualquier binario; licencia; rendimiento/GPU; granularidad de reemplazos UTF-8 de Windows real (ver `native/shims/GUIA.md`).

## Actualización: `wintrust` y `winhttp` (2026-11-07)
La clausura mostró que lo que 3ds Max y su pila Qt piden a estas dos bibliotecas es pequeño: `wintrust` (`WinVerifyTrust` + 3 ayudantes `WTHelper*`, 9 PE) y `winhttp` (solo detección de proxy desde `qt6network`/`qt6webenginecore`, 7 funciones). Se construyeron réplicas Linux parciales, `winluxtrust` (mitad del digest Authenticode, nunca informa confianza) y `winluxhttp` (selección de proxy), ambas verificadas con fuzzers en Zig y controles negativos; ver `native/shims/GUIA.md`. **No cambian el veredicto:** sin cargador de PE ninguna es invocable por `3dsmax.exe`, y faltan los ayudantes `WTHelper*` (estructuras `CRYPT_PROVIDER_DATA`), la validación de cadena, PAC/WPAD, y el resto de los 3 129 pares externos.
