# Fuzzer de errores por hilo

Desde la raíz de WINS, compila el candidato nativo de la pareja `SetLastError`/`GetLastError`:

```sh
zig build-lib native/shims/win32_error.zig -dynamic -lc -O ReleaseSafe -femit-bin=/tmp/wins-win32-error-good-20261107.so
```

Salida real: ninguna. Elige nombres nuevos si no quieres sobrescribir los archivos temporales de un intento anterior.

**Regla de oro:** no cargues bibliotecas desconocidas dentro del proceso principal de WINS. La prueba dinámica carga el candidato dentro de `bubblewrap` y tiene límite de tiempo. Esto no es un cargador de PE ni ejecuta 3ds Max.

Compila el fuzzer:

```sh
zig build-exe native/fuzz_win32_error.zig -lc -O ReleaseSafe -femit-bin=/tmp/wins-fuzz-win32-error-20261107
```

Salida real: ninguna. Ejecuta el candidato en la caja:

```sh
timeout 15 bwrap --unshare-all --die-with-parent --new-session --clearenv --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --ro-bind /tmp/wins-fuzz-win32-error-20261107 /runner --ro-bind /tmp/wins-win32-error-good-20261107.so /candidate.so -- /runner /candidate.so 100000
```

Salida real:

```text
MATCHED iterations=100000 seed=0x6d2b79f5 thread_isolation=observed; not a PE port
```

Para comprobar que el fuzzer detecta una falla, compila la implementación deliberadamente incorrecta:

```sh
zig build-lib native/testdata/win32_error_bad.zig -dynamic -lc -O ReleaseSafe -femit-bin=/tmp/wins-win32-error-bad-20261107.so
```

Salida real: ninguna. Ejecuta el mismo aislamiento con ese candidato:

```sh
timeout 15 bwrap --unshare-all --die-with-parent --new-session --clearenv --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --ro-bind /tmp/wins-fuzz-win32-error-20261107 /runner --ro-bind /tmp/wins-win32-error-bad-20261107.so /candidate.so -- /runner /candidate.so 100000
```

Salida real y código distinto de cero:

```text
DIVERGENCE thread main=fedcba98 worker=fedcba98
error: ThreadIsolationMismatch
```

| Resultado | Significado | Qué hacer |
|---|---|---|
| `MATCHED` | Coincidieron los valores probados y el control por hilo. | Amplía las pruebas antes de integrar el candidato. |
| `DIVERGENCE` | Un valor o aislamiento de hilo difiere del modelo. | Conserva el contraejemplo y corrige la implementación. |
| Error de `bwrap` o `timeout` | La prueba no terminó dentro de la caja. | Revisa el aislamiento y no cuentes el caso como aprobado. |

El oráculo para esta pareja se basa en la [documentación de Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setlasterror): el valor es de 32 bits y se mantiene por hilo. El fuzzer verifica únicamente esa pareja; aún no existe un cargador PE ni un adaptador completo de llamadas Windows en WINS.

# Fuzzer de texto con búferes (CP_UTF8)

`compare` solo admite funciones `uint64_t(uint64_t)`. Este fuzzer añade un protocolo con búferes, longitudes, banderas y códigos de error para `MultiByteToWideChar` y `WideCharToMultiByte`, **solo con CP_UTF8**. Los candidatos exportan `wins_mb2wc` y `wins_wc2mb` y devuelven el código de error por un parámetro de salida (no usan `GetLastError`). Tampoco es un cargador de PE.

Necesitas Zig 0.16 y `bubblewrap`. Compila candidato, fuzzer y oráculo independiente (C, por tabla):

```sh
zig build-lib native/shims/win32_text.zig -dynamic -lc -O ReleaseSafe -femit-bin=/tmp/wins-text-good-20261107.so
zig build-exe native/fuzz_win32_text.zig -lc -O ReleaseSafe -femit-bin=/tmp/wins-fuzz-text-20261107
zig cc -shared -fPIC -O2 native/testdata/win32_text_oracle.c -o /tmp/wins-text-oracle-20261107.so
```

Salida real: ninguna. Ejecuta el candidato en la caja (sin red, 100 000 iteraciones, semilla por defecto `0x57494e53`):

```sh
timeout 30 bwrap --unshare-all --die-with-parent --new-session --clearenv --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --ro-bind /tmp/wins-fuzz-text-20261107 /runner --ro-bind /tmp/wins-text-good-20261107.so /candidate.so --ro-bind /tmp/wins-text-oracle-20261107.so /oracle.so -- /runner /candidate.so /oracle.so 100000
```

Salida real:

```text
MATCHED iterations=100000 seed=0x57494e53 cp_utf8_only mb2wc[ok=21926 e87=10061 e122=4999 e1004=2425 e1113=10589] wc2mb[ok=23741 e87=9965 e122=7839 e1004=2521 e1113=5934]; not a PE port
```

Los contadores muestran qué resultados se ejercitaron: éxito, 87 (parámetro), 122 (destino pequeño), 1004 (banderas) y 1113 (secuencia inválida con bandera estricta). Cada caso inyecta **una sola** falla, porque Microsoft no documenta qué error gana si coinciden varias. El destino lleva canarios: escribir fuera de él se detecta.

Controles negativos incluidos (deben fallar): `native/win32_text_bad_perbyte.zig` reemplaza cada byte inválido en vez de su subparte máxima, y `native/win32_text_bad_overrun.zig` ignora el tamaño del destino. Con el primero:

```text
DIVERGENCE mb2wc iter=42 flags=0x0 cb=-1 cch=10 dst_null=false expected=7/err0 actual=8/err0
input: af dd 07 e0 b6 f5 ea 00 
expected: fffd fffd 0007 fffd fffd fffd 0000 
actual:   fffd fffd 0007 fffd fffd fffd fffd 0000 a5a5 a5a5
```

Pruebas: `python3 -m unittest native.test_win32_text -v` (6 pruebas, ~70 s). Además de las anteriores, el oráculo se contrasta con el códec UTF-8 de CPython en 20 000 vectores por dirección, para no comparar dos copias del mismo supuesto.

**Límites (NOT_DEMONSTRATED):** no se comparó con un kernel de Windows real. La granularidad con que Windows reemplaza secuencias inválidas (aquí: subparte máxima de Unicode) y la precedencia entre errores simultáneos no están demostradas. Solo CP_UTF8, sin `lpDefaultChar`, sin otras páginas de códigos y sin `MB_PRECOMPOSED`/`WC_COMPOSITECHECK`.

# winluxtrust: mitad del digest de `WinVerifyTrust`

Calcula el hash Authenticode de un PE y lo compara con el digest de la firma PKCS#7. **No valida la cadena de certificados, el valor de la firma, la revocación ni la marca de tiempo**, así que nunca devuelve éxito: una coincidencia devuelve `0x20570001` (*digest coincide, cadena sin verificar*), a propósito distinto de `ERROR_SUCCESS` (0). Códigos usados: `0x800B0100` sin firma, `0x800B0003` no es un PE interpretable, `0x80096010` digest distinto, `0xA0570001` firma mal formada, `0xA0570002` algoritmo no soportado.

Compila el candidato y el fuzzer de mutación (Zig):

```sh
zig build-lib native/shims/winluxtrust.zig -dynamic -lc -O ReleaseSafe -femit-bin=/tmp/winluxtrust-20261107.so
zig build-exe native/fuzz_winluxtrust.zig -lc -O ReleaseSafe -femit-bin=/tmp/wins-fuzz-trust-20261107
```

Salida real: ninguna. Necesitas un PE firmado y su digest **calculado por otra herramienta** (aquí `osslsigncode verify`, línea `Current message digest`, en minúsculas). Con una muestra propia firmada con una clave de prueba:

```sh
timeout 60 bwrap --unshare-all --die-with-parent --new-session --clearenv --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --ro-bind /tmp/wins-fuzz-trust-20261107 /runner --ro-bind /tmp/winluxtrust-20261107.so /candidate.so --ro-bind /tmp/wins-signed-sample-20261107.exe /signed.exe -- /runner /candidate.so /signed.exe 181919d330aa31b433d88c4e194fcb97658b171e771d5faa4b4c7b2ecf324a1f 100000
```

Salida real:

```text
MATCHED iterations=100000 seed=0x7472757374 classes[data=40152 header=108 checksum=9990 blob=19789 truncated=9902 appended=10133 structural=9926]; digest half only, chain NOT validated
```

Cada mutación se clasifica por la estructura del archivo, no por el candidato: un bit cambiado en secciones o en datos añadidos debe dar `BAD_DIGEST`; en el campo de checksum (excluido del hash) debe seguir coincidiendo; en la cabecera, cualquier rechazo pero nunca coincidencia; truncar nunca debe coincidir; y el valor 0 no es aceptable jamás. Control negativo (`native/winluxtrust_bad_acceptall.zig`, acepta cualquier digest):

```text
DIVERGENCE iter=0 class=0 rc=0x20570001 len=419248/419248 flips={ 283258 }: expected BAD_DIGEST
```

Pruebas: `python3 -m unittest native.test_winluxtrust` (necesita `osslsigncode`; fabrica un PE con Zig y lo firma con una clave autofirmada desechable, así que no hay binarios propietarios). Límites: la lectura de datos añadidos tras la tabla de certificados sigue la especificación, pero `osslsigncode` rechaza esos archivos por completo, así que no hay oráculo independiente para esa clase; el comportamiento de Windows ante ella es NOT_DEMONSTRATED. Tampoco se probó con catálogos `.cat` ni con firmas duales.

# winluxhttp: selección de proxy (`WinHttp*` de Qt)

Las bibliotecas Qt que 3ds Max trae (`qt6network.dll`, `qt6webenginecore.dll`) solo usan de WinHTTP la detección de proxy (`WinHttpOpen`, `WinHttpGetProxyForUrl`, `WinHttpGetIEProxyConfigForCurrentUser`, `WinHttpGetDefaultProxyConfiguration`, `WinHttpSetTimeouts`, `WinHttpSetStatusCallback`, `WinHttpCloseHandle`), no hacen peticiones. Este candidato implementa la elección de proxy para una URL `http`/`https` a partir de la lista de proxies y la de exclusiones, con los formatos documentados de `WINHTTP_PROXY_INFO`. **No** implementa scripts PAC, detección WPAD, transporte HTTP ni el manejo de `HINTERNET`.

```sh
zig build-lib native/shims/winluxhttp.zig -dynamic -lc -O ReleaseSafe -femit-bin=/tmp/winluxhttp-20261107.so
zig build-exe native/fuzz_winluxhttp.zig -lc -O ReleaseSafe -femit-bin=/tmp/wins-fuzz-http-20261107
```

Salida real: ninguna. No existe un WinHTTP real con el que comparar, así que el oráculo son relaciones metamórficas (alcance por esquema, `*`, mayúsculas, separadores y orden, `<local>`, puertos, comodines, búfer pequeño, URLs inválidas y basura):

```sh
timeout 60 bwrap --unshare-all --die-with-parent --new-session --clearenv --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --ro-bind /tmp/wins-fuzz-http-20261107 /runner --ro-bind /tmp/winluxhttp-20261107.so /candidate.so -- /runner /candidate.so 20000
```

Salida real:

```text
MATCHED iterations=20000 seed=0x68747470 relation_checks_nominal=620000; proxy selection only, no real WinHTTP compared
```

Control negativo (`native/winluxhttp_bad_scheme.zig`, ignora el alcance por esquema) con el mismo fuzzer:

```text
DIVERGENCE iter=0 relation=R3: status 0, expected 1
  url=http://d9cmi.1.8iv6f/p
  proxy=https=px80.corp:2073
  bypass=
```

El segundo control, `native/winluxhttp_bad_case.zig` (exclusiones sensibles a mayúsculas), falla en la relación R6. **Límites:** cuando la documentación no fija un comportamiento (p. ej. si `*.dominio` coincide con el dominio desnudo, el orden entre entradas con alcance y sin él, o `<local>` con direcciones IPv6) este candidato toma una decisión propia; eso es una suposición y NO está demostrado frente a un Windows real. `relation_checks_nominal` es 31 por iteración, no un contador medido.
