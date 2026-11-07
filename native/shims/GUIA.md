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
