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
