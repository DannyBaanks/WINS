# WINS: caja de análisis nativa

Desde la raíz del repositorio, compila el controlador Zig:

```sh
mkdir -p build && zig build-exe native/main.zig -O ReleaseSafe -femit-bin=build/wins-native && zig build-exe native/compare.zig -lc -O ReleaseSafe -femit-bin=build/wins-compare
```

Salida: ninguna si la compilación termina bien.

**Regla de oro:** el contenido extraído es material no confiable. No ejecutes un PE ni cargues sus bibliotecas en Linux; la caja ejecuta únicamente el extractor o los candidatos ELF que tú indiques. No ejecuta Windows ni implementa sus APIs.

Necesitas Linux, Zig 0.16, `bubblewrap` funcional y un extractor Linux (`7zz` o `innoextract`). Las salidas deben ser directorios **nuevos**; en caso de fallo se conservan para inspección, así que usa otro nombre al reintentar. Las rutas siguientes corresponden a la máquina en que se verificó el ejemplo; adáptalas a tu instalación.

## Depositar el contenido de un instalador

```sh
build/wins-native extract '/home/danny/Descargas/wins-samples/npp.8.9.9.Installer.x64.exe' /tmp/wins-guide-npp-1107 /home/danny/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz 7z
```

Salida real:

```text
Extraction complete. Output is untrusted; inspect before use.
```

Para Inno se usa la misma forma con la ruta del ejecutable `innoextract` y el último argumento `inno`; esa ruta también se probó con el instalador de WinMerge. El paquete se monta en solo lectura, el directorio de salida se monta para escritura y no hay red. `/usr` está montado en solo lectura para proporcionar bibliotecas y utilidades: no es un sistema operativo Windows vacío.

### MSI y archivos Compound

Los MSI suelen contener tablas Compound y pueden apuntar a archivos CAB externos. Compila esta versión del controlador, sin sobrescribir las anteriores:

```sh
zig build-exe native/main.zig -O ReleaseSafe -femit-bin=build/wins-msi
```

Salida real: ninguna. Para extraer los flujos de un MSI, usa `msi`:

```sh
build/wins-msi extract '/home/danny/Descargas/WINS-3dsMax-2026/3dsMax-2026.msi' /tmp/wins-3dsmax-msi-guide-20261107 '/home/danny/.cache/electron-builder/7zip@1.0.0/7zip-linux-x64-16wjr/bin/7zz' msi
```

Salida real:

```text
Compound streams extracted; application payloads may be external. Output is untrusted.
```

Elige una carpeta de salida nueva. WINS selecciona el contenedor Compound completo en lugar de descender automáticamente a un ejecutable interno; también detecta la cabecera Compound cuando el tipo elegido es `7z`. Extraer las tablas MSI **no instala la aplicación** ni extrae automáticamente CAB externos.

## Inspeccionar

```sh
build/wins-native inspect '/tmp/wins-guide-npp-1107/notepad++.exe'
```

Salida real, abreviada:

```text
SHA256: b1bb271b558f6e33f357276fa530363c18494a4e9d3be973e3ccd8cb626b867d
Size: 8584176
PE: PE32+, machine=0x8664, sections=7
  .text: offset=1024 size=4548608
```

`inspect` calcula SHA-256 y lee cabeceras y secciones; no desensambla. Está limitado a archivos de 512 MiB.

## Inventariar imports del PE

Compila el controlador actualizado con un nombre nuevo para no sobrescribir una versión anterior:

```sh
zig build-exe native/main.zig -O ReleaseSafe -femit-bin=build/wins-pe
```

Salida real: ninguna. Inspecciona el ejecutable extraído:

```sh
build/wins-pe imports '/tmp/wins-guide-npp-1107/notepad++.exe'
```

Salida real, abreviada:

```text
SHA256: b1bb271b558f6e33f357276fa530363c18494a4e9d3be973e3ccd8cb626b867d
PE32+ machine=0x8664: 21 libraries, 629 imports
  COMCTL32.dll (24)
    ImageList_EndDrag (hint 95)
    ...
    ordinal #17
    ...
Delay imports: NOT_ANALYZED
```

Para alimentar otra herramienta, guarda el reporte estructurado. Elige un nombre nuevo: la redirección `>` sobrescribe un archivo existente:

```sh
build/wins-pe imports '/tmp/wins-guide-npp-1107/notepad++.exe' --json > /tmp/wins-guide-imports-1107.json
```

Salida real: ninguna; el JSON contiene SHA-256, arquitectura, DLL, nombres, ordinales e indicios (`hint`). El parser cubre la tabla normal de imports de PE32 y PE32+; los imports diferidos (`delay imports`), exports, desensamblado y firmas de funciones aún no se analizan. Los imports son un inventario de dependencias, no código fuente ni implementaciones portadas.

## Compilar y contrastar un candidato

La interfaz experimental admite funciones C puras de tipo `uint64_t(uint64_t)`: el candidato exporta `wins_candidate` y el oráculo independiente exporta `wins_oracle`. Los ejemplos están en `native/examples/`.

```sh
build/wins-native compile-c native/examples/candidate.c /tmp/wins-guide-candidate-1107 /home/danny/.local/opt/zig-x86_64-linux-0.16.0
```

Salida real:

```text
Compiled candidate.so. Compilation does not establish PE equivalence.
```

Compila también el oráculo y el candidato defectuoso; ambos producen la misma salida:

```sh
build/wins-native compile-c native/examples/oracle.c /tmp/wins-guide-oracle-1107 /home/danny/.local/opt/zig-x86_64-linux-0.16.0
```

```sh
build/wins-native compile-c native/examples/wrong.c /tmp/wins-guide-wrong-1107 /home/danny/.local/opt/zig-x86_64-linux-0.16.0
```

Para comparar los resultados:

```sh
build/wins-native compare /tmp/wins-guide-candidate-1107/candidate.so /tmp/wins-guide-oracle-1107/candidate.so build/wins-compare 10000
```

Salida real:

```text
MATCHED samples=10000 seed=11400714819323198485 (not a proof of equivalence)
```

Con el candidato incorrecto:

```sh
build/wins-native compare /tmp/wins-guide-wrong-1107/candidate.so /tmp/wins-guide-oracle-1107/candidate.so build/wins-compare 10000
```

Salida real, código 1:

```text
DIVERGENCE iteration=0 input=0 expected=1 actual=2
error: comparison: FuzzFailed
```

El corredor carga ambos ELF **dentro de la caja**; la comparación solo cubre la función y las entradas probadas, y ambos comparten proceso. Un oráculo correcto e independiente debe ser aportado por quien desarrolla el puerto. Las funciones con efectos laterales, punteros o estado aún no tienen un contrato aquí.

## Interpretar el resultado

| Resultado | Significado | Acción |
|---|---|---|
| `Extraction complete` | El extractor terminó con código 0. | Inspecciona la salida; no supone que el programa funcione. |
| `Compiled candidate.so` | Se compiló C para Linux. | Contrástalo con un oráculo apropiado. |
| `MATCHED` | No se encontraron diferencias en esas muestras. | Amplía el oráculo y los casos; no es una prueba general. |
| `DIVERGENCE` | Se encontró una entrada distinta. | Revisa entrada, resultado esperado y obtenido. |
| Error de `bwrap`, timeout o directorio existente | La operación no se completó. | Conserva la salida parcial y reintenta con un directorio nuevo. |

La caja usa espacios de nombres y tiempos límite, pero no establece cuotas de memoria o disco: usa una VM o límites adicionales si necesitas procesar material hostil. Extraer archivos no recompila ni traduce automáticamente un PE cerrado. El flujo Zig actual es experimental y no reemplaza aún todos los comandos y recetas Python. El `compile-fuzz` Python heredado está desactivado; el fuzzer Zig anterior contiene comparaciones de modelos que no demuestran equivalencia con el PE.
