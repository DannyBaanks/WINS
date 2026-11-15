# WINS Native Companion Manifests

This directory holds **native Linux build manifests** for the companion
executables that runtime-wrapped applications ship next to their payload
(`resources/bin/*.exe`: device agents, sidecars, utility hosts...).

WINS resolves a helper in this order:

1. **Local cache** — `~/.cache/wins/companions/<app_id>/<name>.linux-<arch>`.
2. **Manifest** — this directory plus `~/.config/wins/native-manifest.json`.
3. **Micro-Wine shim** — generated launcher when no native build exists.

## Manifest format

```json
{
  "apps": {
    "manus": {
      "linux_package": {
        "url": "https://vendor.example/manus-linux-x64.zip",
        "kind": "zip"
      },
      "binaries": {
        "manus-computer-operator": "resources/bin/manus-computer-operator"
      }
    }
  }
}
```

* `url` — `http(s)://` or `file://` location of the vendor Linux package.
* `kind` — `deb`, `zip`, `tar.gz`, `7z`, `appimage` or `raw`.
* `binaries` — maps the **extension-less host name** (the name the app spawns
  on Linux) to the path of the Linux ELF inside the package. A glob is
  accepted. When omitted, the package is searched by file name.

Files starting with `_` are ignored by the loader, so `_example.json` below is
documentation only.

## User manifests

`~/.config/wins/native-manifest.json` uses the exact same schema and takes
precedence over the built-in manifests.
