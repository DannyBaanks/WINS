WINS Steam compatibility tool: Cuphead (AppID 268910)

This Steam tool starts the installed 64-bit Cuphead.exe with the WINS Win64 PE
loader. It does not use Proton or Wine. Source: the WINS repository,
launch/cuphead.

Build and install (from a WINS checkout):
  mkdir -p /tmp/wins-cuphead-build
  cd native
  zig build-exe winrun64.zig \
      -O ReleaseSafe -lc -lX11 \
      -femit-bin=/tmp/wins-cuphead-build/winrun64
  cd ..
  launch/cuphead/install.sh /tmp/wins-cuphead-build

The normal tools/build_all.sh target does not currently emit winrun64, so the
explicit build command above is required.

Install for Danny:
  1. Build the loader as shown above. Do not modify the installed Cuphead
     directory; the launcher mounts it read-only.
  2. Run: launch/cuphead/install.sh /tmp/wins-cuphead-build
     By default this installs under
     ~/.steam/root/compatibilitytools.d/WINS-Cuphead. The installer does not
     delete data: a file it would replace is retained as
     <name>.prev-<sha256 prefix>.
  3. Fully restart Steam so it discovers the newly installed compatibility tool.
  4. In Steam, open Cuphead > Properties > Compatibility.
  5. Select "WINS (Cuphead)" and choose "Force specific Steam Play
     compatibility tool" (or the equivalent checkbox/dropdown, depending on
     the Steam client version).
  6. Click Play. Steam invokes launch/cuphead/wins with the compatibility
     verb; that entry point launches launch/cuphead/launch-cuphead with
     STEAM_COMPAT_APP_ID=268910.

Approved Win64 game images (SHA-256):
  Cuphead.exe             c5fffd221234ea520b9b5d545d9fff65eba497a0ce1b852334d293770d7ee02d
  UnityPlayer.dll         598135e374441121d797689f6864f44b07d13c9deef0a8b1c40d7d2537399e11
  mono.dll                db4eeb83af1ac262adf1be2469a4e81c68edfa4550e90580aec0063b09b4775e
  MonoPosixHelper.dll     f94476b90aa43fce8da30b5b12d488825e967d1ce176d390336fb31ce2f5dc24
  steam_api64.dll         81321a5cb72ae3f81243fd0b0d8928a063ca09129ab0878573bd36a28422ec4c
  CSteamworks.dll         ad50bb3aaf00ecc3d58c6b69ebab73ae7ad4f2e18625303811a744e0e2af7c57

The launcher verifies these before starting and passes the same pins to
winrun64. A Steam game update which changes any of them is refused; review the
new binary and update the pins deliberately. No game file or proprietary PE is
copied into this repository by the installer.

Host access inside the cleanroom:
  - X11 display and Xauthority are passed through for the game window.
  - /dev/dri and the NVIDIA device nodes are exposed for GPU rendering.
    WINS_GPU=integrated keeps the default GLX GPU instead of NVIDIA PRIME.
  - The PulseAudio runtime socket is exposed; PULSE_SERVER is preserved when
    it is already set.
  - /dev/shm is exposed so the live Steam client can share its
    ValveIPCSharedObj-Steam object. The launcher identifies the one Steam
    process which owns that object and never fabricates Steam ownership.
  - /dev/input is read-only so the SDL2 GameController backend can read
    attached controllers.

Data and safety:
  - The installed Cuphead directory is mounted read-only at both the WINS game
    path and the loader's C:\\ mapping. The loader never writes into the Steam
    installation.
  - The original Steam save directory and Unity persistent data are not
    mounted. WINS keeps its own profile under
    ~/.local/share/wins/cuphead/profile, including
    AppData/LocalLow/StudioMDEntertainment/Cuphead for Unity saves/settings.
  - Loader logs are in ~/.local/state/wins/cuphead/logs.
  - WINS_KEEP_RUN_DIR=1 keeps the temporary workspace for diagnosis.

Requirements (Debian/Ubuntu package names):
  bubblewrap, sha256sum, coreutils, Steam running, libx11-6, libgl1,
  libpulse0, libsdl2-2.0-0, and the normal 64-bit NVIDIA/DRM GL driver when
  NVIDIA rendering is wanted.

Status and limits:
  - This is an experimental Win64 compatibility tool, not a statement that
    Cuphead is fully equivalent to Windows.
  - The launcher reaches the title screen in the wave-2 cleanroom run; a
    complete Cuphead play-through has not been certified by this tool.
  - RawInput APIs are routed before the legacy USER32 placeholders, so
    Unity/Rewired can initialize its RawInput backend. Gamepad state is
    supplied through the XInput/SDL2 path; do not interpret successful
    RawInput initialization as proof that every physical HID device is
    modelled.
  - The exact Win64 loader wiring for xinput1_3.dll, xinput1_4.dll,
    xinput9_1_0.dll and ordinal 100 (XInputGetStateEx) is recorded in
    /tmp/cuphead-input-launch-report.md for the loader maintainer.
  - Steam IPC participation and a real Steam Play-button click are not
    certified by this repository; the launcher requires a live Steam client
    and refuses to fabricate Steam ownership.

If it fails, attach the launcher log. A SHA-256 refusal means the installed
Cuphead build differs from the approved pins; a loader import error names the
exact unresolved PE import or ordinal.
