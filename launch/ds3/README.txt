WINS Steam compatibility tool: DARK SOULS III (AppID 374320)

This Steam tool starts the installed 64-bit DarkSoulsIII.exe with the WINS
Win64 PE loader (winrun64). It does not use Proton or Wine. Source: the WINS
repository, launch/ds3.

Build and install (from a WINS checkout):
  mkdir -p /tmp/wins-ds3-build
  cd native
  zig build-exe winrun64.zig \
      -O ReleaseSafe -lc -lX11 \
      -femit-bin=/tmp/wins-ds3-build/winrun64
  cd ..
  launch/ds3/install.sh /tmp/wins-ds3-build

Install steps:
  1. Build winrun64 as shown above. Do not modify the installed DARK SOULS III
     directory; the launcher mounts it read-only.
  2. Run: launch/ds3/install.sh /tmp/wins-ds3-build
     By default this installs under
     ~/.steam/root/compatibilitytools.d/WINS-DS3. The installer never deletes
     data: a file it would replace is backed up as
     <name>.prev-<sha256 prefix>.
  3. Fully restart Steam so it discovers the compatibility tool.
  4. In Steam, open DARK SOULS III > Properties > Compatibility.
  5. Enable "Force the use of a specific Steam Play compatibility tool" and
     select "WINS (Dark Souls III)".
  6. Click Play (recommended: play in Offline mode; do not connect to
     FromSoftware online servers with an experimental third-party runtime).

Approved Win64 game images (SHA-256):
  DarkSoulsIII.exe        ef5e07c55222f14ffddecf2c724a0c2a95cef0d4da0e075b0de0bb108b69498c
  steam_api64.dll         fc20547408a7c34f0bd4946a34c21aab48a75e3b98dce9e55969f486d37b212f
  fmodex64.dll            3cfda68e1488c1ba7171b218da27f2feded47b958352a9240a5ce78831794468
  fmod_event64.dll        27008d07df0ccfa5ad66ca6820e34fe378388515fecb0c22c48daeb26379c314
  binkw64.dll             d43ab5a4cbd84b4a41a71d5e17c049ca8f14e84ddcd4e300ed4196886de20e2e

steamclient64.dll belongs to the live Steam client and updates with Steam;
launch-ds3 computes its SHA-256 at launch time, mounts it read-only, and pins
that exact digest into winrun64. A game update that changes any pinned image
is refused until reviewed and updated deliberately. No proprietary game files
are stored in this repository.

Host access inside the cleanroom:
  - X11 display and Xauthority are passed through for the 1920x1080 game window.
  - /dev/dri and the NVIDIA device nodes are exposed for OpenGL 4.5 rendering.
    WINS_GPU=integrated keeps the default GLX GPU instead of NVIDIA PRIME.
  - The PulseAudio/PipeWire runtime socket is exposed for FMOD Ex audio.
  - /dev/shm is exposed so the live Steam client can share its
    ValveIPCSharedObj-Steam object. The launcher never fabricates Steam
    ownership.
  - /dev/input is exposed read-only for gamepad/input devices.

Data, logs, and diagnostics:
  - The installed game directory is mounted read-only; WINS never writes into
    the Steam game folder.
  - Saves and GraphicsConfig.xml live in an isolated profile under
    ~/.local/share/wins/ds3/profile (original Steam/Proton saves untouched).
  - Loader logs go to ~/.local/state/wins/ds3/logs/.
  - Optional diagnostics (all off by default, pass via Steam Launch Options):
      WINS_KEEP_RUN_DIR=1         keep the temporary workspace after exit
      WINS_D3D11_DUMP_DIR=<dir>   dump translated GLSL and DXBC shaders
      WINS_D3D11_CAPTURE=<dir>    capture failed shader DXBCs
      WINS_D3D11_TRACE_DRAWS=1    log per-frame draw calls
      WINS_D3D11_SNAP_TRIG=1      enable on-demand 1-frame snapshot via
                                  `touch ~/.local/share/wins/ds3/profile/snap_req`
                                  (writes draws.log, final.ppm, shaders to snap_out/)
      WINS_ALLOW_NO_STEAM=1       diagnostic offline-IPC mode (no Steam bridge)

Requirements (Debian/Ubuntu package names):
  bubblewrap, sha256sum, coreutils, util-linux (setsid), Steam running,
  libx11-6, libgl1, libpulse0, libsdl2-2.0-0, and the 64-bit NVIDIA/DRM GL
  driver.

Demonstrated (observed by hand on Ubuntu 24.04, RTX 4050, X11, 2026-11-23):
  - Steam Play button launches DarkSoulsIII.exe under winrun64 with live
    SteamClient017 IPC and SteamStub unpack.
  - Title screen, menus, EULA, character creation (3D knight), loading screens,
    and in-game Cemetery of Ash at 1920x1080 fullscreen.
  - Full SM5 DXBC -> GLSL 4.20 pipeline: VS, HS/DS tessellation (quad, tri,
    isoline), GS, PS, CS compute shaders, deferred contexts, volumetric sky
    clouds, lighting/god rays, bloom, water reflections and dynamic ripples.
  - FMOD Ex audio via DirectSound -> PipeWire, keyboard, mouse (DirectInput8 /
    Win32), and gamepad input.

Not demonstrated / limits:
  - Play offline only; online multiplayer / FromSoftware servers are untested
    and strongly discouraged with an experimental runtime.
  - Full playthrough, bosses, late-game areas, DLCs, Steam Cloud, Steam
    overlay, achievements, and non-NVIDIA GPUs are not demonstrated.
  - Stream-output GS and long-session GL view lifetime cleanup remain open.
