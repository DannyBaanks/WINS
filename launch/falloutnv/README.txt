WINS Steam compatibility tool: Fallout: New Vegas (AppID 22380)

This Steam tool starts the game's own FalloutNV.exe with the WINS i386 PE loader.
It does not use Proton or Wine. Source: the WINS repository, launch/falloutnv.

Install (from a WINS checkout):
  tools/build_all.sh /tmp/wins-build        (a new, empty directory)
  launch/falloutnv/install.sh /tmp/wins-build
Restart Steam once, then Fallout: New Vegas > Properties > Compatibility, force
"WINS (Fallout: New Vegas)". Reinstalling never deletes anything: a file it would
replace is kept as <name>.prev-<sha256 prefix>.

What works (observed in play-throughs, see libs/GAPS.md and libs/registry.json for
which libraries have actually been run):
  - the menu, New Game, character creation, Continue from a save, the Mojave exterior
  - sound effects, Pip-Boy sounds, voices, music; Bink intro video
  - on a laptop with an NVIDIA GPU it renders on that GPU (WINS_GPU=integrated opts out)
What is not known to work, and has not been tested: long play sessions, every quest,
combat-heavy scenes, water and cube-mapped surfaces (SetClipPlane and cube/volume
samplers are not implemented), controllers, mods and script extenders, saves from
other machines. Experimental software: keep your own backups of saves you care about.

Requirements (Debian/Ubuntu package names; all i386 except bubblewrap):
  bubblewrap, python3 (identifies Steam's IPC process), Steam running
  libx11-6:i386 libgl1:i386 libpulse0:i386 libmpg123-0t64:i386
  libvorbisfile3:i386 libavcodec60:i386 libavutil58:i386
  NVIDIA GPU rendering also needs the 32-bit driver GL libraries (libnvidia-gl-<version>:i386).

Data and safety:
  - The installed game is read-only to the launcher: it copies the small game-root
    files into a fresh /tmp workspace and mounts the original Data directory read-only.
  - Your original "My Games" folder and Steam saves are NOT mounted. WINS keeps its own
    profile (ini files, new saves) in ~/.local/share/wins/falloutnv/profile.
  - Loader logs: ~/.local/state/wins/falloutnv/logs (first lines name the WINS libraries
    and versions the run used: "[WINS:libs] used: ...").
  - WINS_KEEP_RUN_DIR=1 in the Steam launch options keeps the temporary workspace.

If it fails: "Application load error S:0000065432" is Steam's and usually goes away on a
second launch. Anything else: attach the log; its [WINS:libs] line says which versions ran.
