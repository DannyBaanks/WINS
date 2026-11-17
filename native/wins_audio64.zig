//! WINS Win64 audio surface: the DirectSound implementation (wins_dsound.zig,
//! already exercised on i386 by FalloutNV) exported for the x86-64 loader
//! (winrun64) as the emulated "dsound.dll".
//!
//! Why this file exists: FMOD is statically linked inside UnityPlayer.dll
//! (Cuphead_Data/Plugins ships only CSteamworks.dll and steam_api64.dll, no
//! fmod DLL). On Windows it takes the DirectSound output path: it calls
//! LoadLibraryA("dsound.dll"), then DirectSoundEnumerateW/A to count drivers
//! ("FMOD failed to get number of drivers" is that enumeration failing).
//! Under winrun64 the module did not exist at all: LoadLibraryA returned
//! ERROR_MOD_NOT_FOUND, so the engine logged
//! "FMOD failed to get number of drivers ... Error initializing output device"
//! and no sound played. Traced on :96 in /tmp/cuphead-wave2/audio/run1.
//!
//! The implementation itself is unchanged: wins_dsound.zig creates the
//! IDirectSound8 COM objects over memory-backed buffers and its software mixer
//! writes 48 kHz stereo to the host sound server (PipeWire/PulseAudio) through
//! wins_audio.zig. Only the export wiring for the Win64 loader lives here.
//!
//! What this does NOT do, deliberately and visibly:
//!   - no mmdevapi/WASAPI surface: the runtime trace shows FMOD never asks for
//!     it on this game (no mmdevapi.dll load, no MMDeviceEnumerator use);
//!   - no DirectSound capture (the capture entry points report DSERR_NODRIVER;
//!     an empty enumeration is the honest answer);
//!   - no EAX/effects beyond what wins_dsound.zig already states.

const std = @import("std");
const dsound = @import("wins_dsound.zig");

/// dsound.dll export lookup, for the Win64 loader's static/dynamic import
/// resolution and for GetProcAddress on the "dsound.dll" pseudo-handle.
pub fn lookup(name: []const u8) ?usize {
    return dsound.lookupDsound(name);
}

/// winrun64 registryOverride hook. The loader resolves every import through
/// `registryOverride(lib, sym)`; one call site covers static imports, delay
/// imports, dynamic LoadLibrary+GetProcAddress, and the module registry.
pub fn lookupOverride(key: []const u8, sym: []const u8) ?usize {
    if (!std.ascii.eqlIgnoreCase(key, "dsound.dll")) return null;
    return dsound.lookupDsound(sym);
}

test {
    // The Win64 surface answers the exact calls FMOD makes before the error:
    // the driver enumeration and the device creation.
    try std.testing.expect(lookup("DirectSoundEnumerateW") != null);
    try std.testing.expect(lookup("DirectSoundEnumerateA") != null);
    try std.testing.expect(lookup("DirectSoundCreate8") != null);
    try std.testing.expect(lookup("DirectSoundCreate") != null);
    // capture honestly reports no driver
    try std.testing.expect(lookup("DirectSoundCaptureCreate") != null);
    try std.testing.expect(lookupOverride("DSOUND.DLL", "DirectSoundCreate8") != null);
    try std.testing.expect(lookupOverride("winmm.dll", "timeGetTime") == null);
}