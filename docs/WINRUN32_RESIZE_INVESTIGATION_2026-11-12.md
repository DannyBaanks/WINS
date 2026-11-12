# winrun32: recommit regression and unresolved guest resize

On 2026-11-12, Zig 0.16.0 on Linux x86-64, the i386 loader at `6bbe43e`
was compared with Wine 9 in separate bubblewrap environments. The synthetic
`native/testdata/virtualalloc_probe.c` reserves and commits two pages, writes
`A` and `B`, then recommits the second page. Wine printed `AB` and exited 0;
the previous loader printed `A\0` and exited 1. The amended loader printed
`AB` and exited 0. The old loader serves as a negative control. Probe PE
SHA-256: `703088931bf084c1367c5ec8b46c57b7adf7b671accf509fa8c091e009c77581`.

The change handles commits within tracked reservations without replacing the
mapping. It does not establish complete Windows VirtualAlloc semantics: reserve
protection, committed-page tracking, protection changes, concurrent access to
the reservation table, decommit zeroing and reservation-table exhaustion
remain unverified or unimplemented.

## Real application: unresolved

The same user-owned application was run with the amended loader in the existing
isolated test environment, with game data mounted read-only. It still faulted at
`0x713eea`, attempting a write at address `0x34`. A debugger observed a list
whose first pointer was null. At its first growth from four to eight entries,
the first pointer was nonzero before the reallocation and zero afterwards.
The guest's size lookup returned zero for the old pointer, and the call then
entered `winrun32.HeapReAlloc`, whose unknown-block path allocates a fresh block
without copying. At that point the guest's ownership lookup bucket, indexed by
the pointer's high byte, pointed to a different pool in the same high-byte
range. This establishes the immediate data-loss path and a pool lookup mismatch,
not what caused the mismatch. Blindly copying an unknown number of bytes is not
a safe fix.

The raw local traces are temporary, not canonical permanent evidence:

- `/tmp/wins-resume/sandbox-output/trace-guest-va-codex.log`, SHA-256
  `76f8f7895071c7990951a948b3fa3cea3ff12e7428db3529b7e364622eb1b932`.
- `/tmp/wins-va-investigation/trace-resize-buckets.log`, SHA-256
  `652949eb47518ccd552ec5c9deb78343068d376d38ee3bea0f83a556ff302385`.
  This extends and supersedes the earlier temporary resize trace: that scratch
  path was inadvertently overwritten, so its previous hash is no longer
  verifiable.

The test does not demonstrate that the game runs, that the earlier `VirtualAlloc`
bug caused its crash, or that Wine exactly matches Windows. Original proprietary
game files are not included in this repository.

## Follow-up: requested reservation addresses

The guest repeatedly requested large reservations at a specific address already
occupied by the loader. WINS returned a different address and the guest's
high-byte ownership table subsequently pointed to the wrong pool. The loader now
uses a non-destructive mmap hint and fails if it cannot return the requested
address, instead of relocating or replacing a mapping. The expanded synthetic
probe also attempts to reserve already allocated pages: both Wine and the new
loader returned failure, preserved `AB`, and exited 0. The expanded probe PE
SHA-256 is `08f7ce16495ddc06d9395eef773afdc545369973ce8aca38a64048fc8786e6b7`.

In one isolated run with this change, the application advanced past the earlier
`0x713eea` crash into D3D9, then repeatedly invoked the unimplemented
`SetRenderTarget` path and the process exited 139. This is progress, not proof
of a working display or of the cause of the later termination. The local trace
`/tmp/wins-resume/sandbox-output/shipped-run-exact-codex.log` has SHA-256
`f0a0658f3b7b07c19d58e5a02f57098e6d2c7956827750fa793159d0d0c1d210`.

## Follow-up: implicit D3D9 surfaces

REA's GNU objdump provider inspected an 87-byte ELF wrapper made from the
runtime image at `0xe7cd50` (REA evidence
`ev_71b2bfcee1f8a8ca3ed756d59baaaefc3696693c020c2105542f5bfdb570f50f`).
The guest tests the HRESULT from the device vtable call and stores the new
render target only after success. The runtime image is a local memory dump,
SHA-256 `8f6507815c04b7589a9dccd55e27ac7b22a18c223bb0063f8693fb52c5d24392`;
the wrapper is a derived artifact, not the shipped executable. The native
decompilation providers were unavailable in the REA server used for this test.

WINS now accepts binding its own implicit backbuffer and implicit depth surface;
other surfaces and depth unbinding remain unimplemented. A standalone Win32
probe (`native/testdata/d3d_bind_probe.c`) ran under Wine 9 in a fresh prefix
and isolated Xvfb, exiting 0. It checked rebind success, viewport reset,
invalid null RT0, and implicit depth rebind; WINS was checked with Zig tests,
not by running this PE. Wine probe PE SHA-256:
`f60274ea3555d840a5d0bd8684c34d49651a6ad8361ec4c13ecf35fb041e6f67`.

An isolated application run passed both rebind calls, then faulted at
`0xe6ef7d`. REA evidence
`ev_360dd40a61d75f4116b1815dbada2cb5d8e1110d2bce280e75d7241098ac3c85`
shows the guest calls a method through a vtable and dereferences its nonzero
return as an object. The runtime debugger observed that return was `0x80004001`
from WINS `SetLight`; it is not a valid object. Why a D3D device reached this
guest dispatch path is unresolved. Returning fabricated pointers or blanket
success would hide the mismatch. Temporary raw trace:
`/tmp/wins-resume/sandbox-output/trace-guest-depth-codex.log`, SHA-256
`5d553d10de2904e901ab95ba535a68ebda11a1049ad4c3225b03807e464df3b7`.
No functioning application display or playable session is demonstrated.
