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
