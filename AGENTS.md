# WINS agent contract

WINS researches Linux-native rehosting without Wine. Preserve the user's original
application and saves. A PE import inventory, a compiled shim, or a finite fuzz
run is not proof that a Windows program was ported or behaves equivalently.
Report unsupported, unknown and not-yet-tested behavior accurately.

## Turn unsupported cases into regression coverage

When an authorized WINS task encounters an unsupported package, binary, API,
installer, asset or runtime behavior:

1. Record the concrete input type, environment, exact failure, and the boundary
   of what was actually observed. Distinguish unsupported from missing tools,
   corruption, an incomplete analysis, and an untested hypothesis.
2. Reproduce the smallest useful case, preserving negative results. Improve the
   appropriate WINS parser, portability layer, fuzzer or corpus within the task's
   authorized scope; use an independent oracle or a known expected result and
   include a negative control when it meaningfully validates the fix. A test
   must exercise the actual candidate, not compare a function to itself.
3. Prefer synthetic or explicitly redistributable fixtures. Treat game files,
   proprietary binaries, saves, credentials and private paths as user data:
   never add them to git, upload them, or include their contents in a public PR
   without explicit permission and appropriate rights. A hash or minimal
   sanitized description can identify evidence without publishing the file.
4. Run focused regression and fuzz checks, preserve reproducible seeds and
   counterexamples, and state remaining limitations. If a case cannot yet be
   reproduced or fixed, record it as unresolved rather than claiming success.
5. When a generalizable improvement is worthwhile, prepare a concrete PR title,
   description, patch and validation for review. Recommend a PR to the user;
   obtain their explicit approval before pushing, creating a PR, or otherwise
   publishing anything. Never assume that permission to inspect or fix grants
   permission to redistribute the user's application or data.

These instructions do not expand authorization to run untrusted code outside
an appropriate isolation boundary, remove files, or modify unrelated work.

## Native-First Rule: Zig Engine & Wine Differential Oracle (Zero Heavy Python)

1. **System & Harness in Zig**: All loaders (`winrun`, `winrun_gui`), shims, memory allocators,
   fuzzers, and verification runners MUST be written in `.zig`. Python is strictly limited to
   top-level CLI dispatch (`bin/wins`) where inevitable.
2. **Wine is the Oracle of Truth**: Verification and differential correctness are proven against
   real Wine execution (comparing bit-identical exit codes, stdout, stderr, and window behavior
   inside cleanroom `bubblewrap`), NOT by writing synthetic Python mocks or slow `unittest` suites.
3. **No Heavy Python Test Suites**: Do not write or rely on heavy Python `unittest` suites that spawn
   fragile, slow subprocess loops with 180s timeouts. Use high-speed native Zig harnesses that execute
   in sub-millisecond time.

