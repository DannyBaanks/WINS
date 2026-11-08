"""
Tests for WINS Agnostic Runtime Interceptor (libwins_glhook.so)
"""

import os
import unittest
import ctypes
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class TestGLHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook_so = ROOT / "native" / "libwins_glhook.so"
        if not cls.hook_so.is_file():
            raise unittest.SkipTest("libwins_glhook.so not compiled")
        cls.lib = ctypes.CDLL(str(cls.hook_so))

    def test_steamworks_stubs(self):
        """Verifies Steamworks C API stub layer returns expected non-Wine values."""
        # SteamAPI_RestartAppIfNecessary must return False (0)
        restart_fn = self.lib.SteamAPI_RestartAppIfNecessary
        restart_fn.argtypes = [ctypes.c_uint32]
        restart_fn.restype = ctypes.c_bool
        self.assertFalse(restart_fn(268910))

        # SteamAPI_Init / InitSafe must return True (1)
        init_fn = self.lib.SteamAPI_Init
        init_fn.restype = ctypes.c_bool
        self.assertTrue(init_fn())

        init_safe = self.lib.SteamAPI_InitSafe
        init_safe.restype = ctypes.c_bool
        self.assertTrue(init_safe())

        # SteamAPI_IsSteamRunning must return True
        running_fn = self.lib.SteamAPI_IsSteamRunning
        running_fn.restype = ctypes.c_bool
        self.assertTrue(running_fn())

    def test_glx_proc_address_interception(self):
        """Verifies glXGetProcAddress returns hook for glShaderSource."""
        get_proc = self.lib.glXGetProcAddress
        get_proc.argtypes = [ctypes.c_char_p]
        get_proc.restype = ctypes.c_void_p

        ptr = get_proc(b"glShaderSource")
        self.assertIsNotNone(ptr)
        self.assertNotEqual(ptr, 0)

        ptr_arb = get_proc(b"glShaderSourceARB")
        self.assertIsNotNone(ptr_arb)
        self.assertEqual(ptr, ptr_arb)

    def test_transparent_overlay_redirection(self):
        """Verifies openat/open transparently redirects when file exists in overlays cache."""
        cache_overlay_dir = Path.home() / ".cache" / "wins" / "overlays"
        cache_overlay_dir.mkdir(parents=True, exist_ok=True)

        test_overlay = cache_overlay_dir / "test_hook_overlay.txt"
        test_overlay.write_text("WINS_OVERLAY_CONTENT_ACTIVE")

        # Open non-existent source file with matching filename via openat
        dummy_path = "/nonexistent/path/to/test_hook_overlay.txt"
        
        openat_fn = self.lib.openat
        openat_fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        openat_fn.restype = ctypes.c_int

        fd = openat_fn(ctypes.c_int(-100), dummy_path.encode(), ctypes.c_int(os.O_RDONLY))
        self.assertGreater(fd, 0, "openat should have redirected to overlay file")

        content = os.read(fd, 100).decode()
        os.close(fd)
        self.assertEqual(content, "WINS_OVERLAY_CONTENT_ACTIVE")

        # Cleanup test overlay
        test_overlay.unlink(missing_ok=True)

    def test_shader_cache_population(self):
        """Verifies that the WINS shader cache exists and contains transpiled GLSL shaders."""
        shader_cache = Path.home() / ".cache" / "wins" / "shaders"
        self.assertTrue(shader_cache.is_dir())
        manifest = shader_cache / "manifest.json"
        self.assertTrue(manifest.is_file())
        
        glsl_count = len(list(shader_cache.glob("*.glsl")))
        self.assertGreater(glsl_count, 100, f"Expected >100 transpiled shaders, found {glsl_count}")

if __name__ == "__main__":
    unittest.main()
