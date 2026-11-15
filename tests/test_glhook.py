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

        # SteamAPI_Init / InitSafe must return False (0) for graceful DRM-free standalone fallback
        init_fn = self.lib.SteamAPI_Init
        init_fn.restype = ctypes.c_bool
        self.assertFalse(init_fn())

        init_safe = self.lib.SteamAPI_InitSafe
        init_safe.restype = ctypes.c_bool
        self.assertFalse(init_safe())

        # SteamAPI_IsSteamRunning must return False (0)
        running_fn = self.lib.SteamAPI_IsSteamRunning
        running_fn.restype = ctypes.c_bool
        self.assertFalse(running_fn())

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

    def test_win32_dll_and_symbol_hunter(self):
        """Verifies dynamic interception of Win32 DLLs and API hunting/acceptance."""
        self.lib.dlopen.restype = ctypes.c_void_p
        self.lib.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.lib.dlsym.restype = ctypes.c_void_p
        self.lib.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        # 1. dlopen interceptor for Windows DLLs
        handle = self.lib.dlopen(b"user32.dll", 1)
        self.assertEqual(handle, 0x57494e53, "Expected synthetic WINS module handle")

        handle_kernel = self.lib.dlopen(b"kernel32.dll", 1)
        self.assertEqual(handle_kernel, 0x57494e53)

        # 2. Accepted Win32 API: GetCursorPos
        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_int32)]

        get_cursor_pos_ptr = self.lib.dlsym(handle, b"GetCursorPos")
        self.assertIsNotNone(get_cursor_pos_ptr)
        self.assertNotEqual(get_cursor_pos_ptr, 0)

        get_cursor_pos = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(POINT))(get_cursor_pos_ptr)
        pt = POINT(0, 0)
        res = get_cursor_pos(ctypes.byref(pt))
        self.assertEqual(res, 1)
        self.assertEqual(pt.x, 640)
        self.assertEqual(pt.y, 360)

        # 3. Accepted Win32 API: GetSystemMetrics
        metrics_ptr = self.lib.dlsym(handle, b"GetSystemMetrics")
        self.assertIsNotNone(metrics_ptr)
        get_metrics = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(metrics_ptr)
        self.assertEqual(get_metrics(0), 1920) # SM_CXSCREEN
        self.assertEqual(get_metrics(1), 1080) # SM_CYSCREEN

        # 4. Unhandled Win32 API: Hunter catches it, returns safe stub, and logs to journal
        unhandled_api_name = b"RandomUnhandledWin32Api_12345"
        stub_ptr = self.lib.dlsym(handle, unhandled_api_name)
        self.assertIsNotNone(stub_ptr, "Hunter should return safe fallback stub")
        self.assertNotEqual(stub_ptr, 0)

        # Invoking safe stub should execute without segfault
        safe_stub = ctypes.CFUNCTYPE(ctypes.c_void_p)(stub_ptr)
        stub_res = safe_stub()
        self.assertIsNone(stub_res)

        # Verify journal logging
        journal_file = Path.home() / ".cache" / "wins" / "telemetry" / "hunt_journal.jsonl"
        self.assertTrue(journal_file.is_file())
        journal_content = journal_file.read_text()
        self.assertIn("RandomUnhandledWin32Api_12345", journal_content)
        self.assertIn("UNHANDLED_BLOCKER", journal_content)

if __name__ == "__main__":
    unittest.main()
