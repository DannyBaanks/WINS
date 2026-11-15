"""Runs INSIDE the sandbox: calls winlux_verify_trust on every file in a directory.
usage: harness.py CANDIDATE.so DIR  -> one JSON object per file on stdout."""
import ctypes, json, os, sys


class Verdict(ctypes.Structure):
    _fields_ = [('alg', ctypes.c_uint32), ('digest_len', ctypes.c_uint32),
                ('embedded', ctypes.c_ubyte * 64), ('computed', ctypes.c_ubyte * 64)]


lib = ctypes.CDLL(sys.argv[1])
lib.winlux_verify_trust.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(Verdict)]
lib.winlux_verify_trust.restype = ctypes.c_uint32
for name in sorted(os.listdir(sys.argv[2])):
    data = open(os.path.join(sys.argv[2], name), 'rb').read()
    v = Verdict()
    rc = lib.winlux_verify_trust(data, len(data), ctypes.byref(v))
    n = v.digest_len
    print(json.dumps({'file': name, 'rc': rc, 'alg': v.alg, 'embedded': bytes(v.embedded[:n]).hex(),
                      'computed': bytes(v.computed[:n]).hex()}))
