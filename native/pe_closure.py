#!/usr/bin/env python3
"""Dependency closure of an MSI-installed PE inside its external CAB.

Static only: parses PE headers (imports, delay imports, CLR header) and extracts
members with an external extractor into a NEW directory. Nothing is executed.
Libraries not found in the CAB are reported as `unresolved` (OS, redistributables).

usage: pe_closure.py CAB MSI_FILE_TSV ROOT_FILE_KEY NEW_OUT_DIR REPORT.json EXTRACTOR_7Z
"""
import json, struct, subprocess, sys, hashlib
from pathlib import Path


def parse_pe(path):
    d = Path(path).read_bytes()
    if d[:2] != b'MZ': return None
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    if d[pe:pe+4] != b'PE\0\0': return None
    mach, nsec, _, _, _, osz, _ = struct.unpack_from('<HHIIIHH', d, pe+4)
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    is64 = magic == 0x20b
    dd = opt + (112 if is64 else 96)
    ndd = struct.unpack_from('<I', d, dd - 4)[0]
    dirs = [struct.unpack_from('<II', d, dd + 8*i) for i in range(min(ndd, 16))]
    secs = []
    so = opt + osz
    for i in range(nsec):
        vs, va, rs, ro = struct.unpack_from('<IIII', d, so + 40*i + 8)
        secs.append((va, max(vs, rs), ro))
    def off(rva):
        for va, sz, ro in secs:
            if va <= rva < va + sz: return rva - va + ro
        return None
    def cstr(rva):
        o = off(rva)
        if o is None: return None
        e = d.index(b'\0', o)
        return d[o:e].decode('latin1')
    ptr = 8 if is64 else 4
    def thunks(rva):
        names = []
        o = off(rva)
        if o is None: return names
        while True:
            v = int.from_bytes(d[o:o+ptr], 'little')
            if v == 0: break
            if v >> (ptr*8-1):
                names.append('#%d' % (v & 0xFFFF))
            else:
                n = cstr((v & 0x7FFFFFFF) + 2)
                names.append(n)
            o += ptr
            if len(names) > 200000: break
        return names
    imports, delay = {}, {}
    if dirs[1][0]:
        o = off(dirs[1][0])
        while o is not None:
            ot, _, _, nm, ft = struct.unpack_from('<IIIII', d, o)
            if nm == 0 and ft == 0: break
            imports.setdefault(cstr(nm).lower(), []).extend(thunks(ot or ft))
            o += 20
    if len(dirs) > 13 and dirs[13][0]:
        o = off(dirs[13][0])
        while o is not None:
            attrs, nm, mod, iat, int_, bound, unb, ts = struct.unpack_from('<IIIIIIII', d, o)
            if nm == 0: break
            delay.setdefault(cstr(nm).lower(), []).extend(thunks(int_))
            o += 32
    clr = len(dirs) > 14 and dirs[14][0] != 0
    return dict(is64=is64, machine=mach, imports=imports, delay=delay, clr=clr, size=len(d),
                sha256=hashlib.sha256(d).hexdigest())

def main():
    global Z, CAB, OUT, FILE_TSV, ROOT_KEY
    if len(sys.argv) != 7: sys.exit(__doc__)
    CAB, FILE_TSV, ROOT_KEY, OUT, REPORT, Z = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5]), sys.argv[6]
    names = {}
    for line in FILE_TSV.read_text(encoding='utf-8', errors='replace').splitlines()[3:]:
        c = line.split('\t')
        if len(c) < 3: continue
        nm = c[2].split('|')[-1].lower()
        names.setdefault(nm, []).append(c[0])
    OUT.mkdir(exist_ok=False)  # never reuse an output directory
    report = {'root': ROOT_KEY, 'pe': {}, 'unresolved': {}, 'missing_in_cab': {}}
    seen_keys, queue = set(), [ROOT_KEY]
    level = 0
    while queue:
        todo = [k for k in queue if k not in seen_keys]
        seen_keys.update(todo)
        queue = []
        if not todo: break
        subprocess.run([Z, 'x', f'-o{OUT}', str(CAB), *todo, '-y'], check=True, capture_output=True)
        for k in todo:
            p = parse_pe(OUT / k)
            if p is None: continue
            fname = next((n for n, ks in names.items() if k in ks), k)
            p['name'] = fname; p['level'] = level
            report['pe'][k] = p
            for lib, fns in list(p['imports'].items()) + list(p['delay'].items()):
                keys = names.get(lib)
                if keys:
                    queue.extend(x for x in keys if x not in seen_keys)
                else:
                    report['unresolved'].setdefault(lib, set()).update(f for f in fns if f)
        level += 1
        print('level', level - 1, 'extracted', len(todo), 'next', len(set(queue)), file=sys.stderr)
    report['unresolved'] = {k: sorted(v) for k, v in sorted(report['unresolved'].items())}
    json.dump(report, open(REPORT, 'w'), indent=1)
    print('PE files:', len(report['pe']), 'external libs:', len(report['unresolved']))

main()
