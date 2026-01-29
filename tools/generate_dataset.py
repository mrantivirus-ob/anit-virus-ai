#!/usr/bin/env python3
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
BENIGN = DATA / "benign"
MALWARE = DATA / "malware"

BENIGN.mkdir(parents=True, exist_ok=True)
MALWARE.mkdir(parents=True, exist_ok=True)

# Minimal benign PE (re-use minimal pattern)
def make_minimal_pe(path: Path):
    data = bytearray(512)
    data[0:2] = b'MZ'
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, 'little')
    if len(data) < pe_off + 64:
        data.extend(b'\x00' * (pe_off + 256 - len(data)))
    data[pe_off:pe_off+4] = b'PE\x00\x00'
    # COFF header
    data[pe_off+4:pe_off+6] = (0x014c).to_bytes(2, 'little')
    data[pe_off+6:pe_off+8] = (1).to_bytes(2, 'little')
    with open(path, 'wb') as f:
        f.write(data)

# Packed-like (UPX) variant
def make_packed_pe(path: Path):
    data = bytearray(1024)
    data[0:2] = b'MZ'
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, 'little')
    data[pe_off:pe_off+4] = b'PE\x00\x00'
    coff_off = pe_off + 4
    data[coff_off+16:coff_off+18] = (0x00B0).to_bytes(2, 'little')
    # Section header with UPX name
    sec_off = coff_off + 20
    data[sec_off:sec_off+3] = b'UPX'
    with open(path, 'wb') as f:
        f.write(data)

# Suspicious import strings appended
def make_suspicious_imports_pe(path: Path):
    data = bytearray(1024)
    data[0:2] = b'MZ'
    pe_off = 0x80
    data[0x3C:0x40] = pe_off.to_bytes(4, 'little')
    data[pe_off:pe_off+4] = b'PE\x00\x00'
    data.extend(b'GetProcAddress\0LoadLibraryA\0VirtualAlloc\0')
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
    make_minimal_pe(BENIGN / 'minimal_pe.bin')
    make_minimal_pe(BENIGN / 'minimal_pe_2.bin')
    make_packed_pe(MALWARE / 'packed_upx.bin')
    make_suspicious_imports_pe(MALWARE / 'suspicious_imports.bin')
    print('Sample dataset generated under data/')
