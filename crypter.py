#!/usr/bin/env python3

import pefile
import struct
import random
import os
import sys
import argparse
import math
from collections import Counter


def pe_checksum(pe_data, checksum_offset):
    size = len(pe_data)
    cksum = 0
    for i in range(0, size & ~1, 2):
        if checksum_offset <= i < checksum_offset + 4:
            continue
        val = pe_data[i] | (pe_data[i + 1] << 8)
        cksum += val
        cksum = (cksum & 0xFFFF) + (cksum >> 16)
    if size & 1:
        cksum += pe_data[-1]
        cksum = (cksum & 0xFFFF) + (cksum >> 16)
    cksum = (cksum & 0xFFFF) + (cksum >> 16)
    return cksum + size


def count_text_relocs(pe, text_rva, text_size):
    if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        return 0
    count = 0
    text_end = text_rva + text_size
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type != 0 and text_rva <= entry.rva < text_end:
                count += 1
    return count


def make_lcg64():
    mult = random.getrandbits(64) | 1
    inc = random.getrandbits(64) | 1
    return mult, inc, pow(mult, -1, 2**64)


def fisher_yates_shuffle(blocks, seed, mult, inc):
    n = len(blocks)
    result = list(blocks)
    state = seed
    for i in range(n - 1, 0, -1):
        state = (state * mult + inc) & (2**64 - 1)
        j = (state >> 33) % (i + 1)
        result[i], result[j] = result[j], result[i]
    return result, state


def verify_unshuffle(blocks_shuffled, seed, mult, inc, mult_inv, n):
    state = seed
    for _ in range(n - 1):
        state = (state * mult + inc) & (2**64 - 1)
    result = list(blocks_shuffled)
    for i in range(1, n):
        j = (state >> 33) % (i + 1)
        result[i], result[j] = result[j], result[i]
        state = ((state - inc) * mult_inv) & (2**64 - 1)
    return result


def _emit_hash_loop(code, top_offset):
    code += b'\x44\x32\x17\x4D\x0F\xAF\xD3\x48\xFF\xC7\xFF\xC9\x75'
    code += struct.pack('b', top_offset - (len(code) + 1))
    return code


def build_stub(delta_to_text, n_blocks, block_size, oep_offset,
               seed_placeholder, lcg_mult, lcg_inc, lcg_mult_inv,
               tls_mode=False, original_cb_offset=0):
    code = bytearray()
    pk = struct.pack

    if tls_mode:
        code += b'\x53\x55\x56\x57\x51\x52\x41\x50'

    code += b'\xE8\x00\x00\x00\x00\x5D'
    pic = len(code) - 1
    code += b'\x48\x8D\x9D' + pk('<i', -delta_to_text)

    seed_code_offset = len(code) + 2
    code += (b'\x48\xBE' + pk('<Q', seed_placeholder)
             + b'\x49\xBA' + pk('<Q', 0xcbf29ce484222325)
             + b'\x49\xBB' + pk('<Q', 0x00000100000001b3)
             + b'\x48\x8D\xBD' + pk('<i', -pic)
             + b'\xB9' + pk('<I', seed_code_offset))

    hash1_top = len(code)
    code = _emit_hash_loop(code, hash1_top)

    code += b'\x48\x83\xC7\x08'
    part2_patch = len(code) + 1
    code += b'\xB9' + pk('<I', 0)

    hash2_top = len(code)
    code = _emit_hash_loop(code, hash2_top)

    code += (b'\x4C\x31\xD6'
             + b'\xB9' + pk('<I', n_blocks - 1)
             + b'\x49\xB8' + pk('<Q', lcg_mult)
             + b'\x49\xB9' + pk('<Q', lcg_inc))

    fwd_top = len(code)
    code += b'\x49\x0F\xAF\xF0\x4C\x01\xCE\xFF\xC9\x75'
    code += pk('b', fwd_top - (len(code) + 1))

    code += (b'\x49\xB8' + pk('<Q', lcg_mult_inv)
             + b'\xB9\x01\x00\x00\x00')

    undo_top = len(code)
    code += b'\x81\xF9' + pk('<I', n_blocks) + b'\x0F\x8D'
    jge_patch = len(code)
    code += b'\x00\x00\x00\x00'
    code += b'\x48\x89\xF0\x48\xC1\xE8\x21\x31\xD2\x4C\x8D\x51\x01\x49\xF7\xF2'
    code += b'\x39\xD1\x74'
    je_patch = len(code)
    code += b'\x00\x51\x56\x52'

    if block_size <= 127:
        code += b'\x44\x6B\xD1' + pk('B', block_size)
    else:
        code += b'\x44\x69\xD1' + pk('<I', block_size)
    code += b'\x4C\x03\xD3'

    if block_size <= 127:
        code += b'\x44\x6B\xDA' + pk('B', block_size)
    else:
        code += b'\x44\x69\xDA' + pk('<I', block_size)
    code += b'\x4C\x03\xDB'

    code += b'\xB9' + pk('<I', block_size)

    swap_top = len(code)
    code += (b'\x41\x8A\x02\x41\x8A\x13\x41\x88\x12\x41\x88\x03'
             b'\x49\xFF\xC2\x49\xFF\xC3\xFF\xC9\x75')
    code += pk('b', swap_top - (len(code) + 1))

    code += b'\x5A\x5E\x59'
    code[je_patch] = (len(code) - (je_patch + 1)) & 0xFF

    code += b'\x4C\x29\xCE\x49\x0F\xAF\xF0\xFF\xC1\xEB'
    code += pk('b', undo_top - (len(code) + 1))

    struct.pack_into('<i', code, jge_patch, len(code) - (jge_patch + 4))

    if tls_mode:
        code += b'\x48\x8D\x83' + pk('<i', original_cb_offset)
        code += b'\x41\x58\x5A\x59\x5F\x5E\x5D\x5B\xFF\xE0'
    else:
        code += b'\x48\x8D\x83' + pk('<i', oep_offset) + b'\xFF\xE0'

    struct.pack_into('<I', code, part2_patch, len(code) - seed_code_offset - 8)
    return bytes(code), seed_code_offset


def crypt(input_path, output_path, block_size=16, seed=None):
    random.seed(seed if seed is not None else os.urandom(32))

    def _fnv(data):
        h = 0xcbf29ce484222325
        for b in data:
            h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
        return h

    pe = pefile.PE(input_path)
    if pe.FILE_HEADER.Machine != 0x8664:
        raise RuntimeError("x64 only")

    print("[*] Architecture: x64")
    print(f"[*] ImageBase:    0x{pe.OPTIONAL_HEADER.ImageBase:X}")

    text_sec = next((s for s in pe.sections if s.Name.rstrip(b'\x00').lower() == b'.text'), None)
    if text_sec is None:
        raise RuntimeError("No .text section")

    text_name = text_sec.Name.rstrip(b'\x00').decode(errors='replace')
    text_rva = text_sec.VirtualAddress
    text_raw = text_sec.PointerToRawData
    text_virt = text_sec.Misc_VirtualSize
    text_raw_size = text_sec.SizeOfRawData
    text_data = text_sec.get_data()[:text_virt]
    cave_size = text_raw_size - text_virt
    cave_offset = text_virt
    print(f"[*] {text_name}:       0x{text_rva:X}, virt={text_virt}, raw={text_raw_size}")
    print(f"[*] Code cave:    {cave_size}B at {text_name}+0x{cave_offset:X}")

    n_text_relocs = count_text_relocs(pe, text_rva, text_virt)
    if n_text_relocs > 0:
        raise RuntimeError(f".text has {n_text_relocs} relocations")
    print("[*] .text relocs: 0 (ASLR-safe)")

    oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if not (text_rva <= oep_rva < text_rva + text_virt):
        raise RuntimeError(f"OEP 0x{oep_rva:X} not in {text_name}")
    oep_offset_in_text = oep_rva - text_rva
    print(f"[*] OEP:          0x{oep_rva:X}")

    n_blocks = text_virt // block_size
    remainder = text_virt - n_blocks * block_size
    if n_blocks < 2:
        raise RuntimeError(f"Too small: {text_virt}B")
    print(f"[*] Blocks:       {n_blocks} (bs={block_size}, {remainder}B remainder)")

    lcg_seed = random.getrandbits(64) or 1
    lcg_mult, lcg_inc, lcg_mult_inv = make_lcg64()
    print("[*] Key space:    128-bit")

    tls_mode = False
    original_cb_rva = 0
    original_cb_offset_in_text = 0
    tls_cb_file_offset = None

    tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
    if tls_dir.VirtualAddress and tls_dir.Size and hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
        cb_rva = tls_struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        cb_data = pe.get_data(cb_rva, 8)
        first_cb = struct.unpack('<Q', cb_data)[0]
        if first_cb:
            original_cb_rva = first_cb - pe.OPTIONAL_HEADER.ImageBase
            if text_rva <= original_cb_rva < text_rva + text_virt:
                tls_mode = True
                for s in pe.sections:
                    if s.VirtualAddress <= cb_rva < s.VirtualAddress + s.SizeOfRawData:
                        tls_cb_file_offset = s.PointerToRawData + (cb_rva - s.VirtualAddress)
                        break
                original_cb_offset_in_text = original_cb_rva - text_rva
                print(f"[*] TLS callback: 0x{original_cb_rva:X} -> TLS mode")
    if not tls_mode:
        print("[*] Mode:         EP redirect")

    tls_preamble = 8 if tls_mode else 0
    stub_rva = text_rva + cave_offset
    delta_to_text = (stub_rva + tls_preamble + 5) - text_rva

    stub, seed_offset = build_stub(
        delta_to_text=delta_to_text, n_blocks=n_blocks, block_size=block_size,
        oep_offset=oep_offset_in_text, seed_placeholder=0,
        lcg_mult=lcg_mult, lcg_inc=lcg_inc, lcg_mult_inv=lcg_mult_inv,
        tls_mode=tls_mode, original_cb_offset=original_cb_offset_in_text)

    with open(input_path, 'rb') as f:
        pe_data = bytearray(f.read())
    original_size = len(pe_data)
    expanded = False

    if len(stub) > cave_size:
        file_align = pe.OPTIONAL_HEADER.FileAlignment
        needed = len(stub) - cave_size
        expand_by = ((needed + file_align - 1) // file_align) * file_align

        insert_pos = text_raw + text_raw_size
        pe_data[insert_pos:insert_pos] = b'\x00' * expand_by

        text_header_off = text_sec.get_file_offset()
        text_raw_size += expand_by
        cave_size += expand_by
        pe_data[text_header_off + 16:text_header_off + 20] = struct.pack('<I', text_raw_size)

        for s in pe.sections:
            if s.PointerToRawData > text_raw:
                s_hdr = s.get_file_offset()
                old_ptr = struct.unpack('<I', pe_data[s_hdr + 20:s_hdr + 24])[0]
                pe_data[s_hdr + 20:s_hdr + 24] = struct.pack('<I', old_ptr + expand_by)

        if tls_cb_file_offset is not None and tls_cb_file_offset > text_raw + text_raw_size - expand_by:
            tls_cb_file_offset += expand_by

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress:
            opt_off = pe.OPTIONAL_HEADER.get_file_offset()
            old_sec_va = struct.unpack('<I', pe_data[opt_off + 144:opt_off + 148])[0]
            if old_sec_va > text_raw + text_raw_size - expand_by:
                pe_data[opt_off + 144:opt_off + 148] = struct.pack('<I', old_sec_va + expand_by)

        expanded = True
        print(f"[*] Cave expand:  +{expand_by}B (FileAlign={file_align}), cave now {cave_size}B")

    print(f"[*] Stub:         {len(stub)}B into {cave_size}B cave")

    hash_input = stub[:seed_offset] + stub[seed_offset + 8:]
    stub_hash = _fnv(hash_input)
    embedded_seed = (lcg_seed ^ stub_hash) & (2**64 - 1)
    stub = stub[:seed_offset] + struct.pack('<Q', embedded_seed) + stub[seed_offset + 8:]
    verify_input = stub[:seed_offset] + stub[seed_offset + 8:]
    assert (embedded_seed ^ _fnv(verify_input)) & (2**64 - 1) == lcg_seed
    print("[*] Anti-tamper:  verified")

    blocks = [text_data[i*block_size:(i+1)*block_size] for i in range(n_blocks)]
    remainder_data = text_data[n_blocks * block_size:]
    shuffled_blocks, _ = fisher_yates_shuffle(blocks, lcg_seed, lcg_mult, lcg_inc)
    shuffled_data = b''.join(shuffled_blocks) + remainder_data

    changed = sum(1 for a, b in zip(text_data, shuffled_data) if a != b)
    print(f"[*] Changed:      {changed}/{len(text_data)} ({100*changed/len(text_data):.1f}%)")

    restored = verify_unshuffle(shuffled_blocks, lcg_seed, lcg_mult, lcg_inc, lcg_mult_inv, n_blocks)
    if restored != blocks:
        raise RuntimeError("Unshuffle verification FAILED")
    print("[*] Unshuffle:    verified")

    pe_data[text_raw:text_raw + len(shuffled_data)] = shuffled_data
    pe_data[text_raw + cave_offset:text_raw + cave_offset + len(stub)] = stub

    text_header_off = text_sec.get_file_offset()
    new_virt_size = cave_offset + len(stub)
    pe_data[text_header_off + 8:text_header_off + 12] = struct.pack('<I', new_virt_size)
    print(f"[*] .text virt:   {text_virt} -> {new_virt_size}")

    tc_off = text_header_off + 36
    old_c = struct.unpack('<I', pe_data[tc_off:tc_off + 4])[0]
    pe_data[tc_off:tc_off + 4] = struct.pack('<I', old_c | 0x80000000)

    opt_offset = pe.OPTIONAL_HEADER.get_file_offset()
    if tls_mode:
        new_cb_va = pe.OPTIONAL_HEADER.ImageBase + stub_rva
        pe_data[tls_cb_file_offset:tls_cb_file_offset + 8] = struct.pack('<Q', new_cb_va)
        print(f"[*] TLS patched:  -> 0x{stub_rva:X} (in {text_name})")
    else:
        pe_data[opt_offset + 16:opt_offset + 20] = struct.pack('<I', stub_rva)
        print(f"[*] EP patched:   -> 0x{stub_rva:X} (in {text_name})")

    print(f"[*] ASLR:         {'preserved' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 else 'was off'}")

    checksum_offset = opt_offset + 64
    pe_data[checksum_offset:checksum_offset + 4] = b'\x00\x00\x00\x00'
    cksum = pe_checksum(pe_data, checksum_offset)
    pe_data[checksum_offset:checksum_offset + 4] = struct.pack('<I', cksum)
    print(f"[*] Checksum:     0x{cksum:08X}")

    with open(output_path, 'wb') as f:
        f.write(pe_data)

    overhead = len(pe_data) - original_size
    print(f"\n[+] Output:       {output_path} ({len(pe_data)}B, +{overhead}B)")
    print(f"[+] Sections:     {pe.FILE_HEADER.NumberOfSections} (unchanged)")
    mode = "expanded cave" if expanded else "cave"
    print(f"[+] Injection:    {text_name}+0x{cave_offset:X} ({len(stub)}B in {mode})")
    return True


def verify_output(output_path, original_path=None):
    try:
        pe = pefile.PE(output_path)
    except pefile.PEFormatError as e:
        print(f"[-] FAILED: {e}"); return False

    names = [s.Name.rstrip(b'\x00').decode(errors='replace') for s in pe.sections]
    print(f"\n[V] Sections:     {', '.join(names)} ({len(pe.sections)} total)")

    if original_path:
        ope = pefile.PE(original_path)
        onames = [s.Name.rstrip(b'\x00').decode(errors='replace') for s in ope.sections]
        print(f"[V] Match orig:   {names == onames}")
        ope.close()

    text = next((s for s in pe.sections if s.Name.rstrip(b'\x00').lower() == b'.text'), None)
    if text:
        sc = text.Characteristics
        flags = f"{'R' if sc & 0x40000000 else ''}{'W' if sc & 0x80000000 else ''}{'X' if sc & 0x20000000 else ''}"
        print(f"[V] .text flags:  {flags}")
        print(f"[V] .text virt:   {text.Misc_VirtualSize}")
        print(f"[V] .text raw:    {text.SizeOfRawData}")

    rwx = [s.Name.rstrip(b'\x00').decode() for s in pe.sections
           if (s.Characteristics & 0x40000000) and (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000)]
    print(f"[V] RWX sections: {rwx if rwx else 'none'}")

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_sec = "?"
    for s in pe.sections:
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_sec = s.Name.rstrip(b'\x00').decode(errors='replace'); break
    print(f"[V] EP:           0x{ep:X} in {ep_sec}")
    print(f"[V] ASLR:         {'on' if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 else 'off'}")
    print(f"[V] Relocs:       {'present' if pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress else 'zeroed'}")
    print(f"[V] Checksum:     0x{pe.OPTIONAL_HEADER.CheckSum:08X}")

    if text:
        data = text.get_data()
        if data:
            counts = Counter(data); total = len(data)
            ent = -sum((c/total) * math.log2(c/total) for c in counts.values() if c)
            print(f"[V] Entropy:      {ent:.2f} bits/byte")
    pe.close()
    return True


def main():
    p = argparse.ArgumentParser(description='PE Block-Shuffle Crypter (x64, code cave)')
    p.add_argument('input', help='Input PE (x64 only)')
    p.add_argument('-o', '--output', help='Output path')
    p.add_argument('-b', '--block-size', type=int, default=16)
    p.add_argument('-s', '--seed', type=int, default=None)
    args = p.parse_args()

    if not os.path.isfile(args.input):
        print(f"[-] Not found: {args.input}"); sys.exit(1)
    if args.output is None:
        base, ext = os.path.splitext(args.input)
        args.output = f"{base}_crypted{ext}"
    if args.block_size < 4:
        print("[-] Block size >= 4"); sys.exit(1)

    print(f"{'='*60}")
    print("  PE Block-Shuffle Crypter (code cave injection)")
    print(f"{'='*60}")
    print(f"[*] Input:        {args.input}")
    print(f"[*] Output:       {args.output}")
    print(f"[*] Block size:   {args.block_size}\n")

    try:
        crypt(args.input, args.output, args.block_size, args.seed)
    except Exception as e:
        print(f"\n[-] FAILED: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    verify_output(args.output, args.input)


if __name__ == '__main__':
    main()