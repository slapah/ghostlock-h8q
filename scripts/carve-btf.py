#!/usr/bin/env python3
"""
carve-btf.py -- Extract the BTF blob appended to a Samsung kernel Image
and print the struct offsets the exploit cares about.

Run in WSL2 from the directory containing the decompressed kernel Image:

    python3 carve-btf.py Image

Requires: pahole  (sudo apt install pahole)
"""
import argparse
import re
import subprocess
import sys

BTF_MAGIC = b"\x9f\xeb\x01\x00"

STRUCTS = {
    "rt_mutex_waiter": [
        ("pi_tree", "FAKE_WAITER_PI_TREE_ENTRY_OFF"),
        ("pi_tree.prio", "FAKE_WAITER_PI_TREE_PRIO_OFF"),
        ("pi_tree.deadline", "FAKE_WAITER_PI_TREE_DEADLINE_OFF"),
        ("task", "FAKE_WAITER_TASK_OFF"),
        ("lock", "FAKE_WAITER_LOCK_OFF"),
        ("tree.prio", "FAKE_WAITER_TREE_PRIO_OFF"),
        ("tree.deadline", "FAKE_WAITER_TREE_DEADLINE_OFF"),
    ],
    "task_struct": [
        ("usage", "FAKE_TASK_USAGE_OFF"),
        ("prio", "FAKE_TASK_PRIO_OFF"),
        ("normal_prio", "FAKE_TASK_NORMAL_PRIO_OFF"),
        ("task_group", "FAKE_TASK_TASK_GROUP_OFF"),
        ("pi_lock", "FAKE_TASK_PI_LOCK_OFF"),
        ("pi_waiters", "FAKE_TASK_PI_WAITERS_OFF"),
        ("pi_top_task", "FAKE_TASK_PI_TOP_TASK_OFF"),
        ("pi_blocked_on", "FAKE_TASK_PI_BLOCKED_ON_OFF"),
        ("pid", "TASK_PID_OFF"),
        ("tgid", "TASK_TGID_OFF"),
        ("real_parent", "TASK_REAL_PARENT_OFF"),
        ("atomic_flags", "TASK_ATOMIC_FLAGS_OFF"),
        ("real_cred", "TASK_REAL_CRED_OFF"),
        ("cred", "TASK_CRED_OFF"),
        ("comm", "TASK_COMM_OFF"),
        ("tasks", "TASK_TASKS_OFF"),
        ("seccomp", "TASK_SECCOMP_OFF"),
    ],
}


def carve_btf(image_path, out_path):
    with open(image_path, "rb") as f:
        data = f.read()

    m = re.search(BTF_MAGIC, data)
    if not m:
        print(f"[-] BTF magic {BTF_MAGIC.hex()} not found in {image_path}", file=sys.stderr)
        sys.exit(1)

    off = m.start()
    print(f"[+] BTF found at Image offset {off:#x}")

    # BTF header: magic(2) version(1) flags(1) hdr_len(4)
    hdr_len = int.from_bytes(data[off + 4 : off + 8], "little")
    print(f"[+] BTF header length: {hdr_len}")

    btf = data[off:]
    with open(out_path, "wb") as f:
        f.write(btf)
    print(f"[+] Wrote {len(btf)} bytes to {out_path}")
    return out_path


def pahole_offset(btf_path, struct_name, member_path):
    """Return byte offset of member_path in struct_name using pahole."""
    # pahole can print a single member with -C Struct::member
    full = f"{struct_name}::{member_path}"
    try:
        out = subprocess.check_output(
            ["pahole", "-C", full, btf_path],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None

    # pahole output for a member looks like:
    #   unsigned int                     prio;                    /*  1488     4 */
    mm = re.search(r"/\*\s+(\d+)\s+\d+\s*\*/", out)
    if mm:
        return int(mm.group(1))

    # Fallback: parse the whole struct dump
    out = subprocess.check_output(
        ["pahole", "-C", struct_name, btf_path],
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return _parse_member_offset(out, member_path)


def _parse_member_offset(pahole_output, member_path):
    parts = member_path.split(".")
    base_offset = 0
    text = pahole_output

    for part in parts:
        # Match a line like:
        #   struct rb_node                   pi_tree;                 /*    40    24 */
        pattern = re.compile(
            rf"^\s*.*?\s+{re.escape(part)};\s*/\*\s+(\d+)\s+\d+\s*\*/",
            re.MULTILINE,
        )
        m = pattern.search(text)
        if not m:
            return None
        base_offset += int(m.group(1))
        # Restrict further search to the region after this member for nested lookups
        text = text[m.end():]

    return base_offset


def load_target_h(target_h_path):
    values = {}
    try:
        with open(target_h_path) as f:
            for line in f:
                m = re.match(r"^\s*#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)(?:\s+|\s*$)", line)
                if m:
                    values[m.group(1)] = int(m.group(2), 0)
    except FileNotFoundError:
        pass
    return values


def main():
    parser = argparse.ArgumentParser(description="Carve BTF from a Samsung kernel Image")
    parser.add_argument("image", help="path to decompressed kernel Image")
    parser.add_argument("-o", "--output", default="vmlinux.btf", help="output BTF file")
    parser.add_argument("-t", "--target-h", help="target.h to compare offsets against")
    args = parser.parse_args()

    btf_path = carve_btf(args.image, args.output)

    print("\n[+] Struct offsets from BTF (compare with target.h):\n")
    target_values = load_target_h(args.target_h) if args.target_h else {}

    for struct_name, members in STRUCTS.items():
        print(f"struct {struct_name}:")
        for member_path, macro in members:
            off = pahole_offset(btf_path, struct_name, member_path)
            if off is None:
                print(f"  ?  {member_path:30s} -> could not resolve")
                continue
            line = f"  0x{off:04x} {member_path:30s} -> {macro}"
            if macro in target_values:
                expected = target_values[macro]
                mark = "OK" if off == expected else f"MISMATCH (target=0x{expected:04x})"
                line += f"  [{mark}]"
            print(line)
        print()

    print("[+] Next step: run find-trace-caller.py against a vmlinux.elf of this kernel")


if __name__ == "__main__":
    main()
