#!/usr/bin/env python3
"""Generate Ghidra/Processors/SuperH/data/languages/sh7058.pspec.

Inputs (relative to the repo root):
  sh-2e/notes/sh7058_registers.csv  address_hex,size_bits,module,name,description
                                    (addresses may be truncated to 16 bits, e.g. 0000D000)
  sh-2e/notes/sh7058_vectors.csv    vector_number,offset_hex,name (numbers may be ranges "7-8")

The CSV came from a text extraction of the SH7058 hardware manual (Rev. 3.0, REJ09B0177).
FIXES/ADDITIONS below correct it against Appendix A (Table A.1) and the per-module register
tables; page numbers are the manual's printed page numbers.

Usage: python sh-2e/tools/gen_pspec.py [--check | --vector-names]
  --check         only validate and compare with the existing pspec, and check that the
                  VECTOR_NAMES table in ghidra_scripts/SH7058_RawImageSetup.java matches the CSV;
                  exit 1 if either is stale.
  --vector-names  print the 232-entry VECTOR_NAMES Java array body for the setup script.

Stdlib only.
"""

import csv
import re
import sys
from pathlib import Path
from xml.sax.saxutils import quoteattr

REPO = Path(__file__).resolve().parents[2]
REG_CSV = REPO / "sh-2e/notes/sh7058_registers.csv"
VEC_CSV = REPO / "sh-2e/notes/sh7058_vectors.csv"
OUT = REPO / "Ghidra/Processors/SuperH/data/languages/sh7058.pspec"

RAM_START, RAM_END = 0xFFFF0000, 0xFFFFBFFF
IO_START, IO_END = 0xFFFFC000, 0xFFFFFFFF
NUM_VECTORS = 232  # 0..231; 232-255 are unassigned on the SH7058
# Only vectors 0-15 are emitted at address 0. Resets always fetch vectors 0-3 from address 0,
# but every other exception goes through VBR + 4*n, and firmware may move VBR and put code at
# 0x40. Labelling 16-231 at 0 would turn that code into junk code pointers. The full 0-231 table
# is laid down at the image's real VBR by
# Ghidra/Processors/SuperH/ghidra_scripts/SH7058_RawImageSetup.java, which embeds the same names.
PSPEC_VECTORS = 16
SETUP_SCRIPT = REPO / "Ghidra/Processors/SuperH/ghidra_scripts/SH7058_RawImageSetup.java"
SINC = REPO / "Ghidra/Processors/SuperH/data/languages/superh.sinc"


def imask_offset():
    """Register-space offset of imask (the SR.I3-I0 mirror), read from superh.sinc."""
    m = re.search(r"define register offset=(0x[0-9A-Fa-f]+) size=1 \[imask\];",
                  SINC.read_text(encoding="utf-8"))
    if not m:
        sys.exit("superh.sinc: no 1-byte imask register definition")
    return int(m.group(1), 16)

# address -> (new name, new size in bits or None, new description or None)
FIXES = {
    # HCAN-II timer block, Table 16.7 (p.581) and Table A.1: D08C is ICR0_tm, not "ICR0".
    0xFFFFD08C: ("ICR0_tm_0", None, "HCAN0 input capture register for timer counter (ICR0_tm0)"),
    0xFFFFD88C: ("ICR0_tm_1", None, "HCAN1 input capture register for timer counter (ICR0_tm1)"),
    # WDT RSTCSR: word write at EC12, byte read at EC13 (p.444). Give the write alias its own name.
    0xFFFFEC12: ("RSTCSR_W", 16, "WDT reset control/status register, write address (word write with key)"),
    # SYSCR2: word write at F70A, byte read at F70B (Table A.1 notes, section 25.2.3/25.2.4).
    0xFFFFF70A: ("SYSCR2_W", 16, "System control register 2, write address (word write only)"),
    0xFFFFF700: (None, None, "Pulse output port control register (APC); bits PULS7RO-PULS0RO / PULS7SO-PULS0SO"),
}

# (address, size_bits, module, name, description) not in the CSV
ADDITIONS = [
    # HCAN-II timer registers missed by the extractor (Table 16.7, p.581; Table A.1).
    (0xFFFFD08A, 16, "HCAN0", "ICR0_cc_0", "HCAN0 input capture register for cycle counter (ICR0_cc0)"),
    (0xFFFFD09C, 16, "HCAN0", "CCR_buf_0", "HCAN0 cycle counter double buffer (CCR_buf0)"),
    (0xFFFFD09E, 16, "HCAN0", "ICR0_buf_0", "HCAN0 input capture double buffer (ICR0_buf0)"),
    (0xFFFFD88A, 16, "HCAN1", "ICR0_cc_1", "HCAN1 input capture register for cycle counter (ICR0_cc1)"),
    (0xFFFFD89C, 16, "HCAN1", "CCR_buf_1", "HCAN1 cycle counter double buffer (CCR_buf1)"),
    (0xFFFFD89E, 16, "HCAN1", "ICR0_buf_1", "HCAN1 input capture double buffer (ICR0_buf1)"),
    # SYSCR2 read address (byte).
    (0xFFFFF70B, 8, "SYSTEM/APC", "SYSCR2", "System control register 2, read address (byte read only)"),
    # A/D control/status registers (section 17 register table, Table A.1).
    (0xFFFFF818, 8, "A/D", "ADCSR0", "A/D control/status register 0"),
    (0xFFFFF838, 8, "A/D", "ADCSR1", "A/D control/status register 1"),
    (0xFFFFF858, 8, "A/D", "ADCSR2", "A/D control/status register 2"),
    # Port registers (pin values, read only), section 22 tables, Table A.1.
    (0xFFFFF780, 16, "PFC/IO-PORTS", "PAPR", "Port A port register (pin values)"),
    (0xFFFFF782, 16, "PFC/IO-PORTS", "PBPR", "Port B port register (pin values)"),
    (0xFFFFF784, 16, "PFC/IO-PORTS", "PDPR", "Port D port register (pin values)"),
    (0xFFFFF786, 16, "PFC/IO-PORTS", "PJPR", "Port J port register (pin values)"),
    (0xFFFFF788, 16, "PFC/IO-PORTS", "PLPR", "Port L port register (pin values)"),
]

# HCAN-II mailboxes 0-31 (Table 16.2, p.527): 0x20 apart from base+0x100.
HCAN_MB_FIELDS = [(0x00, 48, "CTRL", "message control"), (0x06, 16, "TS", "timestamp"),
                  (0x08, 64, "DATA", "message data 0-7"), (0x10, 32, "LAFM", "LAFM / transmit trigger time")]
for ch, base in ((0, 0xFFFFD000), (1, 0xFFFFD800)):
    for mb in range(32):
        for off, bits, tag, desc in HCAN_MB_FIELDS:
            ADDITIONS.append((base + 0x100 + 0x20 * mb + off, bits, "HCAN%d" % ch,
                              "HCAN%d_MB%d_%s" % (ch, mb, tag),
                              "HCAN%d mailbox %d %s" % (ch, mb, desc)))

# Fixed exception vectors, Table 6.3 (p.87). Names for vectors not listed come from the CSV.
FIXED_VECTOR_NAMES = {
    0: "PowerOnReset_PC", 1: "PowerOnReset_SP", 2: "ManualReset_PC", 3: "ManualReset_SP",
    4: "GeneralIllegalInstruction", 6: "SlotIllegalInstruction", 9: "CPUAddressError",
    10: "DMACAddressError", 11: "NMI", 12: "UserBreak", 13: "FPUException", 14: "H_UDI",
}
STACK_POINTER_VECTORS = {1, 3}

# Overlapping symbols that are intentional (read/write aliases).
ALLOWED_OVERLAPS = {("RSTCSR_W", "RSTCSR"), ("SYSCR2_W", "SYSCR2")}

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name.strip())


def load_registers():
    regs = []
    with open(REG_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            raw = int(row["address_hex"], 16)
            addr = 0xFFFF0000 | (raw & 0xFFFF)
            if raw > 0xFFFF and raw != addr:
                raise SystemExit("unexpected address %s" % row["address_hex"])
            size = int(row["size_bits"])
            module = row["module"].strip()
            name = sanitize(row["name"])
            desc = row["description"].strip() or "%s %s" % (module, row["name"].strip())
            fix = FIXES.get(addr)
            if fix:
                name = fix[0] or name
                size = fix[1] or size
                desc = fix[2] or desc
            regs.append((addr, size, module, name, desc))
    regs.extend(ADDITIONS)
    return regs


def vector_name(n, csv_name):
    if n in FIXED_VECTOR_NAMES:
        return FIXED_VECTOR_NAMES[n]
    if csv_name is None or csv_name.lower() == "reserved":
        return "Reserved_%d" % n
    if csv_name.startswith("Trap instruction"):
        return "Trap_%d" % n
    s = re.sub(r"\s*\(.*?\)", "", csv_name)          # drop "(ATU01)" style group labels
    s = re.sub(r"^ATU-II ch\d+ ", "ATU_", s)        # "ATU-II ch0 ICI0A" -> "ATU_ICI0A"
    s = s.replace("A/D", "AD").replace("/", "_")
    return sanitize(s.replace(" ", "_"))


def load_vectors():
    names = {}
    with open(VEC_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            num = row["vector_number"].strip()
            lo, _, hi = num.partition("-")
            for n in range(int(lo), int(hi or lo) + 1):
                names[n] = row["name"].strip()
    vecs = []
    for n in range(NUM_VECTORS):
        csv_name = names.get(n)
        label = "v_" + vector_name(n, csv_name)
        desc = "Vector %d (offset 0x%03X): %s" % (n, 4 * n, csv_name or "reserved")
        vecs.append((4 * n, n, label, desc))
    return vecs


def validate(regs, vecs):
    errors = []
    names = {}
    for addr, size, module, name, desc in regs:
        if not (IO_START <= addr <= IO_END):
            errors.append("register %s at %08X is outside the I/O block" % (name, addr))
        align = 2 if size > 32 else size // 8  # 48/64-bit entries are HCAN mailbox fields
        if size not in (8, 16, 32, 48, 64) or addr % align:
            errors.append("register %s at %08X has bad size/alignment %d" % (name, addr, size))
        if addr + size // 8 - 1 > IO_END:
            errors.append("register %s runs past the I/O block" % name)
    for item in [(r[3], r[0]) for r in regs] + [(v[2], v[0]) for v in vecs]:
        name, addr = item
        if not NAME_RE.match(name):
            errors.append("invalid label %r" % name)
        if name in names:
            errors.append("duplicate name %s at %08X and %08X" % (name, names[name], addr))
        names[name] = addr
    by_addr = {}
    for addr, size, module, name, desc in regs:
        if addr in by_addr:
            errors.append("duplicate address %08X: %s, %s" % (addr, by_addr[addr], name))
        by_addr[addr] = name
    srt = sorted(regs)
    for a, b in zip(srt, srt[1:]):
        if a[0] + a[1] // 8 > b[0] and (a[3], b[3]) not in ALLOWED_OVERLAPS:
            errors.append("overlap: %s %08X/%d and %s %08X" % (a[3], a[0], a[1], b[3], b[0]))
    if errors:
        raise SystemExit("validation failed:\n  " + "\n  ".join(errors))


def render(regs, vecs):
    out = []
    w = out.append
    w('<?xml version="1.0" encoding="UTF-8"?>')
    w("")
    w("<!--")
    w("  Renesas (Hitachi) SH7058: SH-2E core, 1 MB flash, 48 KB RAM, 16 KB on-chip peripherals.")
    w("  GENERATED by sh-2e/tools/gen_pspec.py from the SH7058 Hardware Manual (Rev. 3.0)")
    w("  register list and exception vector table. Edit the generator, not this file.")
    w("")
    w("  Only vectors 0-15 are labelled at address 0. Resets always read vectors 0-3 from address 0;")
    w("  other exceptions use VBR + 4*n, and firmware may move VBR and place code at 0x40.")
    w("  Run ghidra_scripts/SH7058_RawImageSetup.java to label the full 0-231 table at the real VBR.")
    w("-->")
    w("<processor_spec>")
    w('  <programcounter register="pc"/>')
    w("")
    w("  <!-- On-chip peripheral space (Table 9.3) is volatile for the decompiler whatever the")
    w("       memory block flags say. (The IO block below is also volatile.)")
    w("       imask (SR.I3-I0, see superh.sinc) is volatile so that every LDC/RTE write to the")
    w("       interrupt mask is printed, including one overwritten before any read (a raise/restore")
    w("       bracket) or followed by an infinite loop. On SH-2E nothing reads imask (STC and TRAPA")
    w("       read sr), so this adds no read temporaries. -->")
    w('  <volatile outputop="write_volatile" inputop="read_volatile">')
    w('    <range space="ram" first="0x%08X" last="0x%08X"/>' % (IO_START, IO_END))
    w('    <range space="register" first="0x%X" last="0x%X"/> <!-- imask -->' %
      (imask_offset(), imask_offset()))
    w("  </volatile>")
    w("")
    w("  <default_symbols>")
    w("    <!-- Exception vector table, Table 6.3 / Table 7.3 -->")
    for addr, n, label, desc in vecs[:PSPEC_VECTORS]:
        if n in STACK_POINTER_VECTORS:
            attrs = 'size="4"'
        else:
            attrs = 'size="4" entry="true" type="code_ptr"'
        w('    <symbol name=%s address="0x%08X" %s description=%s/>' %
          (quoteattr(label), addr, attrs, quoteattr(desc)))
    w("")
    w("    <!-- On-chip peripheral registers, Appendix A Table A.1 -->")
    module = None
    for addr, size, mod, name, desc in sorted(regs):
        if mod != module:
            w("    <!-- %s -->" % mod.replace("--", "-"))
            module = mod
        w('    <symbol name=%s address="0x%08X" size="%d" description=%s/>' %
          (quoteattr(name), addr, size // 8, quoteattr(desc)))
    w("  </default_symbols>")
    w("")
    w("  <default_memory_blocks>")
    w('    <memory_block name="RAM" start_address="0x%08X" length="0x%X" mode="rwx" initialized="false"/>' %
      (RAM_START, RAM_END - RAM_START + 1))
    w('    <memory_block name="IO" start_address="0x%08X" length="0x%X" mode="rwv" initialized="false"/>' %
      (IO_START, IO_END - IO_START + 1))
    w("  </default_memory_blocks>")
    w("</processor_spec>")
    return "\n".join(out) + "\n"


def java_vector_names(vecs):
    """The VECTOR_NAMES array body embedded in SH7058_RawImageSetup.java (names without "v_")."""
    names = [label[2:] for addr, n, label, desc in vecs]
    lines, cur = [], "\t\t"
    for nm in names:
        item = '"%s", ' % nm
        if len(cur) + len(item) > 96:
            lines.append(cur.rstrip())
            cur = "\t\t"
        cur += item
    lines.append(cur.rstrip().rstrip(","))
    return "\n".join(lines) + "\n"


def check_script_names(vecs):
    """Check that the setup script's embedded vector-name table matches the CSV."""
    if not SETUP_SCRIPT.exists():
        print("setup script not found, vector-name check skipped:", SETUP_SCRIPT)
        return True
    src = SETUP_SCRIPT.read_text(encoding="utf-8")
    m = re.search(r"VECTOR_NAMES\s*=\s*\{(.*?)\};", src, re.S)
    if not m:
        print("VECTOR_NAMES not found in", SETUP_SCRIPT)
        return False
    got = re.findall(r'"([^"]*)"', m.group(1))
    want = [label[2:] for addr, n, label, desc in vecs]
    if got != want:
        print("VECTOR_NAMES in %s is OUT OF DATE (regenerate with --vector-names)" % SETUP_SCRIPT)
        return False
    print("setup script vector names up to date (%d)" % len(got))
    return True


def main():
    regs = load_registers()
    vecs = load_vectors()
    validate(regs, vecs)
    text = render(regs, vecs)
    print("registers: %d (csv %d, added %d), vectors: %d, symbols: %d" %
          (len(regs), len(regs) - len(ADDITIONS), len(ADDITIONS), PSPEC_VECTORS,
           len(regs) + PSPEC_VECTORS), file=sys.stderr if "--vector-names" in sys.argv else sys.stdout)
    if "--vector-names" in sys.argv:
        print(java_vector_names(vecs), end="")
        return
    if "--check" in sys.argv:
        same = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("pspec up to date" if same else "OUT OF DATE: %s" % OUT)
        ok = check_script_names(vecs)
        sys.exit(0 if same and ok else 1)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
