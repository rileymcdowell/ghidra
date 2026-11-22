#!/usr/bin/env python3
"""Generate Ghidra/Processors/SuperH/data/manuals/superh2e.idx.

Maps Sleigh mnemonics to PDF page numbers (1-based physical pages, as used by "#page=") in
the Renesas SH-2E Programming Manual (REJ09B0316-0200, Rev. 2.00), by finding the section 7
instruction headings ("7.2.1 ADD (ADD Binary): ...", "7.3.1 FABS (...)").

Needs pypdf (installed in the repo .venv). Usage: python sh-2e/tools/gen_idx.py [path-to-pdf]
"""

import re
import sys
from pathlib import Path

from pypdf import PdfReader

REPO = Path(__file__).resolve().parents[2]
PDF = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "sh-2e/sh-2e-software-manual.pdf"
OUT = REPO / "Ghidra/Processors/SuperH/data/manuals/superh2e.idx"
PDF_NAME = "sh-2e-software-manual.pdf"
TITLE = "SH-2E Software Manual (Programming Manual) Rev. 2.00, REJ09B0316-0200"

# Manual heading -> Sleigh mnemonics (see superh.sinc). Headings not listed map to their
# own lower-cased name.
EXPAND = {
    "AND": ["and", "and.b"], "CMP/cond": ["cmp/eq", "cmp/ge", "cmp/gt", "cmp/hi", "cmp/hs",
                                         "cmp/pl", "cmp/pz", "cmp/str"],
    "EXTS": ["exts.b", "exts.w"], "EXTU": ["extu.b", "extu.w"], "LDC": ["ldc", "ldc.l"],
    "LDS": ["lds", "lds.l"], "MAC.W": ["mac.w", "mac"], "MOV": ["mov", "mov.b", "mov.w", "mov.l"],
    "OR": ["or", "or.b"], "SHLLn": ["shll2", "shll8", "shll16"],
    "SHLRn": ["shlr2", "shlr8", "shlr16"], "STC": ["stc", "stc.l"], "STS": ["sts", "sts.l"],
    "SWAP": ["swap.b", "swap.w"], "TAS": ["tas.b"], "TST": ["tst", "tst.b"],
    "XOR": ["xor", "xor.b"], "FCMP": ["fcmp/eq", "fcmp/gt"], "FMOV": ["fmov", "fmov.s"],
}

TOC_LINE = re.compile(r"\.{6,}\s*\d+\s*$", re.M)
HEADING = re.compile(r"^7\.[23]\.\d+\s+(\S+)\s*\(.*$", re.M)


def main():
    reader = PdfReader(str(PDF))
    pages = {}
    order = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        if TOC_LINE.search(text):  # table of contents page; its entries look like headings
            continue
        for m in HEADING.finditer(text):
            name = m.group(1)
            for mn in EXPAND.get(name, [name.lower()]):
                if mn not in pages:  # first wins: CPU LDS/STS (7.2) before FPU forms (7.3)
                    pages[mn] = i
                    order.append(mn)
    lines = ["@ %s[%s]" % (PDF_NAME, TITLE)]
    lines += ["%s, %d" % (mn, pages[mn]) for mn in order]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("%d mnemonics -> %s" % (len(order), OUT))


if __name__ == "__main__":
    main()
