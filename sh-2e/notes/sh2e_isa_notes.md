# SH-2E FPU / ISA notes for a SLEIGH processor spec

Source: `sh2e_programming_manual.txt` (Renesas SH-2E Programming Manual, Rev. 2.00, May 2006, REJ09B0316-0200).

Page citations use the **printed** page number ("page X of 336"). The file's `=== PAGE N ===` markers equal printed page + 12 (e.g. printed p.14 = marker PAGE 26).

Text-extraction caveats: the FPSCR figure (p.14) is scrambled and was reconstructed from its field labels, its number string, the reset value and the LDS write mask (p.47 / p.202). The special-case tables for FCMP, FMAC, FTRC are partly mangled; the pseudo-code was used where the tables were unreadable.

---

## 1. FPU instructions (complete list)

Encodings are from Table 6.9 (p.42), Table 6.11 (alphabetical, p.46-47) and Section 7.3 (p.168-204), which agree except where noted in section 7 below. All FPU opcodes have high nibble `1111`. Execution cycles = 1 unless noted.

| Mnemonic | Operands | Encoding | Operation | Notes |
|---|---|---|---|---|
| FADD | FRm,FRn | 1111nnnnmmmm0000 | FRn = FRn + FRm | p.172 |
| FSUB | FRm,FRn | 1111nnnnmmmm0001 | FRn = FRn - FRm | p.196 |
| FMUL | FRm,FRn | 1111nnnnmmmm0010 | FRn = FRn * FRm | p.192 |
| FDIV | FRm,FRn | 1111nnnnmmmm0011 | FRn = FRn / FRm | **13 cycles**, p.179 |
| FCMP/EQ | FRm,FRn | 1111nnnnmmmm0100 | T = (FRn == FRm) | writes T; p.175 |
| FCMP/GT | FRm,FRn | 1111nnnnmmmm0101 | T = (FRn > FRm) | writes T; p.175 |
| FMOV | FRm,FRn | 1111nnnnmmmm1100 | FRn = FRm | p.188 |
| FMOV.S | @(R0,Rm),FRn | 1111nnnnmmmm0110 | FRn = (R0+Rm) | index addressing only |
| FMOV.S | @Rm+,FRn | 1111nnnnmmmm1001 | FRn = (Rm); Rm += 4 | p.188 |
| FMOV.S | @Rm,FRn | 1111nnnnmmmm1000 | FRn = (Rm) | |
| FMOV.S | FRm,@(R0,Rn) | 1111nnnnmmmm0111 | (R0+Rn) = FRm | |
| FMOV.S | FRm,@-Rn | 1111nnnnmmmm1011 | Rn -= 4; (Rn) = FRm | p.188 |
| FMOV.S | FRm,@Rn | 1111nnnnmmmm1010 | (Rn) = FRm | |
| FMAC | FR0,FRm,FRn | 1111nnnnmmmm1110 | FRn = FR0*FRm + FRn | FR0 is implicit; p.185-186 |
| FABS | FRn | 1111nnnn01011101 | FRn = \|FRn\| | p.170 |
| FNEG | FRn | 1111nnnn01001101 | FRn = -FRn | p.194 |
| FLDI0 | FRn | 1111nnnn10001101 | FRn = 0x00000000 | p.181 |
| FLDI1 | FRn | 1111nnnn10011101 | FRn = 0x3F800000 (1.0) | p.182 |
| FLOAT | FPUL,FRn | 1111nnnn00101101 | FRn = (float)FPUL (signed int) | p.184 |
| FTRC | FRm,FPUL | 1111mmmm00111101 | FPUL = (long)FRm, truncate | see note 3, p.199-200 |
| FLDS | FRm,FPUL | 1111mmmm00011101 | FPUL = FRm (bit copy) | see note 3, p.183 |
| FSTS | FPUL,FRn | 1111nnnn00001101 | FRn = FPUL (bit copy) | p.195 |

Pattern for the "unary" group (low byte = `xxxx1101`, operand in nnnn or mmmm): `0x0D` FSTS, `0x1D` FLDS, `0x2D` FLOAT, `0x3D` FTRC, `0x4D` FNEG, `0x5D` FABS, `0x8D` FLDI0, `0x9D` FLDI1.

Pattern for the "binary" group (low nibble selects op, `nnnn`=FRn, `mmmm`=FRm): `0`=FADD, `1`=FSUB, `2`=FMUL, `3`=FDIV, `4`=FCMP/EQ, `5`=FCMP/GT, `6`=FMOV.S @(R0,Rm), `7`=FMOV.S FRm,@(R0,Rn), `8`=FMOV.S @Rm, `9`=FMOV.S @Rm+, `A`=FMOV.S FRm,@Rn, `B`=FMOV.S FRm,@-Rn, `C`=FMOV FRm,FRn, `E`=FMAC.

Total: 22 FPU encodings (15 non-FMOV mnemonics + 7 FMOV forms).

### FPU-related CPU instructions (p.43, p.201-204)

| Instruction | Encoding | Operation |
|---|---|---|
| LDS Rm,FPUL | 0100mmmm01011010 | FPUL = Rm |
| LDS.L @Rm+,FPUL | 0100mmmm01010110 | FPUL = (Rm); Rm += 4 |
| LDS Rm,FPSCR | 0100mmmm01101010 | FPSCR = Rm & 0x00018C60 (see section 3) |
| LDS.L @Rm+,FPSCR | 0100mmmm01100110 | FPSCR = (Rm) & 0x00018C60; Rm += 4 |
| STS FPUL,Rn | 0000nnnn01011010 | Rn = FPUL |
| STS.L FPUL,@-Rn | 0100nnnn01010010 | Rn -= 4; (Rn) = FPUL |
| STS FPSCR,Rn | 0000nnnn01101010 | Rn = FPSCR |
| STS.L FPSCR,@-Rn | 0100nnnn01100010 | Rn -= 4; (Rn) = FPSCR |

Manual typo: Table 6.10 (p.43) writes "STS.L FPCSR" for the FPSCR store.

Notes on the mnemonics: FPUL-to-FR moves are `FSTS`/`FLDS` (not `FMOV`). FMOV FRm,FRn exists only as the 1100 encoding; there is no separate FMOV.S register form.

### Manual inconsistencies in the encodings

1. **FMUL vs "FMOV.S FRm,FRn"**: Table 6.11 (p.47, line ~2160) lists "FMOV.S FRm,FRn ... 1111nnnnmmmm0010". This is a typo; 0010 is FMUL (Table 6.9 p.42 and section 7.3.11 p.192). The real FMOV register form is 1100.
2. **FLDS and FTRC operand letter**: Table 6.9 and Table 6.11 use `1111mmmm` (source FRm in bits 11-8). Section 7 headers (p.183 FLDS, p.199 FTRC) print `1111nnnn`. The source register is FRm, so `mmmm` is the consistent reading. The register field is bits 11-8 either way (bits 7-0 are the fixed `00011101`/`00111101`); Ghidra and binutils both decode it there (checked in task 5.3).
3. **FTRC description** (p.199) says the result is "stored in FRn". It is stored in FPUL.

---

## 2. Feature presence on SH-2E

| Feature | Status | Evidence |
|---|---|---|
| FSQRT | ABSENT | Not in Table 6.9 (p.42), Table 6.11 (p.46-47), or section 7.3 (17 entries, p.168). Feature list (p.2) names FDIV, FMAC, FLDI0/1 only. |
| FSCHG / FRCHG / FPCHG | ABSENT | No such mnemonic anywhere. The only 1111 encodings are the 22 above. The FPSCR bit list (p.14) has no SZ, PR or FR bit. |
| FCNVSD / FCNVDS | ABSENT | Not in any instruction table. p.1 says double precision is only "PCAPI compatible emulation": "the SH-2E supports single-precision floating point calculations as well as entirely PCAPI compatible emulation of double-precision floating point calculations." |
| Double-precision DRn forms | ABSENT | Register file is "sixteen 32-bit single-precision floating-point registers" (p.12). FPU format is "Single-precision floating point format" (p.2). |
| FMOV @(disp12,Rm) (FMOV.S with displacement) | ABSENT | Only index forms are listed: `FMOV.S @(R0,Rm),FRn` and `FMOV.S FRm,@(R0,Rn)` (p.42, p.47, p.188). No displacement form exists. |
| FIPR | ABSENT | Not in any table or section. |
| FTRV | ABSENT | Not in any table or section. |
| FSRRA | ABSENT | Not in any table or section. |
| FSCA | ABSENT | Not in any table or section. |
| XF0-15 / XD banks | ABSENT | Only FR0-FR15 (p.12, Figure 2.4 p.7). No bank bit in FPSCR. |

Full-text grep for these names (word-bounded) returned no hits outside the FPU register/feature sections.

---

## 3. Floating-point registers and FPSCR

### Registers
- FR0-FR15: sixteen 32-bit single-precision registers (p.12). FR0 is the implicit operand of FMAC (p.12).
- FPUL: 32-bit communication register between CPU and FPU, accessed only by LDS/STS/LDS.L/STS.L (FLDS/FSTS/FLOAT/FTRC move between FPUL and FR) (p.12).
- FPSCR: 32-bit status/control register, part of process context (p.12).

### Reset values (Table 2.1, p.8)
- FR0-FR15: undefined
- FPUL: undefined
- **FPSCR: 0x00040001** (DN=1, RM=01)

### FPSCR bit layout (Figure 4.2, p.14)

The figure is mangled. The layout below is reconstructed from the field labels and cross-checked against the write mask `FPSCR_MASK = 0x00018C60` (p.202) and the reset value 0x00040001. The mask leaves writable exactly bits 16, 15, 11, 10, 6, 5 = CV, CZ, EV, EZ, FV, FZ, which matches the text on p.14.

| Bits | Name | Writable by LDS? | Meaning |
|---|---|---|---|
| 31-19 | reserved | no (0) | |
| 18 | DN | no, fixed 1 | Denormal bit. Always 1, so denormal operands/results are treated as zero (flush to zero). |
| 17 | CE | no (0) | Cause: FPU error |
| 16 | CV | yes | Cause: invalid operation |
| 15 | CZ | yes | Cause: division by zero |
| 14 | CO | no (0) | Cause: overflow (not supported) |
| 13 | CU | no (0) | Cause: underflow (not supported) |
| 12 | CI | no (0) | Cause: inexact (not supported) |
| 11 | EV | yes | Enable: invalid operation |
| 10 | EZ | yes | Enable: division by zero |
| 9 | EO | no (0) | Enable: overflow |
| 8 | EU | no (0) | Enable: underflow |
| 7 | EI | no (0) | Enable: inexact |
| 6 | FV | yes | Flag (sticky): invalid operation |
| 5 | FZ | yes | Flag (sticky): division by zero |
| 4 | FO | no (0) | Flag: overflow |
| 3 | FU | no (0) | Flag: underflow |
| 2 | FI | no (0) | Flag: inexact |
| 1-0 | RM | no, fixed 01 | Rounding mode. Always 01 = round toward zero (RZ). |

Other facts:
- Table 4.1 (p.13): only V (invalid) and Z (division by zero) are "Support in SH-2E = Yes". E, O, U, I are unsupported.
- Flags (FV, FZ) are sticky and cleared only by an explicit FPSCR store. Cause bits are per-instruction, cleared at start of each FP op (p.13; pseudo-code `clear_cause_VZ`, p.169).
- The FPU is enabled after reset. It can be disabled through MSTCR (p.12).

### Write semantics for LDS to FPSCR (p.47, p.202)
- Pseudo-code says `FPSCR = Rm & 0x00018C60`, which would clear all non-mask bits.
- The text ("Previously defined bits in FPSCR are not changed", p.47) and the examples (p.202: LDS 0x00040801 gives 0x00040801) show that non-mask bits (0, 1, 18, and others) are preserved. Treat the mask as "only these bits are written".

### Rounding modes
- Only RZ (round toward zero) is supported (p.2 "Rounding to zero"; p.14 "the value of these bits is always 01"). RM cannot be changed by LDS.

### Number format and special values
- Single precision only, IEEE754 subset (p.15). Bias 127, Emin=-126, Emax=127.
- Denormal operands and results are flushed to 0 for any value-producing op, not for copies (p.17, section 4.3.3). FMOV/FLDS/FSTS/LDS/STS copy the bits.
- **NaN convention is non-IEEE (p.16, Figure 4.4)**: "If bit 22 is set, this indicates a signaling NaN (sNaN). If bit 22 is reset, the value is a quiet NaN (qNaN)." This is the opposite of IEEE 754-2008.
- The qNaN generated by the FPU is `0x7FBFFFFF` (pseudo-code `qnan()`, p.169), which has bit 22 clear, so qNaN, consistent with the manual.
- With EV=0, an invalid operation returns this qNaN. With EV=1, an invalid operation raises the FPU exception and leaves the destination unchanged (p.16-17).
- Division by zero with EZ=0 returns ±INF with the XOR sign (p.17).
- Overflow and underflow with EO/EU=0 return the largest finite value and zero respectively. These are unsupported flags, so the behavior is only defined by the disabled-state text (p.17).
- Infinity: `+INF = 0x7F800000`, `-INF = 0xFF800000`, zeros `0x00000000` and `0x80000000` (Table 4.2, p.17).

### Per-instruction NaN and special-operand behavior (section 7.3, p.168-204)
- sNaN input to any value op raises Invalid. qNaN input propagates a qNaN with no exception.
- FCMP/EQ: qNaN gives T=0 with no exception (the "UO" result). sNaN raises Invalid and T is unchanged if EV=1, or T=0 if EV=0.
- FCMP/GT: qNaN is treated as Invalid (not UO), so it sets FV and raises the exception when EV=1. Note 1 on p.189: "UO if result is FCMP/EQ, invalid if result is FCMP/GT".
- FTRC: see note 4 below.
- FMAC intermediate: the product is rounded (FMUL), then added with FRn (FADD). It is **two roundings, not fused**. The FPSCR cause field of the multiply is OR-ed back in (p.185-186).
- FDIV: 0/0 and inf/inf raise Invalid. x/0 raises DZ (p.191-192).

---

## 4. Non-FPU differences from plain SH-2 and control register changes

- The manual does not contain an explicit list of CPU-instruction differences from SH-2. The CPU instruction set in section 6 is the same SH-2 set (MAC, DIV0/DIV1, TAS, etc.). The only additions are the FPU-related LDS/STS forms in section 3 above.
- **Ambiguity:** DMULS.L (`0011nnnnmmmm1101`) and DMULU.L (`0011nnnnmmmm0101`) are listed as normal instructions (p.89-91, Table 6.11). However, the Appendix B pipeline tables label "Double length multiply/accumulate instructions (SH-2 CPU only)" and "Double length multiplication instructions (SH-2 CPU only)" (Table B.1, around printed p.332-336). This suggests the double-length multiplies are SH-2-only, but the text does not say they are absent on SH-2E. The SH-2E core may not implement them; confirm against the hardware manual before relying on either way.
- SR bits are the SH-2 layout: M(9), Q(8), I3-I0(7-4), S(1), T(0). Reserved bits read 0 (p.4). No FPU-related SR bit exists.
- Control registers SR, GBR, VBR are unchanged. No new control register for FPU.
- Reset: SR I3-I0 = 1111, reserved bits 0 (Table 2.1, p.8).
- Undefined 16-bit opcodes are illegal instructions. If the FPU is stopped via the module stop bit, FP and FPU-related CPU instructions also become illegal (p.56, note 2).

---

## 5. Delay slots, illegal slots, exceptions

### Delay slots
- Illegal-slot list (p.54-55, section 7.1): BF, BT, BRA, BSR, JMP, JSR, RTS, RTE, TRAPA, BF/S, BT/S, BRAF, BSRF. An instruction in a slot that is one of these is an illegal slot instruction.
- **FPU instructions are not on the list**, so they are legal in delay slots. The example on p.178 uses `BT/S TRGET_T` with `FADD FR6,FR7` in the slot, and `BT/S ... FLDI1 FR7 ; Delay slot`.
- Illegal-slot exception behavior (p.56, examples): an ordinary illegal instruction or branch in a slot causes illegal-instruction exception processing.

### FPU exceptions
- All FPU exceptions map to **one exception event with vector offset 0x34** (p.18, section 4.4.3: "All FPU exceptions have a vector table address offset in address H'00000034 as the same general exception event"). Vector number is 0x34/4 = **13**. This is computed from the offset; the manual does not print a vector number.
- Exception sources: invalid operation (FV/EV) and division by zero (FZ/EZ). Software distinguishes them by reading FPSCR (p.17).
- Disabled-state results are not exceptions (p.17-18).
- FCMP/GT with qNaN raises Invalid when EV=1 (section 7.3.3, p.189).
- LDS/LDS.L/STS/STS.L and FP loads/stores can raise an Address error (p.202, p.204) like other memory access instructions.

---

## 6. Timing notes (brief)
- Basic FPU ops: 1 cycle, with 1-2 cycle execution pitch for FADD/FSUB/FMUL (p.2).
- FDIV: 13 cycles (p.179, Table 6.9).
- FMAC: 1 cycle, pitch 1 or 2 (p.2).
- Results used by the next instruction, and FPUL/FPSCR moves, cause one or two slot stalls (section 8.6, p.216; section 8.8.8, p.279-280). These do not change disassembly.

---

## Quick reference: decode constraints for SLEIGH
- Top nibble `1111` selects FPU for all of the 22 encodings above.
- Binary group: bits 3-0 select op, bits 11-8 = FRn, bits 7-4 = FRm.
- Unary group: low byte selects op, one register field.
- Any other `1111xxxx xxxxxxxx` code is undefined. Per p.56 it is an illegal instruction (no FSCHG/FRCHG/FSQRT encodings exist).
- LDS/STS FPUL/FPSCR forms are in the 0x4xxx/0x0xxx groups as listed in section 1.
