# SH7058 (SH-2E) hardware manual notes for Ghidra .pspec work

Page numbers below are the manual's printed page numbers ("page N of 1086"). In the text extraction the "=== PAGE n ===" marker is the printed page + 43 (printed p.145 = PAGE 188).

## 1. Operating modes (Section 4, Table 4.1, p.71)

Mode pins MD2-MD0 and FWE select the mode.

| Mode | FWE | MD2 MD1 MD0 | Mode name | On-chip ROM | Bus width |
|---|---|---|---|---|---|
| 0 | 0 | 1 0 0 | MCU expanded | Disabled | 8 bit |
| 1 | 0 | 1 0 1 | MCU expanded | Disabled | 16 bit |
| 2 | 0 | 1 1 0 | MCU expanded | Enabled | set by BCR1 |
| 3 | 0 | 1 1 1 | MCU single-chip | Enabled | n/a |
| 4 | 1 | 1 0 0 | (name not in extraction) | Enabled | set by BCR1 |
| 5 | 1 | 1 0 1 | Boot mode | Enabled | n/a |
| 6 | 1 | 1 1 0 | (name not in extraction) | Enabled | set by BCR1 |
| 7 | 1 | 1 1 1 | User program mode | Enabled | n/a |
| 8 | 1 | 0 0 0 | (name not in extraction) | Enabled | set by BCR1 |
| 9 | 1 | 0 0 1 | User boot mode | Enabled | n/a |
| - | 0/1 | 0 1 1 | Programmer mode | - | - |

Notes: Modes 0/1 are the "ROM disabled" expanded modes. Mode 2 is expanded with on-chip ROM enabled. Mode 3 is single-chip. Table 4.1 lists 3.3 V for modes 2, 4, 6, 8 and 5.0 V for modes 3, 5, 7, 9. The extraction does not name modes 4, 6 and 8, so their names are left blank. Check against the PDF.

## 2. Address map (Section 9.1.5, Figure 9.2 p.144, Table 9.3 p.145)

Address format: 32-bit addresses. A31-A24 are not output and select the space type. A23-A22 are decoded as CS0-CS3 when A31-A24 = 0x00. A21-A0 are output externally. No mirroring or shadowing of the regions is documented in the manual.

A31-A24 = 0x00: on-chip ROM or CS0-CS3 space.
A31-A24 = 0x01..0xFE: reserved (do not access).
A31-A24 = 0xFF: on-chip RAM or on-chip peripheral space.

On-chip ROM enabled (modes 2, 3, 4-9), Table 9.3 p.145:

| Range | Space | Size | Bus width |
|---|---|---|---|
| 0x00000000-0x000FFFFF | On-chip ROM (flash) | 1 MB | 32 |
| 0x00100000-0x001FFFFF | Reserved | | |
| 0x00200000-0x003FFFFF | CS0 | 2 MB | 8/16 |
| 0x00400000-0x007FFFFF | CS1 | 4 MB | 8/16 |
| 0x00800000-0x00BFFFFF | CS2 | 4 MB | 8/16 |
| 0x00C00000-0x00FFFFFF | CS3 | 4 MB | 8/16 |
| 0x01000000-0xFFFEFFFF | Reserved | | |
| 0xFFFF0000-0xFFFFBFFF | On-chip RAM | 48 KB | 32 |
| 0xFFFFC000-0xFFFFFFFF | On-chip peripheral modules | 16 KB | 8/16 |

On-chip ROM disabled (modes 0 and 1), Table 9.3 p.145:

| Range | Space | Size | Bus width |
|---|---|---|---|
| 0x00000000-0x003FFFFF | CS0 | 4 MB | 8 or 16 (mode 0: 8, mode 1: 16) |
| 0x00400000-0x007FFFFF | CS1 | 4 MB | 8/16 (BCR1) |
| 0x00800000-0x00BFFFFF | CS2 | 4 MB | 8/16 (BCR1) |
| 0x00C00000-0x00FFFFFF | CS3 | 4 MB | 8/16 (BCR1) |
| 0x01000000-0xFFFEFFFF | Reserved | | |
| 0xFFFF0000-0xFFFFBFFF | On-chip RAM | 48 KB | 32 |
| 0xFFFFC000-0xFFFFFFFF | On-chip peripheral modules | 16 KB | 8/16 |

Do not access reserved areas. Operation is not guaranteed.

Note: CS0 is 2 MB in the ROM-enabled map and 4 MB in the ROM-disabled map. The Ghidra spec should use the mode-specific map.

On-chip RAM emulation of flash (RAMER, p.152-153, Table 9.4): RAMER bits RAMS/RAM2-0 can overlay a 4 KB flash window onto RAM at H'FFFF0000-0FFF, or onto the 4 KB flash regions H'00000000-00007FFF in 4 KB steps.

## 3. Flash memory (Section 23, p.833; configuration 23.2.4 p.839)

- On-chip flash of 1 MB (user MAT) plus an 8 KB user boot MAT (p.833, 839).
- The user MAT is split into two 512 KB banks, at H'00000000-H'0007FFFF and H'00080000-H'000FFFFF (Figure 23.3, p.839). The user boot MAT occupies H'00000000-H'00001FFF of its own MAT. The two MATs overlap in address space and are selected with FMATS.
- Flash control registers (Table A.1, p.1050; Appendix A):

| Address | Register | Size |
|---|---|---|
| 0xFFFFE800 | FCCS (flash code control and status) | 8 |
| 0xFFFFE801 | FPCS (program code select) | 8 |
| 0xFFFFE802 | FECS (erase code select) | 8 |
| 0xFFFFE804 | FKEY (key code) | 8 |
| 0xFFFFE805 | FMATS (MAT select) | 8 |
| 0xFFFFE806 | FTDAR (transfer destination address) | 8 |

- Mode-to-operation summary: flash can be read in user mode, programmed/erased only in user program mode, boot mode and programmer mode (Table 23.1, p.837).

## 4. Exception processing vector table (Section 6, Table 6.3 p.87, Table 6.4 p.89; Section 7 Table 7.3 pp.107-115)

Vector table base: the reset vectors are at fixed address 0x00000000 (vector table address = vector number x 4). For exceptions other than resets the table address is VBR + offset (VBR, vector base register, set by software; reset value 0). Table 6.3 is at p.87.

Fixed vectors (Table 6.3 p.87-88):
- 0 (0x000) Power-on reset PC; 1 (0x004) Power-on reset SP
- 2 (0x008) Manual reset PC; 3 (0x00C) Manual reset SP
- 4 (0x010) General illegal instruction
- 6 (0x018) Slot illegal instruction
- 9 (0x024) CPU address error
- 10 (0x028) DMAC address error
- 11 (0x02C) NMI (priority 16)
- 12 (0x030) User break (UBC)
- 13 (0x034) FPU exception
- 14 (0x038) H-UDI
- 32-63 (0x080-0x0FF) Trap instruction (user vectors)
- 64-71 (0x100-0x11C) IRQ0-IRQ7

Peripheral interrupts (Table 7.3 pp.107-115), vectors 72-231 (0x120-0x39C). Full list is in sh7058_vectors.csv. Selected:
- DMAC DEI0-3: 72, 74, 76, 78 (0x120, 0x128, 0x130, 0x138)
- ATU-II ch0-ch11: vectors 80-187 (0x140-0x2EC), see CSV for each
- CMT0 CMTI0 188 (0x2F0); MTAD0 ADT0 189 (0x2F4); A/D0 ADI0 190 (0x2F8)
- CMT1 CMTI1 192 (0x300); MTAD1 ADT1 193 (0x304); A/D1 ADI1 194 (0x308); A/D2 ADI2 196 (0x310)
- SCI0-4: 200-219 (0x320-0x36C), four sources each (ERI, RXI, TXI, TEI)
- HCAN0: ERS0 220, OVR0 221, RM0 222, SLE0 223 (0x370-0x37C)
- WDT ITI 224 (0x380)
- HCAN1: ERS1 228, OVR1 229, RM1 230, SLE1 231 (0x390-0x39C)
- Vectors 232-255 are not assigned.

Unassigned vector numbers inside the peripheral range (73, 75, 77, 79, 81-83, 85, 87, 89, 91, 93-95, ...) are reserved. Vector 15 (0x03C-0x03F) is not listed in the table and is treated as reserved.

Interrupt priority registers (Section 7.3, Table 7.2 p.103; Table 7.4 p.117):
- IPRA ED00, IPRB ED02, IPRC ED04, IPRD ED06, IPRE ED08, IPRF ED0A, IPRG ED0C, IPRH ED0E, IPRI ED10, IPRJ ED12, IPRK ED14, IPRL ED16 (all 16-bit, levels 0-15, reset 0).
- ICR (interrupt control register, NMI) at 0xFFFFED18 (16-bit).
- ISR (IRQ status register) at 0xFFFFED1A (16-bit).

## 5. Register map summary

- BSC / bus controller, Section 9: BCR1 FFFFEC20, BCR2 FFFFEC22, WCR FFFFEC24, RAMER FFFFEC26 (p.143-153).
- UBC, Section 8 (p.125): UBARH/UBARL FFFFEC00/02, UBAMRH/L FFFFEC04/06, UBBR FFFFEC08, UBCR FFFFEC0A.
- WDT, Section 13 (p.440): TCSR EC10 (read), TCNT EC11 (read), RSTCSR write at EC12 (word), read at EC13. TCSR, TCNT and RSTCSR accesses use specific write keys (p.444).
- Power-down: SBYCR FFFFEC14 (8-bit), p.945.
- DMAC, Section 10 (p.166): SAR0-3 FFFFECC0/D0/E0/F0 (32), DAR0-3 +4, DMATCR0-3 +8, CHCR0-3 +C (32, at ECCC/ECDC/ECEC/ECFC), DMAOR FFFFECB0 (16).
- INTC, Section 7 (p.103-118): IPRA-IPRL ED00-ED16, ICR ED18, ISR ED1A.
- SCI, Section 15 (p.463): channels 0-4 at F000/F008/F010/F018/F020 plus per-channel SMR, BRR, SCR, TDR, SSR, RDR, SDCR (+0..+6). Full list in CSV.
- ATU-II, Section 11 (p.199): PSCR1-4 F404-F40A, TSTR F400-F402, ITVRR F424-F428, channel registers F42A-F6EA.
- CMT, Section 14 (p.451): CMSTR FFFFF710, CMCSR0 F712, CMCNT0 F714, CMCOR0 F716, CMCSR1 F718, CMCNT1 F71A, CMCOR1 F71C.
- APC, Section 12 (p.427): POPCR FFFFF700 (pulse output control). PULS/APC detail registers were not extracted (see Limitations).
- SYSCR1 FFFFF708, SYSCR2 FFFFF70A (8-bit).
- PFC / I/O ports, Section 21 (p.745) and Section 22 (p.803): PA-PL IO/control/data registers at F720-F778, ADTRGR0-2 at F76E, F72E, F72F.
- A/D converter, Section 17 (p.617): ADDR0-31 F800-F84E (16-bit, H/L), ADCR0 F819, ADCR1 F839, ADCR2 F859, ADTRGR0-2.
- MTAD (multi-trigger A/D), Section 18 (p.651): ADCNT0 F860 ... ADTIER1 F87E.
- H-UDI, Section 19 (p.697): SDIR FFFFF7C0, SDSR F7C2, SDDRH F7C4, SDDRL F7C6, SDBPR (not extracted).
- HCAN-II, Section 16 (p.519; register list p.606): channel 0 control block at 0xFFFFD000, channel 1 at 0xFFFFD800 (+0x800). Mailbox memory (MB0-MB31 per channel) sits above the control block (D100 onward for ch0, D900 onward for ch1). It is not in the CSV.
- Flash, Section 23 (p.833-885): E800-E806.
- Appendix A (Table A.1 address list, p.1005-1079) is the complete byte-level register list and was the cross-check for all of the above.

## 6. Interrupt vector table, summary

Vector table address = vector number x 4 (resets). Vector table address = VBR + vector number x 4 for all exceptions and interrupts (Table 6.4 p.89). Interrupts use vectors 64-231 in the table (offsets 0x100-0x39C).

## 7. Limitations of this extraction

- The register CSV has 484 rows. Sizes are inferred from the register initial-value width (H'XX=8, H'XXXX=16, H'XXXXXXXX=32, Undefined and "32 bits" = 32). Where a register's access sizes differ, check the register-description tables.
- ATU-II 32-bit counters and compare/capture registers are split H/L in the text. They are listed as separate 16-bit rows (TCNT0H/TCNT0L, ICR0AH/AL, etc.). TCNT10A is listed as 32-bit at F6C0. ICR10AH/AL and OCR10AH/AL at F6D0-F6D6 are inferred from the appendix ordering, not confirmed.
- The HCAN control register addresses come from the Appendix A table. Each has a _0 or _1 suffix for channel 0 or 1. The mailbox memory and per-mailbox bit fields are not included.
- The APC PULS registers (PULS0RO..PULS7SO) and the SD/SDBPR register, the AUD module (Section 20), and the MTAD channel 2 registers were not fully extracted.
- Bit-level definitions were not captured.
- Vector names for ATU-II groups follow the labels in Table 7.3 (for example ATU01, ATU02). These labels are not all clear in the text extraction; check against the hardware manual PDF.
