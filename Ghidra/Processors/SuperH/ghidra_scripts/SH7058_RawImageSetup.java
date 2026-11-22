/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Sets up a raw SH7058 (SH-2E) on-chip flash image, imported with the
// Raw Binary loader at base address 0 and language SuperH:BE:32:SH7058 (or SH-2E).
//
// What it does (every step logs what it found; heuristics are marked "HEURISTIC"):
//  1. Flash block: renames the loader's block at address 0 to FLASH and makes it r-x. A
//     read-only flash lets the decompiler fold literal-pool constants, so globals and calls show
//     as DAT_ffff1234 / FUN_00012345() instead of *PTR_DAT_xxx / (*(code *)PTR_FUN_xxx)(), and
//     GBR set from a pool constant resolves to RAM addresses.
//  1b. RAM/IO: creates the RAM (FFFF0000-FFFFBFFF) and IO (FFFFC000-FFFFFFFF) blocks if they are
//     missing (e.g. generic SH-2E import) and makes every block in the IO range volatile.
//  2. (Not here.) An image that keeps calibration data in flash can split that range off as a
//     writable block in a pre-script run before this one, so reads of calibration scalars show
//     as DAT_ references instead of being folded into constants. This script keeps any block
//     it finds above the block at address 0 as it is, and treats only the block at 0 as FLASH.
//  3. Vectors 0-15 at address 0: pointer data, v_<name> labels, functions at code targets.
//  4. VBR: finds every "ldc Rm,vbr", resolves Rm (mov.l @(disp,pc) / mov.w @(disp,pc) /
//     mov #imm), and lays down the full 232-entry table (pointers, v_<name> labels, functions
//     at the handlers) at each non-zero VBR that looks like a vector table. After analysis it
//     also makes a function (vbr_setup_<addr>) of the code around each ldc vbr that is still
//     outside any function (HEURISTIC).
//  5. Optional prologue scan: creates functions at "sts.l pr,@-r15" (4f22) prologues, plus the
//     register pushes before them, in undefined flash ("noprologues" disables it).
//  5b. More function entries (HEURISTIC, "noentries" disables it): functions at the targets of
//     pointer data in flash (task, service and handler tables), at jump/call targets that land
//     outside every function (literal-pool tail jumps), and at undefined code after a literal
//     pool that starts with a callee-saved register push and pseudo-disassembles as a
//     subroutine (OS services, init routines, getters).
//  6. Removes the bogus references into FFFFF880-FFFFFFFF (past the last SH7058 register) that
//     scalar analysis makes from small negative constants such as "mov #-4,r0".
//  7. GBR: for every "ldc Rm,gbr" with a resolvable constant, sets the GBR register value from
//     that point to the next ldc/ldc.l gbr or the end of the function, adds the missing
//     @(disp,gbr) references, and sets GBR at the entry of functions that use GBR without
//     loading it when all their callers agree ("nogbr" disables it). Code may load GBR per
//     function, so this is a heuristic, not a global setting.
//  8. Address-table repair (HEURISTIC, "norepair" disables it): "Create Address Tables" makes
//     pointers of code words such as 0009xxxx (nop) and 000bxxxx (rts), and flow into them
//     fails with "conflicting data", dropping instructions. Unreferenced pointer data at such a
//     conflict is cleared and the flow disassembled again.
//  9. Calling conventions (HEURISTIC, "nomodels" disables it): the default model in
//     superh2e.cspec kills r0-r7 at a call. A register-write fixed point over the call graph
//     finds the functions that provably never change r4-r7 and gives them __preserve_r4_r7, or
//     __shc_runtime when they also take their inputs in r0-r3/fr0-fr3 (SHC runtime helpers).
//  9b. Prototypes (HEURISTIC, "noprotos" disables it): Ghidra does not run Decompiler Parameter
//     ID on a raw binary, so each call site guesses its own arguments and drops registers whose
//     value is also used elsewhere (e.g. "mov #2,r5; jsr; mov r5,r4" prints one argument).
//     Bottom-up over the call graph, each function's parameter list is committed (return value
//     left open) when the decompiler, the register dataflow of step 9 and the call sites agree;
//     committed functions are tagged SH7058SETUP_PARAMS.
// 10. Unused IO reads ("noioreads" disables it): the decompiler drops a load whose value is
//     unused even from volatile memory, which hides the read half of the SH7058's
//     read-then-write flag clears. Every function that reads IO is decompiled and each IO read
//     with no p-code left gets a pre-comment the C shows ("dummy read of TCSR at 00001234");
//     code outside functions falls back to a listing check (HEURISTIC). Runs last.
//
// Usage:
//   GUI: import as Raw Binary (base 0, SuperH:BE:32:SH7058), answer "No" to "Analyze now?",
//   then run this script: it fixes the blocks and vectors first, runs auto-analysis itself, then
//   does the rest. Running it on an already-analyzed program also works, but analysis will
//   have run with a writable flash block and finds fewer functions.
//   Headless (recommended, same script twice):
//     analyzeHeadless <proj> <name> -import rom.bin -loader BinaryLoader -loader-baseAddr 0
//       -processor SuperH:BE:32:SH7058 -cspec default
//       -preScript SH7058_RawImageSetup.java pre -postScript SH7058_RawImageSetup.java
//   Arguments (any order): pre (only the steps that do not need analysis),
//   noprologues, noentries, nogbr, norepair, nomodels, noprotos, noioreads; "only:<step>" runs
//   one step on its own (models = 9 and 9b, ioreads, repair, blocks, entries), e.g. on an ELF
//   imported as SH-2E, or after creating functions by hand: run only:models, then only:ioreads,
//   so new functions get prototypes and dummy-read comments; "regdump:<file>" writes the
//   per-function register analysis of step 9.
//
// The vector-name table below is generated: sh-2e/tools/gen_pspec.py --vector-names
// (gen_pspec.py --check verifies it against sh-2e/notes/sh7058_vectors.csv).
//@category Processors.SuperH

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.GhidraProgramUtilities;

public class SH7058_RawImageSetup extends GhidraScript {

	private static final String TAG = "[SH7058Setup] ";
	private static final String BOOKMARK_CATEGORY = "SH7058Setup";

	private static final int NUM_VECTORS = 232;
	private static final int FIXED_VECTORS = 16; // vectors 0-15 are read from address 0 at reset (VBR = 0)
	private static final Set<Integer> SP_VECTORS = Set.of(1, 3);

	// Vector names, index = vector number (labels are "v_" + name). Generated, do not edit.
	private static final String[] VECTOR_NAMES = {
		"PowerOnReset_PC", "PowerOnReset_SP", "ManualReset_PC", "ManualReset_SP",
		"GeneralIllegalInstruction", "Reserved_5", "SlotIllegalInstruction", "Reserved_7",
		"Reserved_8", "CPUAddressError", "DMACAddressError", "NMI", "UserBreak", "FPUException",
		"H_UDI", "Reserved_15", "Reserved_16", "Reserved_17", "Reserved_18", "Reserved_19",
		"Reserved_20", "Reserved_21", "Reserved_22", "Reserved_23", "Reserved_24", "Reserved_25",
		"Reserved_26", "Reserved_27", "Reserved_28", "Reserved_29", "Reserved_30", "Reserved_31",
		"Trap_32", "Trap_33", "Trap_34", "Trap_35", "Trap_36", "Trap_37", "Trap_38", "Trap_39",
		"Trap_40", "Trap_41", "Trap_42", "Trap_43", "Trap_44", "Trap_45", "Trap_46", "Trap_47",
		"Trap_48", "Trap_49", "Trap_50", "Trap_51", "Trap_52", "Trap_53", "Trap_54", "Trap_55",
		"Trap_56", "Trap_57", "Trap_58", "Trap_59", "Trap_60", "Trap_61", "Trap_62", "Trap_63",
		"IRQ0", "IRQ1", "IRQ2", "IRQ3", "IRQ4", "IRQ5", "IRQ6", "IRQ7", "DMAC0_DEI0", "Reserved_73",
		"DMAC1_DEI1", "Reserved_75", "DMAC2_DEI2", "Reserved_77", "DMAC3_DEI3", "Reserved_79",
		"ATU_ITV1_ITV2A_ITV2B", "Reserved_81", "Reserved_82", "Reserved_83", "ATU_ICI0A",
		"Reserved_85", "ATU_ICI0B", "Reserved_87", "ATU_ICI0C", "Reserved_89", "ATU_ICI0D",
		"Reserved_91", "ATU_OVI0", "Reserved_93", "Reserved_94", "Reserved_95", "ATU_IMI1A_CMI1",
		"ATU_IMI1B", "ATU_IMI1C", "ATU_IMI1D", "ATU_IMI1E", "ATU_IMI1F", "ATU_IMI1G", "ATU_IMI1H",
		"ATU_OVI1A_OVI1B", "Reserved_105", "Reserved_106", "Reserved_107", "ATU_IMI2A_CMI2A",
		"ATU_IMI2B", "ATU_IMI2C", "ATU_IMI2D", "ATU_IMI2E", "ATU_IMI2F", "ATU_IMI2G", "ATU_IMI2H",
		"ATU_OVI2A_OVI2B", "Reserved_117", "Reserved_118", "Reserved_119", "ATU_IMI3A", "ATU_IMI3B",
		"ATU_IMI3C", "ATU_IMI3D", "ATU_OVI3", "Reserved_125", "Reserved_126", "Reserved_127",
		"ATU_IMI4A", "ATU_IMI4B", "ATU_IMI4C", "ATU_IMI4D", "ATU_OVI4", "Reserved_133",
		"Reserved_134", "Reserved_135", "ATU_IMI5A", "ATU_IMI5B", "ATU_IMI5C", "ATU_IMI5D",
		"ATU_OVI5", "Reserved_141", "Reserved_142", "Reserved_143", "ATU_CMI6A", "ATU_CMI6B",
		"ATU_CMI6C", "ATU_CMI6D", "ATU_CMI7A", "ATU_CMI7B", "ATU_CMI7C", "ATU_CMI7D", "ATU_OSI8A",
		"ATU_OSI8B", "ATU_OSI8C", "ATU_OSI8D", "ATU_OSI8E", "ATU_OSI8F", "ATU_OSI8G", "ATU_OSI8H",
		"ATU_OSI8I", "ATU_OSI8J", "ATU_OSI8K", "ATU_OSI8L", "ATU_OSI8M", "ATU_OSI8N", "ATU_OSI8O",
		"ATU_OSI8P", "ATU_CMI9A", "ATU_CMI9B", "ATU_CMI9C", "ATU_CMI9D", "ATU_CMI9E", "Reserved_173",
		"ATU_CMI9F", "Reserved_175", "ATU_CMI10A", "Reserved_177", "ATU_CMI10B", "Reserved_179",
		"ATU_ICI10A_CMI10G", "Reserved_181", "Reserved_182", "Reserved_183", "ATU_IMI11A",
		"Reserved_185", "ATU_IMI11B", "ATU_OVI11", "CMT0_CMTI0", "MTAD0_ADT0", "AD0_ADI0",
		"Reserved_191", "CMT1_CMTI1", "MTAD1_ADT1", "AD1_ADI1", "Reserved_195", "AD2_ADI2",
		"Reserved_197", "Reserved_198", "Reserved_199", "SCI0_ERI0", "SCI0_RXI0", "SCI0_TXI0",
		"SCI0_TEI0", "SCI1_ERI1", "SCI1_RXI1", "SCI1_TXI1", "SCI1_TEI1", "SCI2_ERI2", "SCI2_RXI2",
		"SCI2_TXI2", "SCI2_TEI2", "SCI3_ERI3", "SCI3_RXI3", "SCI3_TXI3", "SCI3_TEI3", "SCI4_ERI4",
		"SCI4_RXI4", "SCI4_TXI4", "SCI4_TEI4", "HCAN0_ERS0", "HCAN0_OVR0", "HCAN0_RM0", "HCAN0_SLE0",
		"WDT_ITI", "Reserved_225", "Reserved_226", "Reserved_227", "HCAN1_ERS1", "HCAN1_OVR1",
		"HCAN1_RM1", "HCAN1_SLE1"
	};

	// SH7058 on-chip I/O; no register exists above the last pspec label (FFFFF87E).
	private static final long RAM_START = 0xFFFF0000L;
	private static final long IO_START = 0xFFFFC000L;
	private static final long IO_FALLBACK_LAST_REG = 0xFFFFF87FL;

	private boolean optPre, optNoPrologues, optNoGbr, optNoModels, optNoRepair;
	private boolean optNoIoReads, optNoProtos, optNoEntries;
	private String optOnly; // "only:<step>": run one step (models, ioreads, repair, blocks, entries)
	private PrintWriter debugOut; // "regdump:<file>": per-function register analysis
	private final List<Long> vbrSites = new ArrayList<>();
	private final List<Address> entriesCreated = new ArrayList<>(); // step 5b

	private Memory mem;
	private Listing listing;
	private FunctionManager fm;
	private SymbolTable st;
	private ReferenceManager rm;
	private PseudoDisassembler pdis;
	private AddressSpace space;
	private MemoryBlock flash;

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr(TAG + "no program");
			return;
		}
		String proc = currentProgram.getLanguage().getProcessor().toString();
		if (!proc.equals("SuperH") || currentProgram.getLanguage().isBigEndian() == false) {
			printerr(TAG + "this script is for big-endian SuperH (SH-2E / SH7058) programs, not " +
				currentProgram.getLanguageID());
			return;
		}
		if (!currentProgram.getLanguageID().getIdAsString().contains("SH7058")) {
			println(TAG + "WARNING: language is " + currentProgram.getLanguageID() +
				"; SuperH:BE:32:SH7058 gives the RAM/IO blocks and register labels this script expects");
		}
		for (String a : getScriptArgs()) {
			switch (a.toLowerCase()) {
				case "pre" -> optPre = true;
				case "post", "all" -> {
				}
				case "noprologues" -> optNoPrologues = true;
				case "nogbr" -> optNoGbr = true;
				case "nomodels" -> optNoModels = true;
				case "norepair" -> optNoRepair = true;
				case "modelsonly" -> optOnly = "models";
				case "noioreads" -> optNoIoReads = true;
				case "noprotos" -> optNoProtos = true;
				case "noentries" -> optNoEntries = true;
				default -> {
					if (a.toLowerCase().startsWith("only:")) {
						optOnly = a.substring(5).toLowerCase();
					}
					else if (a.toLowerCase().startsWith("regdump:")) {
						debugOut = new PrintWriter(a.substring(8));
					}
					else {
						println(TAG + "ignoring unknown argument '" + a + "'");
					}
				}
			}
		}
		mem = currentProgram.getMemory();
		listing = currentProgram.getListing();
		fm = currentProgram.getFunctionManager();
		st = currentProgram.getSymbolTable();
		rm = currentProgram.getReferenceManager();
		pdis = new PseudoDisassembler(currentProgram);
		space = currentProgram.getAddressFactory().getDefaultAddressSpace();
		if (optOnly != null) {
			// re-run one post-analysis step, e.g. after editing code by hand
			flash = mem.getBlock(addr(0));
			switch (optOnly) {
				case "models" -> assignCallingConventions();
				case "ioreads" -> annotateUnusedIoReads();
				case "repair" -> repairAddressTableConflicts();
				case "blocks" -> setupRamIo();
				case "entries" -> {
					for (int pass = 0; pass < 3 && findMoreEntries() > 0; pass++) {
						analyzeChanges(currentProgram);
					}
					for (int pass = 0; pass < 3 && repairAddressTableConflicts() > 0; pass++) {
						analyzeChanges(currentProgram);
					}
					revalidateEntries();
				}
				default -> printerr(TAG + "unknown step '" + optOnly +
					"' (models, ioreads, repair, blocks, entries)");
			}
			return;
		}

		// ---- steps that do not need analysis (pre-script) ----
		setupFlashBlock();
		if (flash == null) {
			return;
		}
		setupRamIo();
		int created = setupFixedVectors();
		created += setupVbrTables();
		if (optPre) {
			println(TAG + "pre phase done (" + created +
				" functions created); run auto-analysis, then this script again without 'pre'");
			return;
		}

		// ---- analysis ----
		if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) {
			println(TAG + "program not analyzed yet: running auto-analysis");
			analyzeAll(currentProgram);
		}
		else if (created > 0) {
			analyzeChanges(currentProgram);
		}

		// ---- steps that need analysis results ----
		if (!optNoRepair && repairAddressTableConflicts() > 0) {
			analyzeChanges(currentProgram);
		}
		if (vbrSiteFunctions() > 0) {
			analyzeChanges(currentProgram);
		}
		if (!optNoPrologues) {
			if (scanPrologues() > 0) {
				analyzeChanges(currentProgram);
			}
		}
		for (int pass = 0; pass < 3 && !optNoEntries; pass++) {
			if (findMoreEntries() == 0) {
				break;
			}
			analyzeChanges(currentProgram);
		}
		// new code found since the first repair can hit the same address-table problem
		for (int pass = 0; pass < 3 && !optNoRepair; pass++) {
			if (repairAddressTableConflicts() == 0) {
				break;
			}
			analyzeChanges(currentProgram);
		}
		if (!optNoEntries && revalidateEntries() > 0) {
			analyzeChanges(currentProgram);
		}
		removeBogusIoRefs();
		if (!optNoGbr) {
			setupGbr();
		}
		if (!optNoModels) {
			assignCallingConventions();
		}
		// last: which reads the decompiler drops depends on the prototypes set above
		if (!optNoIoReads) {
			annotateUnusedIoReads();
		}
		summary();
	}

	// ------------------------------------------------------------------ helpers

	private Address addr(long off) {
		return space.getAddress(off & 0xffffffffL);
	}

	private boolean inCode(long off) {
		if ((off & 1) != 0 || off < 0 || off > 0xffffffffL) {
			return false;
		}
		MemoryBlock b = mem.getBlock(addr(off));
		return b != null && b.isInitialized() && b.isExecute();
	}

	private Long readInt(long off) {
		try {
			return mem.getInt(addr(off)) & 0xffffffffL;
		}
		catch (Exception e) {
			return null;
		}
	}

	private int readWord(long off) {
		try {
			return mem.getShort(addr(off)) & 0xffff;
		}
		catch (Exception e) {
			return -1;
		}
	}

	private void label(Address a, String name) throws Exception {
		for (Symbol s : st.getSymbols(a)) {
			if (s.getName().equals(name)) {
				return;
			}
		}
		st.createLabel(a, name, SourceType.USER_DEFINED);
	}

	private boolean isFlowBreak(int w) {
		int hi = w >> 12;
		if (hi == 0xA || hi == 0xB) {
			return true; // bra / bsr
		}
		int op8 = w >> 8;
		if (op8 == 0x89 || op8 == 0x8B || op8 == 0x8D || op8 == 0x8F) {
			return true; // bt / bf / bt/s / bf/s
		}
		if (w == 0x000B || w == 0x002B || w == 0x001B) {
			return true; // rts / rte / sleep
		}
		int lo8 = w & 0xff, hi4 = w & 0xf000;
		if (hi4 == 0x4000 && (lo8 == 0x2B || lo8 == 0x0B)) {
			return true; // jmp / jsr
		}
		if (hi4 == 0x0000 && (lo8 == 0x23 || lo8 == 0x03)) {
			return true; // braf / bsrf
		}
		return (w & 0xff00) == 0xC300; // trapa
	}

	/**
	 * Resolve the constant in register r{reg} at {site} by walking back over straight-line code
	 * (at most {maxBack} instructions) to the instruction that wrote it. Handles mov.l @(disp,pc),
	 * mov.w @(disp,pc) and mov #imm. Returns null if the value is not a simple constant.
	 */
	private Long resolveReg(long site, int reg, int maxBack) {
		for (int k = 1; k <= maxBack; k++) {
			long a = site - 2L * k;
			int w = readWord(a);
			if (w < 0) {
				return null;
			}
			// The instruction just before the site may be a delayed branch (site = delay slot).
			if (k > 1 && isFlowBreak(w)) {
				return null;
			}
			int n = (w >> 8) & 0xf;
			int hi = w >> 12;
			if (n == reg && hi == 0xD) {
				return readInt(((a + 4) & ~3L) + 4L * (w & 0xff));
			}
			if (n == reg && hi == 0xE) {
				return (long) (byte) (w & 0xff) & 0xffffffffL;
			}
			if (n == reg && hi == 0x9) {
				int v = readWord(a + 4 + 2L * (w & 0xff));
				return v < 0 ? null : (long) (short) v & 0xffffffffL;
			}
			if (writesReg(a, reg)) {
				return null;
			}
		}
		return null;
	}

	private boolean writesReg(long a, int reg) {
		try {
			PseudoInstruction pi = pdis.disassemble(addr(a));
			if (pi == null) {
				return true;
			}
			for (Object o : pi.getResultObjects()) {
				if (o instanceof Register r && r.getName().equalsIgnoreCase("r" + reg)) {
					return true;
				}
			}
			return false;
		}
		catch (Exception e) {
			return true; // undecodable: give up
		}
	}

	private Function makeFunction(Address a) {
		Function f = fm.getFunctionAt(a);
		if (f != null) {
			return f;
		}
		if (listing.getInstructionAt(a) == null) {
			if (listing.getDefinedDataContaining(a) != null) {
				return null; // do not destroy data analysis decided on
			}
			disassemble(a);
		}
		if (listing.getInstructionAt(a) == null) {
			return null;
		}
		return createFunction(a, null);
	}

	private void putPointer(Address a) throws Exception {
		Data d = listing.getDataAt(a);
		if (d != null && d.isPointer() && d.getLength() == 4) {
			return;
		}
		if (listing.getInstructionContaining(a) != null ||
			listing.getInstructionContaining(a.add(3)) != null) {
			println(TAG + "  clearing instructions over vector slot " + a);
		}
		clearListing(a, a.add(3));
		createData(a, new PointerDataType());
	}

	// ------------------------------------------------------------------ 1. flash block

	private void setupFlashBlock() throws Exception {
		flash = mem.getBlock(addr(0));
		if (flash == null || !flash.isInitialized()) {
			printerr(TAG + "no initialized block at address 0: import the ROM with the Raw " +
				"Binary loader at base address 0");
			flash = null;
			return;
		}
		String old = flash.getName() + " " + (flash.isRead() ? "r" : "-") +
			(flash.isWrite() ? "w" : "-") + (flash.isExecute() ? "x" : "-");
		if (!flash.getName().equals("FLASH")) {
			flash.setName("FLASH");
		}
		flash.setRead(true);
		flash.setWrite(false);
		flash.setExecute(true);
		println(TAG + "flash block " + flash.getStart() + "-" + flash.getEnd() + ": was '" + old +
			"', now 'FLASH r-x'");
		long image = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (b.isInitialized() && b.getStart().getOffset() < RAM_START) {
				image += b.getSize();
			}
		}
		if (image != 0x100000L) {
			println(TAG + "WARNING: the image is 0x" + Long.toHexString(image) +
				" bytes; the SH7058 has 1 MB (0x100000) of flash");
		}
	}

	// ------------------------------------------------------------------ 1b. RAM / IO blocks

	/**
	 * SH7058 address map (hardware manual Table 9.3): on-chip RAM FFFF0000-FFFFBFFF, on-chip
	 * peripherals FFFFC000-FFFFFFFF. The SH7058 language's pspec creates both blocks, with IO
	 * volatile; a program imported with the generic SH-2E language (or edited by hand) may lack
	 * them. Create missing blocks and make every block in the peripheral range volatile, so the
	 * decompiler keeps each register access (MappedEntry.getMutabilityOfAddress reads the
	 * block's volatile flag).
	 */
	private void setupRamIo() throws Exception {
		AddressSet ioRange = new AddressSet(addr(IO_START), addr(0xFFFFFFFFL));
		AddressSet ramRange = new AddressSet(addr(RAM_START), addr(IO_START - 1));
		if (!mem.intersects(ramRange)) {
			MemoryBlock b = mem.createUninitializedBlock("RAM", addr(RAM_START),
				IO_START - RAM_START, false);
			b.setPermissions(true, true, true);
			println(TAG + "created missing RAM block " + b.getStart() + "-" + b.getEnd());
		}
		if (!mem.intersects(ioRange)) {
			MemoryBlock b = mem.createUninitializedBlock("IO", addr(IO_START),
				0x100000000L - IO_START, false);
			b.setPermissions(true, true, false);
			b.setVolatile(true);
			println(TAG + "created missing IO block " + b.getStart() + "-" + b.getEnd() +
				" (volatile)");
			return;
		}
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.getEnd().equals(addr(IO_START - 1)) && b.contains(addr(IO_START)) &&
				!b.getStart().equals(addr(IO_START))) {
				mem.split(b, addr(IO_START)); // a block that spans RAM and IO
				println(TAG + "split block " + b.getName() + " at " + addr(IO_START));
			}
		}
		for (MemoryBlock b : mem.getBlocks()) {
			if (b.getStart().getOffset() >= IO_START && !b.isVolatile()) {
				b.setVolatile(true);
				println(TAG + "block " + b.getName() + " " + b.getStart() + "-" + b.getEnd() +
					" is in the peripheral range: made volatile");
			}
		}
	}

	// ------------------------------------------------------------------ 10. unused IO reads

	private static final String IOREAD_PREFIX = "SH7058Setup: dummy read";

	/**
	 * Ghidra's decompiler drops a read whose value is never used, even from volatile memory
	 * (dead-code elimination removes it before Funcdata::replaceVolatile models the access). On the
	 * SH7058 such "dummy" reads matter: status flags are cleared by reading the flag as 1 and then
	 * writing 0 (e.g. ADCSR, TSR), and the C would show only the write. Each function that reads
	 * an IO register is decompiled; every IO read that has no p-code left in the result gets a
	 * pre-comment, which the C shows: "SH7058Setup: dummy read of TCSR at 00001234 (...)".
	 * <p>
	 * The decompiler prints a pre-comment before the first statement at or after its address in
	 * the same basic block. A read in a delay slot executes before its branch, and its p-code
	 * carries the branch's address, so the comment goes on the branch. When a statement that
	 * executes after the read still prints before the comment (a store in the delay slot of the
	 * rts that follows the read: its p-code has the rts address but sorts after the return), the
	 * comment says so. Reads outside any function, or in functions that do not decompile, fall
	 * back to a listing check (HEURISTIC: the destination register is overwritten before any use
	 * on the straight-line path). Earlier comments of this step are removed first, so running
	 * "only:ioreads" again (e.g. after creating functions) redoes them.
	 */
	private void annotateUnusedIoReads() throws Exception {
		AddressSet ioRange = new AddressSet(addr(IO_START), addr(0xFFFFFFFFL));
		if (!mem.intersects(ioRange)) {
			return;
		}
		// remove this step's earlier comments
		int removed = 0;
		List<Address> old = new ArrayList<>();
		for (AddressIterator ai = listing.getCommentAddressIterator(CommentType.PRE, mem, true); ai
				.hasNext();) {
			old.add(ai.next());
		}
		for (Address a : old) {
			String c = listing.getComment(CommentType.PRE, a);
			if (c == null || !c.contains(IOREAD_PREFIX)) {
				continue;
			}
			List<String> keep = new ArrayList<>();
			for (String ln : c.split("\n")) {
				if (ln.startsWith(IOREAD_PREFIX)) {
					removed++;
				}
				else {
					keep.add(ln);
				}
			}
			listing.setComment(a, CommentType.PRE, keep.isEmpty() ? null : String.join("\n", keep));
		}
		// IO reads, by function
		Map<Function, List<Instruction>> byFunc = new LinkedHashMap<>();
		List<Instruction> loose = new ArrayList<>();
		int reads = 0;
		for (Instruction in : listing.getInstructions(true)) {
			if (ioReadTarget(in, ioRange) == null) {
				continue;
			}
			reads++;
			Function f = fm.getFunctionContaining(in.getAddress());
			if (f == null) {
				loose.add(in);
			}
			else {
				byFunc.computeIfAbsent(f, k -> new ArrayList<>()).add(in);
			}
		}
		Map<Address, List<String>> comments = new TreeMap<>();
		int dropped = 0, late = 0, moved = 0, failed = 0, fallback = 0;
		DecompInterface d = new DecompInterface();
		d.setOptions(new DecompileOptions());
		d.toggleCCode(false);
		d.toggleSyntaxTree(true);
		boolean ok = d.openProgram(currentProgram);
		try {
			for (Map.Entry<Function, List<Instruction>> e : byFunc.entrySet()) {
				monitor.checkCancelled();
				DecompileResults res = ok ? d.decompileFunction(e.getKey(), 60, monitor) : null;
				HighFunction hf = res == null ? null : res.getHighFunction();
				if (hf == null) {
					failed++;
					loose.addAll(e.getValue());
					continue;
				}
				List<PcodeOpAST> ops = new ArrayList<>();
				hf.getPcodeOps().forEachRemaining(ops::add);
				ops.sort(Comparator.comparing(PcodeOp::getSeqnum));
				for (Instruction in : e.getValue()) {
					Address to = ioReadTarget(in, ioRange);
					Address eff = in.getAddress();
					if (in.isInDelaySlot()) {
						Instruction br = listing.getInstructionBefore(eff);
						eff = br == null ? eff : br.getAddress();
					}
					if (readKept(ops, in.getAddress(), eff, to)) {
						continue;
					}
					dropped++;
					// where the decompiler will print a comment placed at eff (CommentSorter)
					Address at = null;
					int[] pos = null;
					for (Address c = eff; c != null && at == null;) {
						pos = commentPosition(hf, ops, c);
						if (pos != null) {
							at = c;
							break;
						}
						Instruction nx = listing.getInstructionAfter(c);
						c = nx == null || !e.getKey().getBody().contains(nx.getAddress()) ||
							nx.getAddress().subtract(eff) > 64 ? null : nx.getAddress();
					}
					if (at == null) {
						at = eff;
					}
					else if (!at.equals(eff)) {
						moved++;
					}
					boolean isLate = pos != null && executesBefore(hf, ops, pos, eff);
					if (isLate) {
						late++;
					}
					comments.computeIfAbsent(at, k -> new ArrayList<>())
							.add(ioReadComment(in, to) + (isLate
									? "; it comes before the preceding statement (delay slot)"
									: ""));
				}
			}
		}
		finally {
			d.dispose();
		}
		// fallback for code the decompiler did not cover
		for (Instruction in : loose) {
			if (in.isInDelaySlot() || !unusedOnStraightLine(in)) {
				continue;
			}
			fallback++;
			comments.computeIfAbsent(in.getAddress(), k -> new ArrayList<>())
					.add(ioReadComment(in, ioReadTarget(in, ioRange)));
		}
		for (Map.Entry<Address, List<String>> e : comments.entrySet()) {
			String c = listing.getComment(CommentType.PRE, e.getKey());
			String add = String.join("\n", e.getValue());
			listing.setComment(e.getKey(), CommentType.PRE, c == null ? add : c + "\n" + add);
		}
		println(TAG + "unused IO reads: " + reads + " instructions read an IO register; " +
			dropped + " of them (in " + byFunc.size() + " functions) are unused (dropped by the " +
			"decompiler, or kept as a dead assignment), each now has a pre-comment shown in the C" +
			(moved > 0 ? " (" + moved + " placed on the next statement)" : "") +
			(late > 0 ? "; " + late + " print after a delay-slot statement and say so" : "") +
			"; HEURISTIC listing check for " + loose.size() + " reads outside functions" +
			(failed > 0 ? " or in " + failed + " functions that did not decompile" : "") + ": " +
			fallback + " commented" + (removed > 0 ? "; " + removed + " old comments replaced" : ""));
	}

	private Address ioReadTarget(Instruction in, AddressSetView ioRange) {
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isRead() && ioRange.contains(r.getToAddress())) {
				return r.getToAddress();
			}
		}
		return null;
	}

	private String ioReadComment(Instruction in, Address to) {
		Symbol s = st.getPrimarySymbol(to);
		String name = s == null ? to.toString() : s.getName();
		return IOREAD_PREFIX + " of " + name + " at " + in.getAddress() + " (value unused; the " +
			"decompiler omits unused reads, even of volatile registers)";
	}

	/**
	 * Is there p-code for the read left (a volatile read, a plain read or a LOAD) whose value
	 * is used? A volatile read whose result goes nowhere prints as "uVar1 = TCSR;" with uVar1
	 * unused, which is still an unused read.
	 */
	private static boolean readKept(List<PcodeOpAST> ops, Address a, Address eff, Address to) {
		for (PcodeOpAST op : ops) {
			Address t = op.getSeqnum().getTarget();
			if (!t.equals(a) && !t.equals(eff)) {
				continue;
			}
			int oc = op.getOpcode();
			if (oc == PcodeOp.LOAD) {
				return true;
			}
			if (oc == PcodeOp.INDIRECT || (oc == PcodeOp.CALLOTHER && op.getOutput() == null)) {
				continue; // indirect effect, or a volatile write
			}
			for (int i = oc == PcodeOp.CALLOTHER ? 1 : 0; i < op.getNumInputs(); i++) {
				Varnode v = op.getInput(i);
				if (v.getAddress().getAddressSpace().equals(to.getAddressSpace()) &&
					v.getOffset() <= to.getOffset() && to.getOffset() < v.getOffset() + v.getSize()) {
					Varnode o = op.getOutput();
					if (oc != PcodeOp.CALLOTHER || o == null || o.getDescendants().hasNext()) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * The block index and order a pre-comment at {@code c} is printed at, following the
	 * decompiler's CommentSorter::findPosition; null if it would not be printed.
	 */
	private static int[] commentPosition(HighFunction hf, List<PcodeOpAST> ops, Address c) {
		PcodeOpAST next = null, prev = null;
		for (PcodeOpAST op : ops) {
			if (op.getSeqnum().getTarget().compareTo(c) >= 0) {
				next = op;
				break;
			}
			prev = op;
		}
		if (next != null && next.getParent() != null && next.getParent().contains(c)) {
			return new int[] { next.getParent().getIndex(), next.getSeqnum().getOrder() };
		}
		if (prev != null && prev.getParent() != null && prev.getParent().contains(c)) {
			return new int[] { prev.getParent().getIndex(), Integer.MAX_VALUE };
		}
		if (next != null && next.getParent() != null && next.getSeqnum().getTarget().equals(c)) {
			return new int[] { next.getParent().getIndex(), next.getSeqnum().getOrder() };
		}
		return null;
	}

	/** Does an op printed before position {@code pos} in its block come after the read? */
	private static boolean executesBefore(HighFunction hf, List<PcodeOpAST> ops, int[] pos,
			Address eff) {
		for (PcodeOpAST op : ops) {
			PcodeBlockBasic b = op.getParent();
			if (b != null && b.getIndex() == pos[0] && op.getSeqnum().getOrder() < pos[1] &&
				op.getSeqnum().getTarget().compareTo(eff) >= 0 && op.getOpcode() != PcodeOp.MULTIEQUAL &&
				op.getOpcode() != PcodeOp.INDIRECT && (op.getOutput() == null ||
					op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND ||
					!op.getOutput().isUnique() && !op.getOutput().isRegister())) {
				return true;
			}
		}
		return false;
	}

	/** Listing fallback: the load's destination is overwritten before any use (straight line). */
	private boolean unusedOnStraightLine(Instruction in) {
		long dst = instrWrites(in) & 0xFFFFL & ~bit(15);
		if (Long.bitCount(dst) != 1) {
			return false;
		}
		Instruction x = in.getNext();
		for (int k = 0; k < 40 && x != null; k++) {
			if (x.getDelaySlotDepth() > 0 || !x.getFlowType().isFallthrough() ||
				hasIncomingJump(x.getAddress()) || (instrReads(x) & dst) != 0 ||
				pushReg(word(x)) == Long.numberOfTrailingZeros(dst)) {
				return false;
			}
			if ((instrWrites(x) & dst) != 0) {
				return true;
			}
			x = x.getNext();
		}
		return false;
	}

	// ------------------------------------------------------------------ 3. vectors 0-15

	private int setupFixedVectors() throws Exception {
		int created = 0;
		for (int n = 0; n < FIXED_VECTORS; n++) {
			Address va = addr(4L * n);
			putPointer(va);
			label(va, "v_" + VECTOR_NAMES[n]);
			Long t = readInt(va.getOffset());
			if (SP_VECTORS.contains(n) || t == null || !inCode(t)) {
				continue;
			}
			boolean had = fm.getFunctionAt(addr(t)) != null;
			Function f = makeFunction(addr(t));
			if (f != null && !had) {
				created++;
			}
		}
		Long reset = readInt(0);
		if (reset != null && inCode(reset)) {
			Function f = fm.getFunctionAt(addr(reset));
			if (f != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
				f.setName("h_PowerOnReset", SourceType.USER_DEFINED);
			}
			addEntryPoint(addr(reset));
		}
		println(TAG + "vectors 0-15 at 0x0: typed and labelled, " + created +
			" new functions at their targets (reset PC " +
			(reset == null ? "?" : "0x" + Long.toHexString(reset)) + ")");
		return created;
	}

	// ------------------------------------------------------------------ 4. VBR tables

	private int setupVbrTables() throws Exception {
		// Raw scan for "ldc Rm,vbr" (0100 mmmm 0010 1110) in executable memory, so this works
		// before analysis has found the code.
		TreeMap<Long, List<Long>> vbrs = new TreeMap<>();
		int sites = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.isInitialized() || !b.isExecute()) {
				continue;
			}
			for (long o = (b.getStart().getOffset() + 1) & ~1L; o + 1 <= b.getEnd().getOffset(); o +=
				2) {
				int w = readWord(o);
				if ((w & 0xf0ff) != 0x402e) {
					continue;
				}
				Instruction existing = listing.getInstructionContaining(addr(o));
				if (existing != null && !existing.getAddress().equals(addr(o))) {
					continue;
				}
				if (listing.getDefinedDataContaining(addr(o)) != null) {
					continue;
				}
				Long v = resolveReg(o, (w >> 8) & 0xf, 6);
				if (v == null) {
					continue;
				}
				sites++;
				vbrs.computeIfAbsent(v, k -> new ArrayList<>()).add(o);
				vbrSites.add(o);
			}
		}
		int created = 0;
		for (Map.Entry<Long, List<Long>> e : vbrs.entrySet()) {
			long vbr = e.getKey();
			String where = e.getValue().stream().map(x -> "0x" + Long.toHexString(x)).toList()
					.toString();
			if (vbr == 0) {
				println(TAG + "VBR = 0 set at " + where + " (boot code; vectors 0-15 at 0 cover it)");
				for (long s : e.getValue()) {
					disassembleSite(s);
				}
				continue;
			}
			int valid = vectorTableScore(vbr);
			if (valid < NUM_VECTORS / 2) {
				println(TAG + "ignoring candidate VBR 0x" + Long.toHexString(vbr) + " from " + where +
					": only " + valid + "/" + NUM_VECTORS + " entries are code addresses or erased");
				continue;
			}
			println(TAG + "VBR = 0x" + Long.toHexString(vbr) + " set at " + where + "; " + valid +
				"/" + NUM_VECTORS + " entries point to code or are erased");
			for (long s : e.getValue()) {
				disassembleSite(s);
				createBookmark(addr(s), BOOKMARK_CATEGORY,
					"ldc vbr: VBR = 0x" + Long.toHexString(vbr));
			}
			created += layVectorTable(vbr);
		}
		if (vbrs.isEmpty()) {
			println(TAG + "no 'ldc Rm,vbr' with a constant Rm found: only vectors 0-15 at 0 labelled");
		}
		return created;
	}

	private int vbrSiteFunctions() {
		// HEURISTIC: the VBR setup code is usually reached only through a pointer, so analysis
		// leaves it outside any function. Walk back from each "ldc Rm,vbr" over instructions that
		// fall through into it and create a function at the start of that run.
		int created = 0;
		for (long s : vbrSites) {
			Instruction cur = listing.getInstructionAt(addr(s));
			if (cur == null || fm.getFunctionContaining(cur.getAddress()) != null) {
				continue;
			}
			for (int k = 0; k < 64; k++) {
				Instruction prev = listing.getInstructionBefore(cur.getAddress());
				if (prev == null || !cur.getAddress().equals(prev.getFallThrough()) ||
					prev.isInDelaySlot() && prev.getFlowType().isTerminal() ||
					fm.getFunctionContaining(prev.getAddress()) != null) {
					break;
				}
				cur = prev;
			}
			while (cur != null && cur.isInDelaySlot()) {
				cur = cur.getNext();
			}
			if (cur == null) {
				continue;
			}
			Function f = makeFunction(cur.getAddress());
			if (f == null) {
				println(TAG + "HEURISTIC: could not create a function for the ldc vbr at 0x" +
					Long.toHexString(s));
				continue;
			}
			created++;
			if (f.getSymbol().getSource() == SourceType.DEFAULT) {
				try {
					f.setName("vbr_setup_" + Long.toHexString(cur.getAddress().getOffset()),
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					// keep the default name
				}
			}
			println(TAG + "HEURISTIC: function " + f.getName() + " at " + f.getEntryPoint() +
				" holds the ldc vbr at 0x" + Long.toHexString(s));
		}
		return created;
	}

	private void disassembleSite(long site) {
		// Disassemble from the constant load before the ldc so the setup code shows up.
		for (int k = 6; k >= 0; k--) {
			long a = site - 2L * k;
			int w = readWord(a);
			int hi = w >> 12;
			if (k == 0 || hi == 0xD || hi == 0xE || hi == 0x9) {
				if (listing.getInstructionAt(addr(a)) == null &&
					listing.isUndefined(addr(a), addr(a + 1))) {
					disassemble(addr(a));
				}
				if (listing.getInstructionAt(addr(site)) != null) {
					return;
				}
			}
		}
	}

	private int vectorTableScore(long vbr) {
		if (!mem.contains(addr(vbr)) || !mem.contains(addr(vbr + 4L * NUM_VECTORS - 1))) {
			return 0;
		}
		// Entries must be code addresses or erased (FFFFFFFF), with at least 16 real handlers.
		int code = 0, erased = 0;
		for (int i = 0; i < NUM_VECTORS; i++) {
			Long t = readInt(vbr + 4L * i);
			if (t != null && inCode(t)) {
				code++;
			}
			else if (t != null && t == 0xffffffffL) {
				erased++;
			}
		}
		return code < 16 ? code : code + erased;
	}

	private int layVectorTable(long vbr) throws Exception {
		Map<Long, List<Integer>> byTarget = new TreeMap<>();
		for (int n = 0; n < NUM_VECTORS; n++) {
			Address va = addr(vbr + 4L * n);
			putPointer(va);
			label(va, "v_" + VECTOR_NAMES[n]);
			Long t = readInt(va.getOffset());
			if (t != null && inCode(t) && !SP_VECTORS.contains(n)) {
				byTarget.computeIfAbsent(t, k -> new ArrayList<>()).add(n);
			}
		}
		label(addr(vbr), "VECTOR_TABLE_VBR");
		setPlateComment(addr(vbr), "Exception vector table at VBR = 0x" + Long.toHexString(vbr) +
			" (232 entries, labelled by SH7058_RawImageSetup)");
		int created = 0, failed = 0;
		long defTarget = -1;
		int defCount = 0;
		for (Map.Entry<Long, List<Integer>> e : byTarget.entrySet()) {
			if (e.getValue().size() > defCount) {
				defCount = e.getValue().size();
				defTarget = e.getKey();
			}
		}
		for (Map.Entry<Long, List<Integer>> e : byTarget.entrySet()) {
			Address ta = addr(e.getKey());
			boolean had = fm.getFunctionAt(ta) != null;
			Function f = makeFunction(ta);
			if (f == null) {
				failed++;
				continue;
			}
			if (!had) {
				created++;
			}
			List<Integer> vs = e.getValue();
			String name = null;
			if (e.getKey() == defTarget && defCount >= 8) {
				name = "h_DefaultHandler";
			}
			else if (vs.size() == 1) {
				name = "h_" + VECTOR_NAMES[vs.get(0)];
			}
			if (name != null && f.getSymbol().getSource() == SourceType.DEFAULT) {
				f.setName(name, SourceType.USER_DEFINED);
			}
			if (vs.size() > 1 && listing.getComment(CommentType.PLATE, ta) == null) {
				StringBuilder sb = new StringBuilder("Handler for " + vs.size() + " vectors:");
				for (int v : vs) {
					if (VECTOR_NAMES[v].startsWith("Reserved_") && vs.size() > 8) {
						continue; // list only the named ones on the default handler
					}
					sb.append(' ').append(v).append(' ').append(VECTOR_NAMES[v]);
				}
				setPlateComment(ta, sb.toString());
			}
		}
		println(TAG + "  table 0x" + Long.toHexString(vbr) + "-0x" +
			Long.toHexString(vbr + 4L * NUM_VECTORS - 1) + ": " + byTarget.size() +
			" distinct handlers, " + created + " new functions, " + failed +
			" targets could not be made functions; default handler 0x" +
			Long.toHexString(defTarget) + " (" + defCount + " vectors)");
		return created;
	}

	// ------------------------------------------------------------------ 5. prologue scan

	private boolean isPush(int w) {
		return (w & 0xff0f) == 0x2f06 || // mov.l Rm,@-r15
			(w & 0xff0f) == 0xff0b || // fmov.s FRm,@-r15
			w == 0x4f22 || w == 0x4f12 || w == 0x4f02 || w == 0x4f13; // sts.l pr/macl/mach, stc.l gbr
	}

	private int scanPrologues() throws Exception {
		// HEURISTIC: many functions are reached only through pointer tables. Look for the
		// "sts.l pr,@-r15" prologue in undefined executable memory, back up over the register
		// pushes before it, and keep the candidate only if it starts right after existing code
		// or data (or nop/erased padding) and pseudo-disassembles to a valid subroutine.
		int created = 0, rejected = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.isInitialized() || !b.isExecute()) {
				continue;
			}
			long lo = (b.getStart().getOffset() + 1) & ~1L;
			for (long o = lo; o + 1 <= b.getEnd().getOffset(); o += 2) {
				if (readWord(o) != 0x4f22 || !listing.isUndefined(addr(o), addr(o + 1))) {
					continue;
				}
				monitor.checkCancelled();
				long s = o;
				for (int k = 0; k < 16 && s - 2 >= lo; k++) {
					int w = readWord(s - 2);
					if (!isPush(w) || !listing.isUndefined(addr(s - 2), addr(s - 1))) {
						break;
					}
					s -= 2;
				}
				if (!boundaryBefore(s, lo)) {
					rejected++;
					continue;
				}
				if (!pdis.isValidSubroutine(addr(s), true)) {
					rejected++;
					continue;
				}
				disassemble(addr(s));
				if (createFunction(addr(s), null) != null) {
					created++;
				}
			}
		}
		println(TAG + "HEURISTIC prologue scan: " + created +
			" functions created at 4f22 (sts.l pr,@-r15) prologues; " + rejected +
			" candidates rejected (no code/data/padding boundary or not a valid subroutine)");
		return created;
	}

	private boolean boundaryBefore(long s, long lo) {
		if (s <= lo) {
			return true;
		}
		Address p = addr(s - 1);
		if (listing.getInstructionContaining(p) != null ||
			listing.getDefinedDataContaining(p) != null) {
			return true;
		}
		int w = readWord(s - 2);
		return w == 0x0009 || w == 0xffff || w == 0x0000;
	}

	// ------------------------------------------------------------------ 5b. more function entries

	/** Does code end right before {@code a} (no instruction falls into it)? */
	private boolean entryBoundary(Address a) {
		Instruction prev = listing.getInstructionContaining(a.subtract(1));
		if (prev == null) {
			return boundaryBefore(a.getOffset(), flash.getStart().getOffset()) ||
				listing.getDefinedDataContaining(a.subtract(1)) != null ||
				listing.isUndefined(a.subtract(2), a.subtract(1)); // after a literal pool
		}
		if (prev.isInDelaySlot()) {
			Instruction br = listing.getInstructionBefore(prev.getAddress());
			// bra/jmp/rts, or a bra Ghidra types as a tail call (CALL_TERMINATOR)
			return br != null && !br.getFlowType().hasFallthrough();
		}
		return !prev.getFlowType().hasFallthrough();
	}

	/**
	 * The words before {@code o} are a literal pool or padding after the end of a routine: an
	 * rts, rte, bra or jmp within {@code words} words above.
	 */
	private boolean afterReturn(long o, int words) {
		for (int k = 1; k <= words; k++) {
			int w = readWord(o - 2L * k);
			if (w == 0x000B || w == 0x002B || (w & 0xF000) == 0xA000 || (w & 0xF0FF) == 0x402B) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does an instruction read or write the first 4 bytes at {@code a} as data (a table, not
	 * code)? Only 4: a short routine's own literal pool can follow within a few words.
	 */
	private boolean readAsData(Address a) {
		for (int k = 0; k < 4; k++) {
			for (Reference r : rm.getReferencesTo(a.add(k))) {
				RefType t = r.getReferenceType();
				if ((t.isRead() || t.isWrite()) &&
					listing.getInstructionAt(r.getFromAddress()) != null) {
					return true;
				}
			}
		}
		return false;
	}

	/** Words that start a SHC function: a push of r8-r14/pr/mach/macl/gbr/fr12-fr15. */
	private static boolean isEntryPush(int w) {
		if ((w & 0xFF0F) == 0x2F06) {
			return ((w >> 4) & 0xF) >= 8 && ((w >> 4) & 0xF) <= 14;
		}
		if ((w & 0xFF0F) == 0xFF0B) {
			return ((w >> 4) & 0xF) >= 12;
		}
		return w == 0x4F22 || w == 0x4F12 || w == 0x4F02 || w == 0x4F13;
	}

	/**
	 * HEURISTIC ("noentries" disables it): auto-analysis leaves code reached only through
	 * function-pointer tables, literal-pool tail jumps ("mov.l @(disp,pc),Rn; jmp @Rn") or
	 * nothing visible (OS services) outside any function, often undisassembled, so it is never
	 * decompiled. Creates functions at (1) targets of pointer data in flash, (2) targets of jumps
	 * and calls that leave a function and land outside every function, and (3) undefined code
	 * after a literal pool or padding that starts with a callee-saved register push and
	 * pseudo-disassembles to a valid subroutine. Each target must start right after code that
	 * does not fall into it. Returns the number of functions created.
	 */
	private int findMoreEntries() throws Exception {
		Set<Address> cands = new TreeSet<>();
		int fromPtr = 0, fromJump = 0, fromPush = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (!b.isInitialized()) {
				continue;
			}
			for (Data d : listing.getDefinedData(new AddressSet(b.getStart(), b.getEnd()), true)) {
				if (!d.isPointer() || d.getLength() != 4 || !(d.getValue() instanceof Address t)) {
					continue;
				}
				Symbol s = st.getPrimarySymbol(d.getAddress());
				if (s != null && s.getName().startsWith("v_")) {
					continue; // vector slots: handled by steps 3/4
				}
				if (inCode(t.getOffset()) && fm.getFunctionContaining(t) == null && cands.add(t)) {
					fromPtr++;
				}
			}
		}
		for (Function f : fm.getFunctions(true)) {
			for (Instruction in : listing.getInstructions(f.getBody(), true)) {
				FlowType ft = in.getFlowType();
				if (!ft.isJump() && !ft.isCall()) {
					continue;
				}
				for (Reference r : in.getReferencesFrom()) {
					Address t = r.getToAddress();
					if ((r.getReferenceType().isJump() || r.getReferenceType().isCall()) &&
						!f.getBody().contains(t) && inCode(t.getOffset()) &&
						fm.getFunctionContaining(t) == null && cands.add(t)) {
						fromJump++;
					}
				}
			}
		}
		for (Address s : new ArrayList<>(cands)) {
			boolean undef = listing.getInstructionAt(s) == null;
			// undefined targets: a push, or code right after a routine's end that disassembles
			// as a subroutine (pool pointers also point at data tables, e.g. 01 02 04 08 masks)
			boolean push = isEntryPush(readWord(s.getOffset()));
			if (!entryBoundary(s) || readAsData(s) || (undef && !push &&
				(!afterReturn(s.getOffset(), 8) || !pdis.isValidSubroutine(s, true)))) {
				cands.remove(s);
			}
		}
		// (3) push-started code in undefined flash after a pool or padding
		long lo = (flash.getStart().getOffset() + 1) & ~1L;
		long hi = flash.getEnd().getOffset();
		for (long o = lo + 2; o + 1 < hi; o += 2) {
			if (!isEntryPush(readWord(o)) || isEntryPush(readWord(o - 2)) ||
				!listing.isUndefined(addr(o), addr(o + 1))) {
				continue;
			}
			Address a = addr(o);
			if (cands.contains(a) || !entryBoundary(a)) {
				continue;
			}
			// pools can be long (a dozen words or more)
			if (!afterReturn(o, 32) || readAsData(a) || !pdis.isValidSubroutine(a, true)) {
				continue;
			}
			cands.add(a);
			fromPush++;
		}
		int created = 0;
		List<String> ex = new ArrayList<>();
		for (Address a : cands) {
			monitor.checkCancelled();
			if (fm.getFunctionContaining(a) != null) {
				continue; // swallowed by a function created just before
			}
			if (listing.getInstructionAt(a) == null) {
				if (listing.getDefinedDataContaining(a) != null) {
					continue;
				}
				disassemble(a);
			}
			if (listing.getInstructionAt(a) == null) {
				continue;
			}
			if (createFunction(a, null) != null) {
				entriesCreated.add(a);
				created++;
				if (ex.size() < 12) {
					ex.add(a.toString());
				}
			}
		}
		println(TAG + "HEURISTIC more function entries: " + created + " functions created (" +
			"candidates: " + fromPtr + " pointer targets, " + fromJump + " jump/call targets " +
			"outside any function, " + fromPush + " push-started code after a pool), e.g. " + ex);
		return created;
	}

	/**
	 * Step 5b, second check, after all disassembly: an entry made there is wrong when code
	 * disassembled later falls into it (the join or epilogue of a function whose body the
	 * address-table repair redid, or an entry whose first instruction uses a register the
	 * instruction before it loads). Such a function is removed and the function it belongs to
	 * gets its body back, unless the entry is also called from elsewhere or is the target of
	 * pointer data (a routine with two table entries). Returns the number removed.
	 */
	private int revalidateEntries() throws Exception {
		int removed = 0;
		List<String> ex = new ArrayList<>();
		for (Address a : entriesCreated) {
			Function f = fm.getFunctionAt(a);
			if (f == null) {
				continue;
			}
			Instruction prev = listing.getInstructionBefore(a);
			if (prev == null || !prev.getMaxAddress().next().equals(a)) {
				continue;
			}
			boolean falls;
			if (prev.isInDelaySlot()) {
				Instruction br = listing.getInstructionBefore(prev.getAddress());
				falls = br != null && br.getFlowType().hasFallthrough();
			}
			else {
				falls = prev.getDelaySlotDepth() == 0 && prev.getFlowType().hasFallthrough();
			}
			if (!falls) {
				continue;
			}
			// calls from the function that falls into it don't count: once a function sits at
			// a join, Ghidra types that function's own "bra" to it as a tail call (0x90a8)
			Function owner = fm.getFunctionContaining(prev.getAddress());
			boolean entry = false;
			for (Reference r : rm.getReferencesTo(a)) {
				RefType t = r.getReferenceType();
				Data d = listing.getDefinedDataContaining(r.getFromAddress());
				Function from = fm.getFunctionContaining(r.getFromAddress());
				entry |= (t.isCall() && (from == null || !from.equals(owner))) ||
					(d != null && d.isPointer());
			}
			if (entry) {
				continue;
			}
			fm.removeFunction(a);
			// the Shared Return Calls analyzer turned the owner's own branches to the entry into
			// tail calls (flow override); make them plain branches again
			for (Reference r : rm.getReferencesTo(a)) {
				Instruction br = listing.getInstructionAt(r.getFromAddress());
				if (br != null && br.getFlowOverride() != FlowOverride.NONE && owner != null &&
					owner.getBody().contains(br.getAddress())) {
					br.setFlowOverride(FlowOverride.NONE);
				}
			}
			if (owner != null) {
				CreateFunctionCmd.fixupFunctionBody(currentProgram, owner, monitor);
			}
			removed++;
			if (ex.size() < 12) {
				ex.add(a + (owner == null ? "" : " (into " + owner.getName() + ")"));
			}
		}
		println(TAG + "HEURISTIC more function entries, re-check after disassembly: " + removed +
			" removed because the code before falls into them and nothing calls or points to " +
			"them " + ex);
		return removed;
	}

	// ------------------------------------------------------------------ 6. bogus IO refs

	private void removeBogusIoRefs() throws Exception {
		MemoryBlock io = mem.getBlock(addr(IO_START));
		long lastReg = IO_FALLBACK_LAST_REG;
		if (io != null) {
			long max = -1;
			SymbolIterator it = st.getSymbolIterator(io.getStart(), true);
			while (it.hasNext()) {
				Symbol s = it.next();
				if (!io.contains(s.getAddress())) {
					break;
				}
				if (s.getSource() != SourceType.DEFAULT) {
					max = Math.max(max, s.getAddress().getOffset());
				}
			}
			if (max > 0) {
				lastReg = max + 7; // allow for a 64-bit register at the last label
			}
		}
		AddressSet bogus = new AddressSet(addr(lastReg + 1), addr(0xffffffffL));
		AddressIterator dests = rm.getReferenceDestinationIterator(bogus, true);
		List<Reference> del = new ArrayList<>();
		while (dests.hasNext()) {
			Address d = dests.next();
			Symbol s = st.getPrimarySymbol(d);
			if (s != null && s.getSource() != SourceType.DEFAULT) {
				continue; // somebody labelled it on purpose
			}
			for (Reference r : rm.getReferencesTo(d)) {
				if (listing.getInstructionAt(r.getFromAddress()) != null) {
					del.add(r);
				}
			}
		}
		for (Reference r : del) {
			rm.delete(r);
		}
		println(TAG + "removed " + del.size() + " instruction references to " + bogus.getMinAddress() +
			"-ffffffff (no SH7058 register there; they come from small negative constants)");
	}

	// ------------------------------------------------------------------ 7. GBR

	private boolean isGbrLoad(Instruction in) {
		String m = in.getMnemonicString().toLowerCase();
		return (m.equals("ldc") || m.equals("ldc.l") || m.equals("_ldc") || m.equals("_ldc.l")) &&
			in.toString().toLowerCase().endsWith("gbr");
	}

	private void setupGbr() throws Exception {
		Register gbr = currentProgram.getRegister("gbr");
		ProgramContext ctx = currentProgram.getProgramContext();
		int sites = 0, restores = 0, resolved = 0, unresolved = 0, ranges = 0;
		TreeMap<Long, Integer> values = new TreeMap<>();
		AddressSet covered = new AddressSet();
		InstructionIterator ii = listing.getInstructions(true);
		List<Instruction> loads = new ArrayList<>();
		while (ii.hasNext()) {
			Instruction in = ii.next();
			if (isGbrLoad(in)) {
				loads.add(in);
			}
		}
		for (Instruction in : loads) {
			monitor.checkCancelled();
			sites++;
			int w = readWord(in.getAddress().getOffset());
			if ((w & 0xf0ff) == 0x4017) {
				restores++; // ldc.l @Rm+,gbr: restores the caller's GBR
				continue;
			}
			Long v = resolveReg(in.getAddress().getOffset(), (w >> 8) & 0xf, 8);
			if (v == null) {
				unresolved++;
				continue;
			}
			resolved++;
			values.merge(v, 1, Integer::sum);
			AddressSet range = gbrRange(in);
			for (AddressRange r : range) {
				ctx.setValue(gbr, r.getMinAddress(), r.getMaxAddress(), BigInteger.valueOf(v));
				ranges++;
			}
			covered.add(range);
		}
		println(TAG + "HEURISTIC GBR: " + sites + " ldc ...,gbr sites: " + resolved +
			" constant, " + restores + " ldc.l @Rm+,gbr restores, " + unresolved +
			" unresolved; GBR set over " + ranges + " ranges (" + covered.getNumAddresses() +
			" bytes); " + values.size() + " distinct values");

		int propagated = propagateGbrToCallees(gbr, ctx, covered);
		addGbrReferences(gbr, ctx);
		if (propagated > 0) {
			println(TAG + "  set GBR at the entry of " + propagated +
				" functions that use GBR without loading it (all callers agree)");
		}
	}

	/** From after the ldc to the next GBR load, or the end of the function / straight-line code. */
	private AddressSet gbrRange(Instruction ldc) {
		AddressSet set = new AddressSet();
		Function f = fm.getFunctionContaining(ldc.getAddress());
		AddressSetView body = f != null ? f.getBody() : null;
		Instruction in = ldc.getNext();
		Address start = null, last = null;
		long limit = ldc.getAddress().getOffset() + 0x1000;
		while (in != null) {
			Address a = in.getAddress();
			boolean inside = body != null ? body.contains(a)
					: (last == null || a.equals(last.next())) && a.getOffset() < limit;
			if (!inside || isGbrLoad(in)) {
				break;
			}
			if (start == null) {
				start = a;
			}
			last = in.getMaxAddress();
			if (body == null && in.getFlowType().isTerminal() && in.getDelaySlotDepth() == 0) {
				break;
			}
			in = in.getNext();
			if (in != null && body == null && in.isInDelaySlot()) {
				last = in.getMaxAddress();
				break;
			}
		}
		if (start != null) {
			set.add(start, last);
		}
		if (body != null) {
			set = set.intersect(body);
		}
		return set;
	}

	private boolean usesGbrRelative(Instruction in) {
		return in.toString().toLowerCase().contains(",gbr)");
	}

	private int propagateGbrToCallees(Register gbr, ProgramContext ctx, AddressSet covered)
			throws Exception {
		int n = 0;
		FunctionIterator fi = fm.getFunctions(true);
		while (fi.hasNext()) {
			Function f = fi.next();
			boolean uses = false;
			for (Instruction in : listing.getInstructions(f.getBody(), true)) {
				if (isGbrLoad(in)) {
					break; // loads its own GBR before any use
				}
				if (usesGbrRelative(in)) {
					uses = true;
					break;
				}
			}
			if (!uses || ctx.getValue(gbr, f.getEntryPoint(), false) != null) {
				continue;
			}
			BigInteger agreed = null;
			boolean ok = true;
			int callers = 0;
			for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
				if (!r.getReferenceType().isCall()) {
					continue;
				}
				callers++;
				BigInteger v = ctx.getValue(gbr, r.getFromAddress(), false);
				if (v == null || (agreed != null && !agreed.equals(v))) {
					ok = false;
					break;
				}
				agreed = v;
			}
			if (!ok || agreed == null || callers == 0) {
				continue;
			}
			for (AddressRange r : f.getBody()) {
				ctx.setValue(gbr, r.getMinAddress(), r.getMaxAddress(), agreed);
			}
			n++;
		}
		return n;
	}

	private void addGbrReferences(Register gbr, ProgramContext ctx) throws Exception {
		int rel = 0, known = 0, added = 0, matched = 0, mismatched = 0;
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext()) {
			Instruction in = ii.next();
			if (!usesGbrRelative(in)) {
				continue;
			}
			rel++;
			int w = readWord(in.getAddress().getOffset());
			int op = w >> 8;
			int size = switch (op) {
				case 0xC0, 0xC4 -> 1;
				case 0xC1, 0xC5 -> 2;
				case 0xC2, 0xC6 -> 4;
				default -> 0; // @(r0,gbr) forms: r0 is not a constant
			};
			BigInteger v = ctx.getValue(gbr, in.getAddress(), false);
			if (size == 0 || v == null) {
				continue;
			}
			known++;
			Address to = addr(v.longValue() + (long) size * (w & 0xff));
			if (!mem.contains(to)) {
				continue;
			}
			int opIndex = -1;
			for (int i = 0; i < in.getNumOperands(); i++) {
				if (in.getDefaultOperandRepresentation(i).toLowerCase().contains("gbr")) {
					opIndex = i;
				}
			}
			if (opIndex < 0) {
				continue;
			}
			boolean found = false, other = false;
			for (Reference r : in.getReferencesFrom()) {
				if (r.getToAddress().equals(to)) {
					found = true;
				}
				else if (r.isMemoryReference()) {
					other = true;
				}
			}
			if (found) {
				matched++;
				continue;
			}
			if (other) {
				mismatched++; // keep analysis' reference, but count the disagreement
				continue;
			}
			RefType type = op <= 0xC2 ? RefType.WRITE : RefType.READ;
			rm.addMemoryReference(in.getAddress(), to, type, SourceType.ANALYSIS, opIndex);
			added++;
		}
		println(TAG + "  @(disp,gbr) operands: " + rel + " GBR-relative instructions, " + known +
			" with a known GBR; analysis' reference agrees for " + matched + ", " + added +
			" references added, " + mismatched + " disagree with analysis (left alone)");
	}

	// ------------------------------------------------------------------ 8. address-table repair

	private static final Pattern CONFLICT = Pattern.compile(
		"Failed to disassemble at ([0-9a-fA-F]+) due to conflicting data at ([0-9a-fA-F]+)");

	/**
	 * HEURISTIC: the "Create Address Tables" analyzer turns runs of SH code whose words look like
	 * flash addresses (0x0009xxxx = nop + anything, 0x000bxxxx = rts + anything) into pointer
	 * tables, and flow into them then fails with "conflicting data". That silently drops the
	 * instructions (often an rts and its delay slot). Clear such data when nothing refers to it and
	 * the bytes disassemble, and disassemble the flow again.
	 */
	private int repairAddressTableConflicts() throws Exception {
		BookmarkManager bm = currentProgram.getBookmarkManager();
		List<Bookmark> errs = new ArrayList<>();
		Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
		while (it.hasNext()) {
			Bookmark b = it.next();
			if (CONFLICT.matcher(b.getComment()).find()) {
				errs.add(b);
			}
		}
		int fixed = 0, skipped = 0;
		for (Bookmark b : errs) {
			Matcher m = CONFLICT.matcher(b.getComment());
			m.find();
			Address at = addr(Long.parseLong(m.group(1), 16));
			Address conf = addr(Long.parseLong(m.group(2), 16));
			if (listing.getInstructionAt(at) != null) {
				bm.removeBookmark(b);
				continue;
			}
			if (listing.getDefinedDataContaining(conf) == null &&
				listing.getDefinedDataContaining(at) == null) {
				// the data has gone since (cleared by an earlier repair): just disassemble
				disassemble(at);
				if (listing.getInstructionAt(at) != null) {
					bm.removeBookmark(b);
					fixed++;
					println(TAG + "HEURISTIC address-table repair: " + at +
						" disassembled (the conflicting data is gone)");
					continue;
				}
			}
			// the run of removable data items from the conflict on (at most 32 bytes)
			List<Data> run = new ArrayList<>();
			Address p = conf;
			while (p != null && p.subtract(conf) < 32) {
				Data d = listing.getDefinedDataContaining(p);
				if (d == null || !removableTableData(d)) {
					break;
				}
				run.add(d);
				p = d.getMaxAddress().next();
			}
			Data first = listing.getDefinedDataContaining(conf);
			if (run.isEmpty() || first == null || !run.get(0).equals(first)) {
				skipped++;
				println(TAG + "HEURISTIC address-table repair: left the conflict at " + at +
					" alone (data at " + conf + " is referenced, named or not a pointer)");
				continue;
			}
			Address end = run.get(run.size() - 1).getMaxAddress();
			Address clearFrom = at.compareTo(run.get(0).getMinAddress()) < 0 ? at
					: run.get(0).getMinAddress();
			clearListing(clearFrom, end);
			disassemble(at);
			if (listing.getInstructionAt(at) == null) {
				skipped++;
				println(TAG + "HEURISTIC address-table repair: " + at + " still does not disassemble");
				continue;
			}
			bm.removeBookmark(b);
			Instruction before = listing.getInstructionBefore(at);
			Function f = before == null ? null : fm.getFunctionContaining(before.getAddress());
			if (f != null) {
				CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
			}
			fixed++;
			println(TAG + "HEURISTIC address-table repair: " + at + " disassembled again after " +
				"clearing " + run.size() + " unreferenced pointer item(s) at " +
				run.get(0).getMinAddress() + "-" + end +
				(f == null ? "" : " (function " + f.getName() + ")"));
		}
		if (!errs.isEmpty()) {
			println(TAG + "HEURISTIC address-table repair: " + fixed + " of " + errs.size() +
				" 'conflicting data' errors repaired, " + skipped + " left");
		}
		return fixed;
	}

	private boolean removableTableData(Data d) {
		if (d.getLength() > 8 || !(d.isPointer() || Undefined.isUndefined(d.getDataType()))) {
			return false;
		}
		for (Address a = d.getMinAddress(); a.compareTo(d.getMaxAddress()) <= 0; a = a.next()) {
			for (Reference r : rm.getReferencesTo(a)) {
				if (!r.getReferenceType().isFlow()) {
					return false; // flow into the item is what made the conflict
				}
			}
			for (Symbol s : st.getSymbols(a)) {
				if (s.getSource() != SourceType.DEFAULT) {
					return false;
				}
			}
		}
		return true;
	}

	// ------------------------------------------------------------------ 9. calling conventions

	// Register bit indices for the write/read analysis: r0-r15 = 0-15, fr0-fr15 = 16-31.
	private static final int MACH = 32, MACL = 33, GBR = 34, PR = 35, FPUL = 36, SR = 37,
			FPSCR = 38;
	private static final long ALL_REGS = (1L << 39) - 1;
	private static final long R4_R7 = 0xF0L;
	private static final long FR4_FR11 = 0xFFL << 20;
	private static final long RT_ARGS = 0x0FL | (0x0FL << 16); // r0-r3, fr0-fr3
	// what the default model calls callee-saved: r8-r14, fr12-fr15, mach, macl, gbr
	private static final long DEFAULT_UNAFFECTED =
		0x7F00L | (0xFL << 28) | (1L << MACH) | (1L << MACL) | (1L << GBR);

	static final String CC_PRESERVE = "__preserve_r4_r7";
	static final String CC_RUNTIME = "__shc_runtime";

	private static class RegInfo {
		long local; // registers written by the function's own instructions
		long restored; // pushed in the prologue and popped on every exit
		long inputs; // read before written (own instructions)
		boolean unknown; // unresolved call/jump, or flow into non-code
		String why;
		final Set<Function> callees = new LinkedHashSet<>();
		long writes; // fixed point: what the function may have changed when it returns
	}

	private static long bit(int i) {
		return 1L << i;
	}

	private int regIndex(Register r) {
		if (r == null) {
			return -1;
		}
		String n = r.getBaseRegister().getName().toLowerCase();
		if (n.matches("r\\d{1,2}")) {
			return Integer.parseInt(n.substring(1));
		}
		if (n.matches("fr\\d{1,2}")) {
			return 16 + Integer.parseInt(n.substring(2));
		}
		return switch (n) {
			case "mach" -> MACH;
			case "macl" -> MACL;
			case "gbr" -> GBR;
			case "pr" -> PR;
			case "fpul" -> FPUL;
			case "sr" -> SR;
			case "fpscr" -> FPSCR;
			default -> -1;
		};
	}

	private static String regMaskString(long m) {
		StringBuilder sb = new StringBuilder();
		String[] special = { "mach", "macl", "gbr", "pr", "fpul", "sr", "fpscr" };
		for (int i = 0; i < 39; i++) {
			if ((m & bit(i)) != 0) {
				sb.append(sb.length() == 0 ? "" : ",")
						.append(i < 16 ? "r" + i : i < 32 ? "fr" + (i - 16) : special[i - 32]);
			}
		}
		return sb.toString();
	}

	/** Register saved by a push onto the r15 stack, or -1. */
	private static int pushReg(int w) {
		if ((w & 0xFF0F) == 0x2F06) {
			return (w >> 4) & 0xF; // mov.l Rm,@-r15
		}
		if ((w & 0xFF0F) == 0xFF0B) {
			return 16 + ((w >> 4) & 0xF); // fmov.s FRm,@-r15
		}
		return switch (w) {
			case 0x4F02 -> MACH;
			case 0x4F12 -> MACL;
			case 0x4F13 -> GBR;
			case 0x4F22 -> PR;
			case 0x4F52 -> FPUL;
			case 0x4F62 -> FPSCR;
			case 0x4F03 -> SR;
			default -> -1;
		};
	}

	/** Register restored by a pop from the r15 stack, or -1. */
	private static int popReg(int w) {
		if ((w & 0xF0FF) == 0x60F6 && (w & 0x0F00) != 0x0F00) {
			return (w >> 8) & 0xF; // mov.l @r15+,Rn
		}
		if ((w & 0xF0FF) == 0xF0F9) {
			return 16 + ((w >> 8) & 0xF); // fmov.s @r15+,FRn
		}
		return switch (w) {
			case 0x4F06 -> MACH;
			case 0x4F16 -> MACL;
			case 0x4F17 -> GBR;
			case 0x4F26 -> PR;
			case 0x4F56 -> FPUL;
			case 0x4F66 -> FPSCR;
			case 0x4F07 -> SR;
			default -> -1;
		};
	}

	private int word(Instruction in) {
		return readWord(in.getAddress().getOffset());
	}

	private long varnodeMask(Varnode v) {
		if (v == null || !v.isRegister()) {
			return 0;
		}
		Register r = currentProgram.getRegister(v.getAddress(), v.getSize());
		if (r == null) {
			r = currentProgram.getRegister(v.getAddress());
		}
		int i = regIndex(r);
		return i < 0 ? 0 : bit(i);
	}

	/**
	 * Registers an instruction writes. A delayed branch's p-code includes its delay slot, so only
	 * the branch's own effect (pr for bsr/jsr/bsrf) is counted; the slot is analysed on its own.
	 */
	private long instrWrites(Instruction in) {
		if (in.getDelaySlotDepth() > 0) {
			return in.getFlowType().isCall() ? bit(PR) : 0;
		}
		long m = 0;
		for (PcodeOp op : in.getPcode()) {
			if (!isSelfCopy(op)) {
				m |= varnodeMask(op.getOutput());
			}
		}
		return m;
	}

	/** "nop" is "r0 = r0" in superh.sinc: a self-copy neither reads nor changes the register. */
	private static boolean isSelfCopy(PcodeOp op) {
		return op.getOpcode() == PcodeOp.COPY && op.getOutput() != null &&
			op.getOutput().equals(op.getInput(0));
	}

	/** Registers an instruction reads as values (a push only saves its register). */
	private long instrReads(Instruction in) {
		long m = 0;
		if (in.getDelaySlotDepth() > 0) {
			for (int i = 0; i < in.getNumOperands(); i++) {
				for (Object o : in.getOpObjects(i)) {
					if (o instanceof Register r) {
						int k = regIndex(r);
						m |= k < 0 ? 0 : bit(k);
					}
				}
			}
			if (in.getFlowType().isConditional()) {
				m |= bit(SR);
			}
			return m;
		}
		int w = word(in);
		if (pushReg(w) >= 0) {
			return bit(15);
		}
		// in p-code order: a register an earlier op of this instruction wrote in full is no
		// longer an input (e.g. swap.w/swap.b build Rn in steps; xtrct really reads old Rn)
		long defined = 0;
		for (PcodeOp op : in.getPcode()) {
			if (isSelfCopy(op)) {
				continue;
			}
			for (Varnode v : op.getInputs()) {
				m |= varnodeMask(v) & ~defined;
			}
			Varnode o = op.getOutput();
			long om = varnodeMask(o);
			if (om != 0) {
				Register r = currentProgram.getRegister(o.getAddress(), o.getSize());
				if (r != null && r.isBaseRegister() && o.getSize() == r.getMinimumByteSize()) {
					defined |= om;
				}
			}
		}
		// "subc Rn,Rn" (Rn = -T), "sub Rn,Rn" and "xor Rn,Rn" (Rn = 0) do not depend on Rn
		int n = (w >> 8) & 0xF, k = (w >> 4) & 0xF, lo = w & 0xF00F;
		if (n == k && (lo == 0x300A || lo == 0x3008 || lo == 0x200A)) {
			m &= ~bit(n);
		}
		return m;
	}

	private boolean hasIncomingJump(Address a) {
		for (Reference r : rm.getReferencesTo(a)) {
			if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) {
				return true;
			}
		}
		return false;
	}

	/** Pops in the straight-line epilogue that ends at an exit instruction (and its slot). */
	private long epiloguePops(Instruction exit) {
		long pops = 0;
		if (exit.getDelaySlotDepth() > 0) {
			Instruction ds = listing.getInstructionAt(exit.getMaxAddress().next());
			if (ds != null && popReg(word(ds)) >= 0) {
				pops |= bit(popReg(word(ds)));
			}
		}
		Instruction cur = exit;
		for (int k = 0; k < 48; k++) {
			if (hasIncomingJump(cur.getAddress())) {
				break; // another path joins here and may skip the pops before it
			}
			Instruction prev = listing.getInstructionBefore(cur.getAddress());
			if (prev == null || prev.isInDelaySlot() || prev.getDelaySlotDepth() > 0 ||
				!cur.getAddress().equals(prev.getFallThrough()) || !prev.getFlowType().isFallthrough() ||
				prev.getFlowType().isCall()) {
				break;
			}
			int p = popReg(word(prev));
			if (p >= 0) {
				pops |= bit(p);
			}
			cur = prev;
		}
		return pops;
	}

	private RegInfo localRegInfo(Function f) {
		RegInfo ri = new RegInfo();
		AddressSetView body = f.getBody();
		// prologue: pushes in the straight-line code at the entry, before the register is written
		long pushed = 0, early = 0;
		Instruction in = listing.getInstructionAt(f.getEntryPoint());
		for (int k = 0; k < 40 && in != null && body.contains(in.getAddress()); k++) {
			if (in.getDelaySlotDepth() > 0 || !in.getFlowType().isFallthrough()) {
				break;
			}
			int p = pushReg(word(in));
			if (p >= 0 && (early & bit(p)) == 0) {
				pushed |= bit(p);
			}
			else {
				early |= instrWrites(in);
			}
			Address ft = in.getFallThrough();
			in = ft == null ? null : listing.getInstructionAt(ft);
		}
		long restored = pushed;
		for (Instruction x : listing.getInstructions(body, true)) {
			ri.local |= instrWrites(x);
			FlowType ft = x.getFlowType();
			Address[] flows = x.getFlows();
			boolean exit = false;
			if (ft.isCall()) {
				if (flows.length == 0) {
					List<Address> tbl = tableCallTargets(x);
					if (tbl == null) {
						unknown(ri, "computed call at " + x.getAddress());
					}
					else {
						flows = tbl.toArray(new Address[0]);
						tableCalls++;
					}
				}
				for (Address t : flows) {
					calleeAt(ri, t, x);
				}
			}
			else if (ft.isJump()) {
				if (ft.isComputed() && flows.length == 0) {
					unknown(ri, "unresolved computed jump at " + x.getAddress());
				}
				for (Address t : flows) {
					if (!body.contains(t)) {
						exit = true; // tail call, or a jump into another function
						calleeAt(ri, t, x);
					}
				}
			}
			else if (ft.isTerminal()) {
				exit = true;
			}
			if (ft.isCall() && ft.isTerminal()) {
				exit = true; // jmp/bra used as a tail call
			}
			// A delay slot's own fall-through is not a flow; its branch's fall-through is.
			Address fall = x.isInDelaySlot() ? null : x.getFallThrough();
			if (fall != null) {
				if (listing.getInstructionAt(fall) == null) {
					unknown(ri, "flow from " + x.getAddress() + " into non-code at " + fall);
				}
				else if (!body.contains(fall)) {
					exit = true;
					calleeAt(ri, fall, x);
				}
			}
			if (exit && restored != 0) {
				restored &= epiloguePops(x);
			}
		}
		ri.restored = restored;
		return ri;
	}

	private int tableCalls;

	/**
	 * HEURISTIC: targets of "mova @(disp,pc),r0; ... mov.l @(r0,Rm),Rn; ... jsr @Rn" (a call
	 * through a constant table of function pointers, as in a table-lookup dispatch).
	 * Returns the run of consecutive table entries that are function entry points (at least 2,
	 * stopping at the first entry that is not), or null.
	 */
	private List<Address> tableCallTargets(Instruction call) {
		int w = word(call);
		if ((w & 0xF0FF) != 0x400B) {
			return null; // jsr @Rn only
		}
		int rn = (w >> 8) & 0xF;
		long a = call.getAddress().getOffset();
		int idxReg = -1;
		for (int k = 1; k <= 8; k++) {
			long pa = a - 2L * k;
			int pw = readWord(pa);
			if (pw < 0 || (k > 1 && isFlowBreak(pw))) {
				return null;
			}
			if (idxReg < 0) {
				// mov.l @(r0,Rm),Rn = 0000 nnnn mmmm 1110
				if ((pw & 0xF00F) == 0x000E && ((pw >> 8) & 0xF) == rn) {
					idxReg = (pw >> 4) & 0xF;
					continue;
				}
				if (writesReg(pa, rn)) {
					return null;
				}
				continue;
			}
			if ((pw & 0xFF00) == 0xC700) { // mova @(disp,pc),r0
				long base = ((pa + 4) & ~3L) + 4L * (pw & 0xff);
				List<Address> t = new ArrayList<>();
				for (int i = 0; i < 64; i++) {
					Long v = readInt(base + 4L * i);
					if (v == null || !inCode(v) || fm.getFunctionAt(addr(v)) == null) {
						break;
					}
					t.add(addr(v));
				}
				return t.size() >= 2 ? t : null;
			}
			if (writesReg(pa, 0)) {
				return null;
			}
		}
		return null;
	}

	private void unknown(RegInfo ri, String why) {
		if (!ri.unknown) {
			ri.unknown = true;
			ri.why = why;
		}
	}

	private void calleeAt(RegInfo ri, Address t, Instruction from) {
		Function g = fm.getFunctionAt(t);
		if (g == null) {
			unknown(ri, "flow from " + from.getAddress() + " to " + t + ", which is not a function");
		}
		else {
			ri.callees.add(g);
		}
	}

	/**
	 * Registers read before being written on some path from the entry: a forward "may still
	 * hold the entry value" dataflow over the function's instructions. A call adds the callee's
	 * inputs (if still unwritten) and then counts the callee's may-write set as written; a tail
	 * jump adds the target's inputs. Delay slots execute before their branch takes effect.
	 */
	private long dataflowInputs(Function f, Map<Function, RegInfo> info) {
		AddressSetView body = f.getBody();
		Map<Address, Long> uin = new HashMap<>();
		Deque<Address> work = new ArrayDeque<>();
		uin.put(f.getEntryPoint(), ALL_REGS);
		work.add(f.getEntryPoint());
		long inputs = 0;
		int steps = 0;
		while (!work.isEmpty() && steps++ < 200000) {
			Address a = work.poll();
			Instruction x = listing.getInstructionAt(a);
			if (x == null) {
				continue;
			}
			long u = uin.get(a);
			inputs |= instrReads(x) & u;
			long out = u & ~instrWrites(x);
			Instruction branch = x;
			if (x.getDelaySlotDepth() > 0) {
				Instruction ds = listing.getInstructionAt(x.getMaxAddress().next());
				if (ds == null) {
					continue;
				}
				inputs |= instrReads(ds) & out;
				out &= ~instrWrites(ds);
			}
			else if (x.isInDelaySlot()) {
				continue; // reached only through its branch
			}
			FlowType ft = branch.getFlowType();
			List<Address> next = new ArrayList<>();
			Address[] flows = branch.getFlows();
			if (ft.isCall()) {
				if (flows.length == 0) {
					List<Address> tbl = tableCallTargets(branch);
					flows = tbl == null ? flows : tbl.toArray(new Address[0]);
				}
				long w = flows.length == 0 ? ALL_REGS : 0;
				for (Address t : flows) {
					RegInfo gi = info.get(fm.getFunctionAt(t));
					if (gi == null) {
						w = ALL_REGS;
						continue;
					}
					inputs |= gi.inputs & out;
					w |= gi.writes;
				}
				out &= ~w;
				if (!ft.isTerminal() && branch.getFallThrough() != null) {
					next.add(branch.getFallThrough());
				}
			}
			else {
				for (Address t : flows) {
					next.add(t);
				}
				if (ft.isFallthrough() || ft.isConditional()) {
					if (branch.getFallThrough() != null) {
						next.add(branch.getFallThrough());
					}
				}
			}
			for (Address t : next) {
				if (!body.contains(t)) {
					RegInfo gi = info.get(fm.getFunctionAt(t));
					if (gi != null) {
						inputs |= gi.inputs & out; // tail call / fall into another function
					}
					continue;
				}
				Long old = uin.get(t);
				long nu = old == null ? out : old | out;
				if (old == null || nu != old) {
					uin.put(t, nu);
					work.add(t);
				}
			}
		}
		return inputs & ~(bit(15) | bit(PR) | bit(SR) | bit(GBR) | bit(FPSCR));
	}

	/**
	 * HEURISTIC: SHC code relies on some callees (runtime helpers, small leaf routines) leaving
	 * r4-r7 alone, although the ABI makes them scratch. The default model in superh2e.cspec says
	 * r4-r7 are killed by a call (the safe choice). This step computes, as a fixed point over the
	 * call graph, which registers each function may change, and gives the functions that
	 * provably never change r4-r7 the __preserve_r4_r7 model. Those that also take their
	 * arguments in r0-r3/fr0-fr3 (SHC runtime and library helpers) get __shc_runtime.
	 * Anything unresolved (computed calls or jumps, flow into data) counts as changing every
	 * register, so the result is conservative.
	 */
	private void assignCallingConventions() throws Exception {
		CompilerSpec cs = currentProgram.getCompilerSpec();
		if (cs.getCallingConvention(CC_PRESERVE) == null) {
			println(TAG + "compiler spec has no '" + CC_PRESERVE + "' model (old superh2e.cspec?): " +
				"calling-convention step skipped");
			return;
		}
		boolean haveRt = cs.getCallingConvention(CC_RUNTIME) != null;
		String defName = cs.getDefaultCallingConvention().getName();
		Map<Function, RegInfo> info = new LinkedHashMap<>();
		tableCalls = 0;
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			info.put(f, localRegInfo(f));
		}
		for (RegInfo ri : info.values()) {
			ri.writes = ((ri.unknown ? ALL_REGS : 0) | ri.local) & ~ri.restored;
		}
		boolean changed = true;
		int rounds = 0;
		while (changed) {
			changed = false;
			rounds++;
			for (RegInfo ri : info.values()) {
				long w = ri.writes;
				for (Function g : ri.callees) {
					RegInfo gi = info.get(g);
					w |= gi == null ? ALL_REGS : gi.writes;
				}
				w &= ~ri.restored;
				if (w != ri.writes) {
					ri.writes = w;
					changed = true;
				}
			}
		}
		// inputs: fixed point over the call graph (monotone; capped for safety)
		for (int r = 0; r < 30; r++) {
			boolean ch = false;
			for (Map.Entry<Function, RegInfo> e : info.entrySet()) {
				long in = dataflowInputs(e.getKey(), info) | e.getValue().inputs;
				if (in != e.getValue().inputs) {
					e.getValue().inputs = in;
					ch = true;
				}
			}
			if (!ch) {
				break;
			}
		}
		Map<Function, String> exc = exceptionEntries();
		int excVoid = 0;
		List<String> excKept = new ArrayList<>(), excRteOnly = new ArrayList<>();
		int preserve = 0, runtime = 0, reset = 0, kept = 0, unknownCount = 0, abiViolations = 0;
		List<String> violEx = new ArrayList<>(), rtEx = new ArrayList<>();
		for (Map.Entry<Function, RegInfo> e : info.entrySet()) {
			Function f = e.getKey();
			RegInfo ri = e.getValue();
			if (ri.unknown) {
				unknownCount++;
			}
			else if ((ri.local & ~ri.restored & DEFAULT_UNAFFECTED) != 0) {
				abiViolations++;
				if (violEx.size() < 12) {
					violEx.add(f.getName() + "(" +
						regMaskString(ri.local & ~ri.restored & DEFAULT_UNAFFECTED) +
						")");
				}
			}
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			String why = exc.get(f);
			if (why != null) {
				// exception/interrupt entry: no register arguments, nothing returned in r0/fr0
				String cur = f.getCallingConventionName();
				if (CC_PRESERVE.equals(cur) || CC_RUNTIME.equals(cur)) {
					f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
				}
				boolean called = false;
				for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
					called |= r.getReferenceType().isCall();
				}
				if (!called && f.getSignatureSource() == SourceType.DEFAULT) {
					f.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING,
						new ReturnParameterImpl(VoidDataType.dataType, currentProgram),
						List.of(), FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
						SourceType.ANALYSIS);
					excVoid++;
				}
				else {
					excKept.add(f.getName() + (called ? "(called)" : "(user signature)"));
				}
				if (!why.startsWith("vector")) {
					excRteOnly.add(f.getName() + "@" + f.getEntryPoint());
				}
				continue;
			}
			String want = null;
			if ((ri.writes & R4_R7) == 0) {
				boolean rt = haveRt && (ri.inputs & RT_ARGS) != 0 &&
					(ri.inputs & (R4_R7 | FR4_FR11)) == 0;
				want = rt ? CC_RUNTIME : CC_PRESERVE;
			}
			String cur = f.getCallingConventionName();
			boolean ours = CC_PRESERVE.equals(cur) || CC_RUNTIME.equals(cur);
			boolean free = ours || cur == null ||
				Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(cur) ||
				Function.DEFAULT_CALLING_CONVENTION_STRING.equals(cur) || defName.equals(cur);
			if (!free || (f.getSignatureSource() == SourceType.USER_DEFINED && !ours)) {
				kept++;
				continue;
			}
			if (want == null) {
				if (ours) {
					f.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
					reset++;
				}
			}
			else {
				if (!want.equals(cur)) {
					f.setCallingConvention(want);
				}
				if (want.equals(CC_RUNTIME)) {
					runtime++;
					if (rtEx.size() < 16) {
						rtEx.add(f.getName() + "(in " + regMaskString(ri.inputs) + ")");
					}
				}
				else {
					preserve++;
				}
			}
		}
		println(TAG + "HEURISTIC calling conventions: register-write fixed point over " +
			info.size() + " functions (" + rounds + " rounds); " + unknownCount +
			" have unresolved flow and count as changing every register; " + tableCalls +
			" calls through constant function-pointer tables resolved");
		println(TAG + "  " + preserve + " functions provably leave r4-r7 unchanged -> " +
			CC_PRESERVE + "; " + runtime + " of the others also take r0-r3/fr0-fr3 arguments -> " +
			CC_RUNTIME + "; the rest keep the default model (r4-r7 killed by a call)" +
			(reset > 0 ? "; " + reset + " reset to the default" : "") +
			(kept > 0 ? "; " + kept + " with a user-set convention left alone" : ""));
		if (!rtEx.isEmpty()) {
			println(TAG + "  " + CC_RUNTIME + " e.g. " + rtEx);
		}
		println(TAG + "  " + exc.size() + " exception/interrupt entries (vector targets or rte) keep " +
			"the default model; " + excVoid + " of them get a void(void) signature" +
			(excKept.isEmpty() ? "" : "; signature left alone: " + excKept) +
			(excRteOnly.isEmpty() ? "" : "; entries found only by rte: " + excRteOnly));

		if (abiViolations > 0) {
			println(TAG + "  NOTE: " + abiViolations + " functions may change a register the " +
				"default model treats as callee-saved (hand-written code?), e.g. " + violEx);
		}
		if (!optNoProtos) {
			commitPrototypes(info, exc);
		}
		if (debugOut != null) {
			for (Map.Entry<Function, RegInfo> e : info.entrySet()) {
				RegInfo ri = e.getValue();
				debugOut.println(e.getKey().getEntryPoint() + " " + e.getKey().getName() + " cc=" +
					e.getKey().getCallingConventionName() + " writes=" + regMaskString(ri.writes) +
					" restored=" + regMaskString(ri.restored) + " inputs=" +
					regMaskString(ri.inputs) + (ri.unknown ? " UNKNOWN(" + ri.why + ")" : ""));
			}
			debugOut.flush();
		}
	}

	/**
	 * Exception and interrupt entries: functions whose entry is stored in a vector slot (a "v_"
	 * label, from steps 3/4), or that nothing calls and whose body returns with rte. They take no
	 * register arguments.
	 */
	private Map<Function, String> exceptionEntries() {
		Map<Function, String> m = new LinkedHashMap<>();
		for (Function f : fm.getFunctions(true)) {
			for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
				Symbol s = st.getPrimarySymbol(r.getFromAddress());
				if (listing.getDefinedDataAt(r.getFromAddress()) != null && s != null &&
					s.getName().startsWith("v_")) {
					m.put(f, "vector " + s.getName());
					break;
				}
			}
			if (m.containsKey(f)) {
				continue;
			}
			boolean called = false;
			for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
				called |= r.getReferenceType().isCall();
			}
			if (called) {
				continue; // e.g. "mov r5,r15; push 0; push r4; rte" starting a task
			}
			for (Instruction in : listing.getInstructions(f.getBody(), true)) {
				if (word(in) == 0x002B) {
					m.put(f, "rte at " + in.getAddress());
					break;
				}
			}
		}
		return m;
	}

	// ------------------------------------------------------------------ 9b. prototypes

	private static final String PROTO_TAG = "SH7058SETUP_PARAMS";

	/** Register index (see regIndex) of the register a storage varnode lies in, or -1. */
	private int storageRegIndex(Varnode v) {
		if (v == null || !v.isRegister()) {
			return -1;
		}
		Register r = currentProgram.getRegister(v.getAddress(), v.getSize());
		if (r == null) {
			for (Register c : currentProgram.getLanguage().getRegisters()) {
				if (c.isBaseRegister() && c.getAddressSpace().equals(v.getAddress().getAddressSpace()) &&
					c.getOffset() <= v.getOffset() &&
					v.getOffset() + v.getSize() <= c.getOffset() + c.getMinimumByteSize()) {
					r = c;
					break;
				}
			}
		}
		return regIndex(r);
	}

	/** Callees first (post-order over the call graph; cycles are cut where they close). */
	private List<Function> bottomUp(Map<Function, RegInfo> info) {
		List<Function> order = new ArrayList<>();
		Set<Function> seen = new HashSet<>();
		for (Function root : info.keySet()) {
			if (!seen.add(root)) {
				continue;
			}
			Deque<Object[]> stack = new ArrayDeque<>();
			stack.push(new Object[] { root, info.get(root).callees.iterator() });
			while (!stack.isEmpty()) {
				@SuppressWarnings("unchecked")
				Iterator<Function> it = (Iterator<Function>) stack.peek()[1];
				if (it.hasNext()) {
					Function g = it.next();
					if (info.containsKey(g) && seen.add(g)) {
						stack.push(new Object[] { g, info.get(g).callees.iterator() });
					}
				}
				else {
					order.add((Function) stack.pop()[0]);
				}
			}
		}
		return order;
	}

	/**
	 * Call-site evidence for a callee's argument registers. For each call (or tail jump) to
	 * {@code f}, the caller's code that can run just before it is searched backwards (all paths,
	 * delay slots included, at most 48 instructions, not past another call): the argument
	 * registers written there count as set by the caller, and when the search reaches the
	 * caller's entry the caller's own inputs count too (an argument passed through). Returns the
	 * number of call sites at index 39 and, per register index, how many set that register.
	 */
	private int[] callSiteEvidence(Function f, Map<Function, RegInfo> info, long argMask) {
		int[] ev = new int[40];
		for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
			RefType t = r.getReferenceType();
			if (!t.isCall() && !t.isJump()) {
				continue;
			}
			Instruction call = listing.getInstructionAt(r.getFromAddress());
			Function caller = call == null ? null : fm.getFunctionContaining(call.getAddress());
			if (call == null || caller == null || caller.equals(f)) {
				continue;
			}
			AddressSetView body = caller.getBody();
			long w = 0;
			boolean atEntry = false;
			if (call.getDelaySlotDepth() > 0) {
				Instruction ds = listing.getInstructionAt(call.getMaxAddress().next());
				w |= ds == null ? 0 : instrWrites(ds);
			}
			// backward search: instructions whose effect happens before 'call'
			Deque<Instruction> work = new ArrayDeque<>();
			Set<Address> seen = new HashSet<>();
			work.add(call);
			int budget = 48;
			while (!work.isEmpty() && budget > 0) {
				Instruction cur = work.poll();
				if (cur.getAddress().equals(caller.getEntryPoint())) {
					atEntry = true;
				}
				// predecessors of cur: the instruction falling into it, and branches to it
				List<Instruction> preds = new ArrayList<>();
				Instruction prev = listing.getInstructionBefore(cur.getAddress());
				if (prev != null && body.contains(prev.getAddress()) &&
					cur.getAddress().equals(prev.getMaxAddress().next())) {
					if (prev.isInDelaySlot()) {
						Instruction br = listing.getInstructionBefore(prev.getAddress());
						if (br != null && br.getFlowType().isConditional() &&
							!br.getFlowType().isCall()) {
							preds.add(prev); // bt/s, bf/s: slot, then fall through
						}
					}
					else if (prev.getDelaySlotDepth() == 0 && !prev.getFlowType().isCall() &&
						(prev.getFlowType().isFallthrough() || prev.getFlowType().isConditional())) {
						preds.add(prev);
					}
				}
				for (Reference in : rm.getReferencesTo(cur.getAddress())) {
					Instruction src = listing.getInstructionAt(in.getFromAddress());
					if (src != null && in.getReferenceType().isJump() &&
						!in.getReferenceType().isCall() && body.contains(src.getAddress())) {
						if (src.getDelaySlotDepth() > 0) {
							Instruction ds = listing.getInstructionAt(src.getMaxAddress().next());
							if (ds != null && seen.add(ds.getAddress())) {
								w |= instrWrites(ds);
								budget--;
							}
						}
						preds.add(src);
					}
				}
				for (Instruction p : preds) {
					if (!seen.add(p.getAddress())) {
						continue;
					}
					if (p.isInDelaySlot()) {
						w |= instrWrites(p);
						budget--;
						Instruction br = listing.getInstructionBefore(p.getAddress());
						if (br != null && seen.add(br.getAddress())) {
							work.add(br); // a conditional delayed branch: continue above it
						}
						continue;
					}
					if (p.getFlowType().isCall()) {
						continue; // not past another call
					}
					w |= instrWrites(p);
					budget--;
					work.add(p);
				}
			}
			RegInfo ci = info.get(caller);
			if (atEntry && ci != null && !ci.unknown) {
				w |= ci.inputs; // passed through from the caller's own arguments
			}
			ev[39]++;
			for (int k = 0; k < 39; k++) {
				if ((argMask & bit(k) & w) != 0) {
					ev[k]++;
				}
			}
		}
		return ev;
	}

	private DecompInterface newDecompiler() {
		DecompInterface d = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		opts.grabFromProgram(currentProgram);
		d.setOptions(opts);
		d.toggleCCode(false);
		d.toggleSyntaxTree(true);
		d.setSimplificationStyle("decompile");
		if (!d.openProgram(currentProgram)) {
			d.dispose();
			return null;
		}
		return d;
	}

	private static boolean hasProtoTag(Function f) {
		return f.getTags().stream().anyMatch(t -> t.getName().equals(PROTO_TAG));
	}

	/**
	 * HEURISTIC ("noprotos" disables it): commit parameter lists, so that call sites show the
	 * arguments the callee takes. Ghidra does not run "Decompiler Parameter ID" on a raw binary,
	 * so every callee prototype stays unlocked and each call site guesses its own arguments. That
	 * guess drops a register whose value is also used by anything other than the call
	 * (Funcdata::onlyOpUse / ancestorOpUse): "mov #2,r5; jsr; mov r5,r4" passes only r4, a
	 * "fldi0 fr5" that a compare also reads is not passed, "mov r5,r4; add #-2,r4" loses r5. With
	 * the callee's parameters committed, the call site uses them instead of guessing.
	 * <p>
	 * Bottom-up over the call graph, each function is decompiled (its callees already committed).
	 * Three views of each argument register (r4-r7 and fr4-fr11, or r0-r3/fr0-fr3 for
	 * __shc_runtime) are combined: the decompiler's own parameter list, the register inputs from
	 * the dataflow of step 9 (may be read before written, own code and callees), and the call
	 * sites (does the caller set the register just before the call, or pass its own argument
	 * through). Each view over-approximates in its own way (paths that never run, registers
	 * spilled to the stack, stale values left in registers), so a register is kept when the
	 * dataflow reads it and at least half of the call sites set it (with no call sites: when the
	 * decompiler also has it). With unresolved flow in or below the function the dataflow is only
	 * a lower bound, so there a register needs the decompiler or the dataflow, plus the call
	 * sites. The kept list is filled up to the highest kept register of each class (SHC assigns
	 * argument registers in order), with the decompiler's types where it has them; the
	 * decompiler's stack parameters are kept only if no register above them was dropped. A
	 * function that may really read a register the callers do not set (the dataflow and the
	 * decompiler agree; under unresolved flow, any view) is left alone rather than shown reading
	 * an in_ register, and so are functions the decompiler cannot handle (a caller that crashes
	 * the decompiler with a committed callee gets that callee unlocked again). The return value
	 * is not committed.
	 * Committed functions get the tag SH7058SETUP_PARAMS (cleared and redone when the step runs
	 * again).
	 */
	private void commitPrototypes(Map<Function, RegInfo> info, Map<Function, String> exc)
			throws Exception {
		// unresolved flow anywhere below a function: its dataflow inputs are only a lower bound
		Set<Function> transUnknown = new HashSet<>();
		for (Map.Entry<Function, RegInfo> e : info.entrySet()) {
			if (e.getValue().unknown) {
				transUnknown.add(e.getKey());
			}
		}
		for (boolean ch = true; ch;) {
			ch = false;
			for (Map.Entry<Function, RegInfo> e : info.entrySet()) {
				if (transUnknown.contains(e.getKey())) {
					continue;
				}
				for (Function g : e.getValue().callees) {
					if (!info.containsKey(g) || transUnknown.contains(g)) {
						transUnknown.add(e.getKey());
						ch = true;
						break;
					}
				}
			}
		}
		int redo = 0;
		for (Function f : info.keySet()) {
			if (hasProtoTag(f)) {
				if (f.getSignatureSource() == SourceType.ANALYSIS) {
					f.setSignatureSource(SourceType.DEFAULT);
					redo++;
				}
				f.removeTag(PROTO_TAG);
			}
		}
		DecompInterface d = newDecompiler();
		if (d == null) {
			println(TAG + "prototype step skipped: decompiler did not start");
			return;
		}
		int committed = 0, voids = 0, unsure = 0, stackCut = 0, odd = 0, failed = 0,
				fewer = 0, more = 0, sameAsDecomp = 0, lowerBound = 0;
		List<String> reverted = new ArrayList<>();
		List<String> fewerEx = new ArrayList<>(), moreEx = new ArrayList<>();
		try {
			for (Function f : bottomUp(info)) {
				monitor.checkCancelled();
				RegInfo ri = info.get(f);
				if (f.isThunk() || f.isExternal() || exc.containsKey(f) ||
					f.getSignatureSource() != SourceType.DEFAULT) {
					continue;
				}
				boolean lower = transUnknown.contains(f);
				String cc = f.getCallingConventionName();
				boolean rt = CC_RUNTIME.equals(cc);
				int intLo = rt ? 0 : 4, intHi = rt ? 3 : 7, fltLo = rt ? 16 : 20, fltHi = rt ? 19 : 27;
				long argMask = 0;
				for (int k = intLo; k <= intHi; k++) {
					argMask |= bit(k);
				}
				for (int k = fltLo; k <= fltHi; k++) {
					argMask |= bit(k);
				}
				DecompileResults res = d.decompileFunction(f, 30, monitor);
				if (!res.decompileCompleted()) {
					// A stock decompiler (without the subflow.cc/fspec.cc fix on this branch) can die on a
					// caller of some committed prototypes. Unlock this function's committed callees until
					// it works.
					d.dispose();
					d = newDecompiler();
					for (Function g : ri.callees) {
						if (res.decompileCompleted() || !hasProtoTag(g)) {
							continue;
						}
						g.setSignatureSource(SourceType.DEFAULT);
						g.removeTag(PROTO_TAG);
						committed--;
						reverted.add(g.getName() + " (for " + f.getName() + ")");
						res = d.decompileFunction(f, 30, monitor);
						if (!res.decompileCompleted()) {
							d.dispose();
							d = newDecompiler();
						}
					}
				}
				HighFunction hf = res.getHighFunction();
				if (!res.decompileCompleted() || hf == null) {
					failed++;
					continue;
				}
				LocalSymbolMap sm = hf.getLocalSymbolMap();
				Map<Integer, HighSymbol> dReg = new TreeMap<>(); // r first, then fr
				List<HighSymbol> dStack = new ArrayList<>();
				boolean strange = false;
				for (int i = 0; i < sm.getNumParams(); i++) {
					HighSymbol p = sm.getParamSymbol(i);
					VariableStorage vs = p.getStorage();
					if (vs.isStackStorage()) {
						dStack.add(p);
						continue;
					}
					Varnode[] vns = vs.getVarnodes();
					int k = vns.length == 1 ? storageRegIndex(vns[0]) : -1;
					if (k < 0 || (argMask & bit(k)) == 0 || dReg.containsKey(k)) {
						strange = true;
						break;
					}
					dReg.put(k, p);
				}
				if (strange) {
					odd++;
					continue;
				}
				long dMask = 0;
				for (int k : dReg.keySet()) {
					dMask |= bit(k);
				}
				long sMask = ri.inputs & argMask;
				int[] ev = callSiteEvidence(f, info, argMask);
				int sites = ev[39];
				long keep = 0, evMask = 0;
				for (int k = 0; k < 39; k++) {
					if ((argMask & bit(k)) == 0) {
						continue;
					}
					boolean s = (sMask & bit(k)) != 0, dd = (dMask & bit(k)) != 0;
					boolean callers = sites > 0 && 2 * ev[k] >= sites;
					evMask |= callers ? bit(k) : 0;
					boolean ok = lower ? (s || dd) && callers : s && (sites > 0 ? callers : dd);
					if (ok) {
						keep |= bit(k);
					}
				}
				int hiInt = intLo - 1, hiFlt = fltLo - 1;
				for (int k = intLo; k <= intHi; k++) {
					hiInt = (keep & bit(k)) != 0 ? k : hiInt;
				}
				for (int k = fltLo; k <= fltHi; k++) {
					hiFlt = (keep & bit(k)) != 0 ? k : hiFlt;
				}
				long full = 0;
				for (int k = intLo; k <= hiInt; k++) {
					full |= bit(k);
				}
				for (int k = fltLo; k <= hiFlt; k++) {
					full |= bit(k);
				}
				// a register that may really be read (dataflow and decompiler agree, or either one
				// under unresolved flow) but that the callers do not set: leave the function alone
				long read = lower ? sMask | dMask | evMask : sMask & dMask;
				if ((read & ~full) != 0) {
					if (lower) {
						lowerBound++;
					}
					else {
						unsure++;
					}
					continue;
				}
				if (!dStack.isEmpty() && (dMask & ~full) != 0) {
					stackCut++;
					continue;
				}
				List<Parameter> params = new ArrayList<>();
				for (int k = 0; k < 39; k++) {
					if ((full & bit(k)) == 0) {
						continue;
					}
					HighSymbol p = dReg.get(k);
					if (p != null) {
						params.add(new ParameterImpl(null, p.getDataType(), p.getStorage(),
							currentProgram));
					}
					else {
						Register reg = currentProgram.getRegister(k < 16 ? "r" + k : "fr" + (k - 16));
						DataType dt = k < 16 ? Undefined4DataType.dataType : FloatDataType.dataType;
						params.add(new ParameterImpl(null, dt, new VariableStorage(currentProgram, reg),
							currentProgram));
					}
				}
				dStack.sort(Comparator.comparingLong(p -> p.getStorage().getStackOffset()));
				for (HighSymbol p : dStack) {
					params.add(new ParameterImpl(null, p.getDataType(), p.getStorage(),
						currentProgram));
				}
				// name the default model: a locked prototype with no model prints a warning
				String newCc = cc == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(cc) ||
					Function.DEFAULT_CALLING_CONVENTION_STRING.equals(cc)
						? currentProgram.getCompilerSpec().getDefaultCallingConvention().getName()
						: null;
				f.updateFunction(newCc, null, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				if (!VariableUtilities.storageMatches(params, f.getParameters())) {
					f.updateFunction(null, null, params, FunctionUpdateType.CUSTOM_STORAGE, true,
						SourceType.ANALYSIS);
				}
				f.addTag(PROTO_TAG);
				committed++;
				voids += params.isEmpty() ? 1 : 0;
				if (full == dMask) {
					sameAsDecomp++;
				}
				else if ((full & ~dMask) == 0) {
					fewer++;
					if (fewerEx.size() < 8) {
						fewerEx.add(f.getName() + "(" + regMaskString(dMask) + " -> " +
							regMaskString(full) + ")");
					}
				}
				else {
					more++;
					if (moreEx.size() < 8) {
						moreEx.add(f.getName() + "(" + regMaskString(dMask) + " -> " +
							regMaskString(full) + ")");
					}
				}
			}
		}
		finally {
			d.dispose();
		}
		println(TAG + "HEURISTIC prototypes: " + committed + " parameter lists committed (" +
			voids + " with no parameters); " + sameAsDecomp + " as the decompiler has them, " +
			fewer + " with fewer registers (e.g. " + fewerEx + "), " + more + " with more (e.g. " +
			moreEx + ")" + (redo > 0 ? "; " + redo + " redone" : ""));
		if (!reverted.isEmpty()) {
			println(TAG + "  unlocked again because a caller crashed the decompiler with them: " +
				reverted);
		}
		println(TAG + "  left to the decompiler's per-call guess: " + unsure + " that read a " +
			"register most callers do not set, " + lowerBound + " more of those with unresolved " +
			"flow in or below them, " + stackCut +
			" with stack parameters above a dropped register, " + odd +
			" with parameters outside the argument registers, " + failed +
			" decompile failures");
	}

	// ------------------------------------------------------------------ summary

	private void summary() {
		int funcs = fm.getFunctionCount();
		int rel = 0, withRef = 0, toRam = 0, toIo = 0, toNamed = 0;
		MemoryBlock ram = mem.getBlock("RAM");
		MemoryBlock io = mem.getBlock(addr(IO_START));
		InstructionIterator ii = listing.getInstructions(true);
		while (ii.hasNext()) {
			Instruction in = ii.next();
			if (!usesGbrRelative(in)) {
				continue;
			}
			rel++;
			for (Reference r : in.getReferencesFrom()) {
				if (r.isMemoryReference()) {
					withRef++;
					Address to = r.getToAddress();
					if (ram != null && ram.contains(to)) {
						toRam++;
					}
					else if (io != null && io.contains(to)) {
						toIo++;
					}
					Symbol s = st.getPrimarySymbol(to);
					if (s != null && s.getSource() != SourceType.DEFAULT) {
						toNamed++;
					}
					break;
				}
			}
		}
		println(TAG + "done: " + funcs + " functions; GBR-relative instructions " + rel +
			", with a memory reference " + withRef + " (RAM " + toRam + ", IO " + toIo +
			", to a named symbol " + toNamed + ")");
	}
}
