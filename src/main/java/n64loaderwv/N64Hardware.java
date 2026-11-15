package n64loaderwv;

import java.io.IOException;

import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public final class N64Hardware {

	private N64Hardware() {
	}

	public static void addHardware(Program program) throws LockException, MemoryConflictException,
			AddressOverflowException, InvalidInputException, IOException {
		addHardware(program, false);
	}

	public static void addHardware(Program program, boolean cartridgeBootMapped) throws LockException,
			MemoryConflictException, AddressOverflowException, InvalidInputException, IOException {
		addRegisters(program, ".rdreg", "RDRAM Registers", 0xA3F00000L, "RDRAM_CONFIG", "RDRAM_DEVICE_ID",
				"RDRAM_DELAY", "RDRAM_MODE", "RDRAM_REF_INTERVAL", "RDRAM_REF_ROW", "RDRAM_RAS_INTERVAL",
				"RDRAM_MIN_INTERVAL", "RDRAM_ADDR_SELECT", "RDRAM_DEVICE_MANUF");
		addRegisters(program, ".spreg", "Signal Processor Registers", 0xA4040000L, "SP_MEM_ADDR", "SP_DRAM_ADDR",
				"SP_RD_LEN", "SP_WR_LEN", "SP_STATUS", "SP_DMA_FULL", "SP_DMA_BUSY", "SP_SEMAPHORE");
		addRegisters(program, ".spcreg", "Signal Processor PC / BIST", 0xA4080000L, "SP_PC", "SP_IBIST");
		addRegisters(program, ".dpcreg", "DP Command Registers", 0xA4100000L, "DPC_START", "DPC_END", "DPC_CURRENT",
				"DPC_STATUS", "DPC_CLOCK", "DPC_BUFBUSY", "DPC_PIPEBUSY", "DPC_TMEM");
		addRegisters(program, ".dpsreg", "DP Span Registers", 0xA4200000L, "DPS_TBIST", "DPS_TEST_MODE",
				"DPS_BUFTEST_ADDR", "DPS_BUFTEST_DATA");
		addRegisters(program, ".mireg", "MIPS Interface Registers", 0xA4300000L, "MI_INIT_MODE", "MI_VERSION",
				"MI_INTR", "MI_INTR_MASK");
		addRegisters(program, ".vireg", "Video Interface Registers", 0xA4400000L, "VI_STATUS", "VI_ORIGIN", "VI_WIDTH",
				"VI_INTR", "VI_CURRENT", "VI_BURST", "VI_V_SYNC", "VI_H_SYNC", "VI_LEAP", "VI_H_START", "VI_V_START",
				"VI_V_BURST", "VI_X_SCALE", "VI_Y_SCALE");
		addRegisters(program, ".aireg", "Audio Interface Registers", 0xA4500000L, "AI_DRAM_ADDR", "AI_LEN",
				"AI_CONTROL", "AI_STATUS", "AI_DACRATE", "AI_BITRATE");
		addRegisters(program, ".pireg", "Peripheral Interface Registers", 0xA4600000L, "PI_DRAM_ADDR", "PI_CART_ADDR",
				"PI_RD_LEN", "PI_WR_LEN", "PI_STATUS", "PI_BSD_DOM1_LAT", "PI_BSD_DOM1_PWD", "PI_BSD_DOM1_PGS",
				"PI_BSD_DOM1_RLS", "PI_BSD_DOM2_LAT", "PI_BSD_DOM2_PWD", "PI_BSD_DOM2_PGS", "PI_BSD_DOM2_RLS");
		addRegisters(program, ".rireg", "RDRAM Interface Registers", 0xA4700000L, "RI_MODE", "RI_CONFIG",
				"RI_CURRENT_LOAD", "RI_SELECT", "RI_REFRESH", "RI_LATENCY", "RI_RERROR", "RI_WERROR");
		addRegisters(program, ".sireg", "Serial Interface Registers", 0xA4800000L, "SI_DRAM_ADDR",
				"SI_PIF_ADDR_RD64B_REG", null, null, "SI_PIF_ADDR_WR64B_REG", null, "SI_STATUS");
		addRegisters(program, ".ddreg", "64DD ASIC Registers", 0xA5000500L, "ASIC_DATA", "ASIC_MISC_REG", "ASIC_STATUS",
				"ASIC_CUR_TK", "ASIC_BM_STATUS", "ASIC_ERR_SECTOR", "ASIC_SEQ_STATUS", "ASIC_CUR_SECTOR",
				"ASIC_HARD_RESET", "ASIC_C1_S0", "ASIC_HOST_SECBYTE", "ASIC_C1_S2", "ASIC_SEC_BYTE", "ASIC_C1_S4",
				"ASIC_C1_S6", "ASIC_CUR_ADDR", "ASIC_ID_REG", "ASIC_TEST_REG", "ASIC_TEST_PIN_SEL");
		addLabel(program, 0xA5000508L, "ASIC_CMD");
		addLabel(program, 0xA5000510L, "ASIC_BM_CTL");
		addLabel(program, 0xA5000518L, "ASIC_SEQ_CTL");
		if (!cartridgeBootMapped) {
			addMemory(program, ".sp_dmem", "RSP Data Memory", 0xA4000000L, 0x1000, false);
		}
		addMemory(program, ".sp_imem", "RSP Instruction Memory", 0xA4001000L, 0x1000, false);
		addMemory(program, ".pifram", "PIF RAM", 0xBFC007C0L, 0x40, true);
		addBootLabels(program);
	}

	private static void addRegisters(Program program, String name, String description, long base, String... registers)
			throws LockException, MemoryConflictException, AddressOverflowException, InvalidInputException,
			IOException {
		addMemory(program, name, description, base, registers.length * 4L, true);
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		for (int i = 0; i < registers.length; i++) {
			if (registers[i] == null)
				continue;
			long offset = base + i * 4L;
			Address addr = space.getAddress(offset);
			addLabel(program, offset, registers[i]);
			try {
				program.getListing().createData(addr, DWordDataType.dataType);
			} catch (CodeUnitInsertionException ex) {
				throw new IOException("Could not define hardware register " + registers[i], ex);
			}
		}
	}

	private static void addMemory(Program program, String name, String description, long base, long size,
			boolean isVolatile) throws LockException, MemoryConflictException, AddressOverflowException {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		MemoryBlock block = program.getMemory().createUninitializedBlock(name, space.getAddress(base), size, false);
		block.setRead(true);
		block.setWrite(true);
		block.setExecute(false);
		block.setVolatile(isVolatile);
		block.setComment(description);
	}

	private static void addLabel(Program program, long address, String name) throws InvalidInputException {
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		if (program.getMemory().contains(addr)) {
			program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		}
	}

	public static void addBootLabels(Program program) throws InvalidInputException {
		addLabel(program, 0x80000000L, "TLB_REFILL");
		addLabel(program, 0x80000080L, "XTLB_REFILL");
		addLabel(program, 0x80000100L, "CACHE_ERROR");
		addLabel(program, 0x80000180L, "GEN_EXCEPTION");
		addLabel(program, 0x80000300L, "NTSC_PAL");
		addLabel(program, 0x80000304L, "CART_DD");
		addLabel(program, 0x80000308L, "ROM_BASE");
		addLabel(program, 0x8000030CL, "RESET");
		addLabel(program, 0x80000310L, "CIC_ID");
		addLabel(program, 0x80000314L, "VERSION");
		addLabel(program, 0x80000318L, "RDRAM_SIZE");
		addLabel(program, 0x8000031CL, "NMI_BUFFER");
	}
}