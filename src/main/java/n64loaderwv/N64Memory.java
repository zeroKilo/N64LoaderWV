package n64loaderwv;

import java.io.IOException;
import java.util.List;
import java.util.zip.CRC32;
import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;

public final class N64Memory {

	public static final String OPTION_ALIASES = "Map RDRAM aliases";
	public static final long KSEG0 = 0x80000000L;
	public static final long KSEG1 = 0xA0000000L;
	public static final long MAX_RDRAM = 0x800000L;

	private N64Memory() {
	}

	public static Option aliasOption() {
		return Option.newBoolean(OPTION_ALIASES).value(false)
				.commandLineArgument(Loader.COMMAND_LINE_ARG_PREFIX + "-aliases").build();
	}

	public static boolean isEnabled(List<Option> options, String name) {
		for (Option option : options) {
			if (name.equals(option.getName()))
				return Boolean.TRUE.equals(option.getValue());
		}
		return false;
	}

	public static void addRdramAliases(Program program, MessageLog log) throws IOException {
		addAlias(program, ".ivt", log);
		addAlias(program, ".ram", log);
	}

	private static void addAlias(Program program, String name, MessageLog log) throws IOException {
		MemoryBlock source = program.getMemory().getBlock(name);
		if (source == null || !source.isInitialized())
			return;
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		if (!source.getStart().getAddressSpace().equals(space))
			return;
		long start = source.getStart().getOffset();
		long segment = start & 0xE0000000L;
		long physical = start & 0x1FFFFFFFL;
		if (segment != KSEG0 && segment != KSEG1)
			return;
		if (physical >= MAX_RDRAM || source.getSize() > MAX_RDRAM - physical) {
			log.appendMsg("Skipping RDRAM alias for " + name + ": outside physical RAM limits");
			return;
		}
		long aliasBase = segment == KSEG0 ? KSEG1 : KSEG0;
		Address target = space.getAddress(aliasBase + physical);
		try {
			MemoryBlock alias = program.getMemory().createByteMappedBlock(name + "_alias", target, source.getStart(),
					source.getSize(), false);
			alias.setRead(source.isRead());
			alias.setWrite(source.isWrite());
			// Avoid automatic duplicate function discovery.
			alias.setExecute(false);
			alias.setComment("RDRAM alias of " + source.getName());
			log.appendMsg(String.format("Mapped RDRAM alias %s at 0x%08X", name, target.getOffset()));
		} catch (LockException | MemoryConflictException | AddressOverflowException ex) {
			throw new IOException("Could not create RDRAM alias for " + name, ex);
		}
	}

	public record BootRange(long loadAddress, int byteCount, long ipl3CRC) {
	}

	public static BootRange getCartridgeBootRange(byte[] rom, long loadAddress) throws IOException {
		if (rom.length < 0x1000)
			throw new IOException("Incomplete cartridge header");
		CRC32 crc = new CRC32();
		crc.update(rom, 0x40, 0xFC0);
		long checksum = crc.getValue();
		int byteCount = 0x100000;
		switch ((int) checksum) {
		case 0x6170A4A1: // 6101
		case 0x90BB6CB5: // 6102 / 7101
		case 0x98BC2C86: // 6105 / 7105
			break;
		case 0x009E9EA3: // 7102
			loadAddress = 0x80000480L;
			break;
		case 0x0B050EE0: // 6103 / 7103
		case 0xACC8580A: // 6106 / 7106
			byteCount += 4;
			break;
		default:
			throw new IOException(
					String.format("Unsupported IPL3 CRC32: %08X. " + "Please provide an RDRAM dump.", checksum));
		}
		long segment = loadAddress & 0xE0000000L;
		long physical = loadAddress & 0x1FFFFFFFL;
		if (segment != KSEG0 && segment != KSEG1)
			throw new IOException("Invalid IPL3 load address");
		if (physical < 0x400 || physical >= MAX_RDRAM || byteCount > MAX_RDRAM - physical || (loadAddress & 3) != 0)
			throw new IOException("Invalid IPL3 load range");
		if (rom.length - 0x1000 < byteCount)
			throw new IOException("Incomplete IPL3 boot payload");
		return new BootRange(loadAddress, byteCount, checksum);
	}
}