package n64loaderwv;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.Path;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class N64DDMedia {

	public static final String OPTION_IPL = "IPL ROM file";
	public static final String OPTION_DISK = "64DD expansion disk file";

	private N64DDMedia() {
	}

	public static N64DDHeader readHeader(ByteProvider provider) throws IOException {
		long size = provider.length();
		if (size <= N64DDHeader.D64_DATA_OFFSET || size > N64DDHeader.MAME_IMAGE_SIZE)
			throw new IOException("Unsupported disk image size");
		return N64DDHeader.parse(provider.readBytes(0, Math.min(size, N64DDHeader.PREFIX_SIZE)), size);
	}

	public static void loadExpansionDisk(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (path == null || path.isBlank())
			return;
		try (ByteProvider provider = new FileByteProvider(Path.of(path).toFile(), null, AccessMode.READ)) {
			N64DDHeader header = readHeader(provider);
			N64DDDisk disk = new N64DDDisk(header);
			log.appendMsg("Attached 64DD expansion disk:");
			log.appendMsg(header.toString());
			mapDisk(program, provider, header, disk, log, monitor);
			log.appendMsg("Cartridge boot priority preserved; " + "disk payload not copied to RDRAM");
		} catch (IllegalArgumentException | IllegalStateException ex) {
			throw new IOException("Invalid 64DD expansion disk", ex);
		}
	}

	public static void mapDisk(Program program, ByteProvider provider, N64DDHeader header, N64DDDisk disk,
			MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		String format = header.format.name();
		monitor.setMessage("Mapping complete " + format + " image");
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(format, start, fileBytes, 0,
					provider.length(), true);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName(provider.getName());
			block.setComment(header.format == N64DDHeader.Format.MAME ? "Complete 64DD image in physical track order"
					: "Complete 64DD " + format + " image");
			Address diskStart = block.getStart();
			N64DDTypes.apply(program, diskStart, header);
			label(program, diskStart, format + "_SYSTEM_AREA");
			label(program, diskStart.add(header.headerOffset), format + "_SYSTEM_HEADER");
			label(program, diskStart.add(disk.getLbaOffset(0)),
					header.format == N64DDHeader.Format.MAME ? "MAME_USER_LBA_0" : format + "_USER_AREA");
			if (header.format == N64DDHeader.Format.D64) {
				label(program, diskStart.add(0x100), "D64_DISK_ID");
				if (header.ramStartLba != 0xFFFF) {
					label(program, diskStart.add(disk.getLbaOffset(header.ramStartLba)), "D64_RAM_AREA");
				}
			}
			log.appendMsg(String.format("Mapped complete %s image: 0x%X bytes", format, provider.length()));
		} catch (LockException | MemoryConflictException | AddressOverflowException | InvalidInputException ex) {
			throw new IOException("Could not map 64DD image", ex);
		}
	}

	public static void loadIpl(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		N64Firmware.loadIpl(program, path, log, monitor);
	}

	private static void label(Program program, Address address, String name) throws InvalidInputException {
		program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
	}
}