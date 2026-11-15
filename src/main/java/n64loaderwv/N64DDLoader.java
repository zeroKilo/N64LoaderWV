package n64loaderwv;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class N64DDLoader extends AbstractLibrarySupportLoader {

	private static final String OPTION_RDRAM = "RDRAM dump file";
	private static final String OPTION_IPL = "IPL ROM file";
	private static final String OPTION_PIF = "PIF file";
	private static final String OPTION_MODEM = "Modem.bin file";
	private static final String OPTION_SIGNATURE = "Signature file";

	@Override
	public String getName() {
		return "N64DD Loader by Warranty Voider";
	}

	private N64DDHeader readHeader(ByteProvider provider) throws IOException {
		return N64DDMedia.readHeader(provider);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		try {
			N64DDHeader header = readHeader(provider);
			N64DDDisk disk = new N64DDDisk(header);
			N64DDDisk.BootRange boot = disk.getBootRange();
			long imageBase = boot.loadAddress & 0xE0000000L;
			return List.of(
					new LoadSpec(this, imageBase, new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true));
		} catch (IOException | IllegalArgumentException | IllegalStateException ex) {
			return List.of();
		}
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		N64DDHeader header = readHeader(provider);
		N64DDDisk disk = new N64DDDisk(header);
		N64DDDisk.BootRange boot = disk.getBootRange();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address entry = space.getAddress(boot.loadAddress);
		long ramBase = boot.loadAddress & 0xE0000000L;
		settings.log().appendMsg("64DD system header:");
		settings.log().appendMsg(header.toString());
		String rdramPath = getStringOption(settings.options(), OPTION_RDRAM);
		try {
			if (rdramPath.isEmpty()) {
				settings.monitor().setMessage("Loading 64DD boot payload");
				FileBytes fileBytes = createBootFileBytes(program, settings, header, disk, boot);
				byte[] bootBytes = new byte[boot.byteCount];
				if (fileBytes.getOriginalBytes(0, bootBytes) != bootBytes.length)
					throw new IOException("Incomplete boot payload");
				try {
					String sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bootBytes));
					settings.log().appendMsg("Boot payload SHA-256: " + sha256);
				} catch (NoSuchAlgorithmException ex) {
					throw new IllegalStateException(ex);
				}
				MemoryBlock ram = program.getMemory().createInitializedBlock(".ram", entry, fileBytes, 0,
						boot.byteCount, false);
				configureRamBlock(ram, provider.getName(), "Initial RDRAM contents loaded by the 64DD IPL");
				settings.log().appendMsg(
						String.format("Loaded 0x%X bytes from %d logical disk blocks " + "into RDRAM at 0x%08X",
								boot.byteCount, header.iplLoadBlocks, boot.loadAddress));
			} else {
				settings.monitor().setMessage("Loading RDRAM dump");
				Path path = Path.of(rdramPath);
				byte[] data = N64LoaderWVLoader.readRdramDump(path);
				long bootOffset = boot.loadAddress - ramBase;
				if (bootOffset + boot.byteCount > data.length)
					throw new IOException("IPL load range exceeds RDRAM dump size");
				FileBytes fileBytes;
				try (ByteArrayInputStream input = new ByteArrayInputStream(data)) {
					fileBytes = program.getMemory().createFileBytes(path.getFileName().toString(), 0, data.length,
							input, settings.monitor());
				}
				MemoryBlock ivt = program.getMemory().createInitializedBlock(".ivt", space.getAddress(ramBase),
						fileBytes, 0, 0x400, false);
				configureRamBlock(ivt, rdramPath, "Captured interrupt vectors and boot parameters");
				MemoryBlock ram = program.getMemory().createInitializedBlock(".ram", space.getAddress(ramBase + 0x400),
						fileBytes, 0x400, data.length - 0x400, false);
				configureRamBlock(ram, rdramPath, "Captured RDRAM contents");
				settings.log().appendMsg(String.format("Restored 0x%X bytes of RDRAM at 0x%08X", data.length, ramBase));
			}
			loadFirmware(program, settings);
			N64Hardware.addHardware(program);
			loadDiskImage(program, settings, header, disk);
			program.getSymbolTable().createLabel(entry, "entry", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entry);

		} catch (LockException | MemoryConflictException | AddressOverflowException | InvalidInputException ex) {
			throw new IOException("Failed to reconstruct 64DD RDRAM", ex);
		}
		if (N64Memory.isEnabled(settings.options(), N64Memory.OPTION_ALIASES)) {
			N64Memory.addRdramAliases(program, settings.log());
		}
		N64Symbols.apply(program, getStringOption(settings.options(), OPTION_SIGNATURE), settings.log(),
				settings.monitor());
		settings.log().appendMsg("64DD loading completed.");
	}

	private void configureRamBlock(MemoryBlock block, String source, String comment) {
		block.setRead(true);
		block.setWrite(true);
		block.setExecute(true);
		block.setSourceName(source);
		block.setComment(comment);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>(
				super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout));
		list.add(new FileOption(OPTION_RDRAM, "", Loader.COMMAND_LINE_ARG_PREFIX + "-rdram"));
		list.add(new FileOption(OPTION_IPL, "", Loader.COMMAND_LINE_ARG_PREFIX + "-ipl"));
		list.add(new FileOption(OPTION_PIF, "", Loader.COMMAND_LINE_ARG_PREFIX + "-pif"));
		list.add(new FileOption(OPTION_MODEM, "", Loader.COMMAND_LINE_ARG_PREFIX + "-modem"));
		list.add(new FileOption(OPTION_SIGNATURE, "", Loader.COMMAND_LINE_ARG_PREFIX + "-signature"));
		list.add(N64Memory.aliasOption());
		return list;
	}

	private String getStringOption(List<Option> options, String name) {
		for (Option option : options) {
			if (name.equals(option.getName())) {
				if (option.getValue() instanceof String value)
					return value.trim();
			}
		}
		return "";
	}

	private void loadFirmware(Program program, ImporterSettings settings)
			throws IOException, CancelledException, InvalidInputException {
		N64Firmware.loadIpl(program, getStringOption(settings.options(), OPTION_IPL), settings.log(),
				settings.monitor());
		MemoryBlock pif = N64Firmware.loadPif(program, getStringOption(settings.options(), OPTION_PIF), settings.log(),
				settings.monitor());
		if (pif != null) {
			program.getSymbolTable().createLabel(pif.getStart(), "pifMain", SourceType.IMPORTED);
		}
		N64Firmware.loadModem(program, getStringOption(settings.options(), OPTION_MODEM), settings.log(),
				settings.monitor());
	}

	private void loadDiskImage(Program program, ImporterSettings settings, N64DDHeader header, N64DDDisk disk)
			throws IOException, CancelledException {
		N64DDMedia.mapDisk(program, settings.provider(), header, disk, settings.log(), settings.monitor());
	}

	private FileBytes createBootFileBytes(Program program, ImporterSettings settings, N64DDHeader header,
			N64DDDisk disk, N64DDDisk.BootRange boot) throws IOException, CancelledException {
		ByteProvider provider = settings.provider();
		if (header.format != N64DDHeader.Format.MAME) {
			return MemoryBlockUtils.createFileBytes(program, provider, boot.fileOffset, boot.byteCount,
					settings.monitor());
		}
		byte[] payload = new byte[boot.byteCount];
		int position = 0;
		for (int lba = 0; lba < header.iplLoadBlocks; lba++) {
			settings.monitor().checkCancelled();
			long offset = disk.getLbaOffset(lba);
			int size = disk.getLbaSize(lba);
			byte[] block = provider.readBytes(offset, size);
			System.arraycopy(block, 0, payload, position, size);
			position += size;
		}
		if (position != payload.length)
			throw new IOException("Incomplete IPL boot payload");
		try (ByteArrayInputStream input = new ByteArrayInputStream(payload)) {
			return program.getMemory().createFileBytes(provider.getName() + ".boot", 0, payload.length, input,
					settings.monitor());
		}
	}
}