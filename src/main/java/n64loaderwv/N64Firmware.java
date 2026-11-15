package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public final class N64Firmware {
	private record StorageLabel(long address, String name) {
	}

	public static final long IPL_ADDRESS = 0xA6000000L;
	public static final long PIF_ADDRESS = 0xBFC00000L;
	public static final long MODEM_ADDRESS = 0xB8000000L;
	public static final int IPL_SIZE = 0x400000;
	public static final int PIF_SIZE = 0x7C0;
	public static final int MODEM_SIZE = 0x400000;

	private N64Firmware() {
	}

	private static String hash(byte[] data, String algorithm) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(data));
		} catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static byte[] readFile(String path, int maxSize) throws IOException {
		try (InputStream input = Files.newInputStream(Path.of(path))) {
			byte[] data = input.readNBytes(maxSize + 1);
			if (data.length > maxSize)
				throw new IOException("Firmware image too large: " + path);
			return data;
		}
	}

	private static String normalizeIpl(byte[] data) throws IOException {
		if (data.length != IPL_SIZE)
			throw new IOException("64DD IPL ROM must be 4 MiB");
		int magic = ByteBuffer.wrap(data).getInt();
		switch (magic) {
		case 0x80270740:
			return "Big-endian";
		case 0x27804007:
			for (int i = 0; i < data.length; i += 2) {
				byte tmp = data[i];
				data[i] = data[i + 1];
				data[i + 1] = tmp;
			}
			return "Byte-swapped";
		case 0x40072780:
			for (int i = 0; i < data.length; i += 4) {
				byte a = data[i];
				byte b = data[i + 1];
				data[i] = data[i + 3];
				data[i + 1] = data[i + 2];
				data[i + 2] = b;
				data[i + 3] = a;
			}
			return "Little-endian";
		default:
			throw new IOException(String.format("Invalid 64DD IPL magic: %08X", magic));
		}
	}

	private static String identifyIpl(String sha256) {
		return switch (sha256) {
		case "7d1235bea19816f5682e4208c09c47d2fc1b2639570588a86dd0c24ec064099f" -> "Japanese IPL v1.0 (Beta)";
		case "2bd70afe81e5bc9de6b90e1703369e11e1824bd0dd910fd388bf014e3ccf53aa" -> "Japanese IPL v1.1 (Beta)";
		case "806400ec0df94b0755de6c5b8249d6b6a9866124c5ddbdac198bde22499bfb8b" -> "Japanese IPL v1.2 (Retail)";
		case "e9fec87a45fba02399e88064b9e2f8cf0f2106e351c58279a87f05da5bc984ad" -> "USA IPL (Prototype)";
		case "9c2962a8b994a29e4cd04b3a6e4ed730a751414655ab6a9799ebf5fc08b79d44" -> "Japanese TOOL IPL (Development)";
		default -> "Unknown IPL variant";
		};
	}

	private static String identifyPif(byte[] data) {
		return switch (hash(data, "MD5")) {
		case "5c124e7948ada85da603a522782940d0" -> "NTSC PIF (Japan / North America)";
		case "d4232dc935cad0650ac2664d52281f3a" -> "PAL PIF (Europe)";
		default -> "Unknown PIF variant";
		};
	}

	private static FileBytes createFileBytes(Program program, String source, byte[] data, TaskMonitor monitor)
			throws IOException, CancelledException {
		try (ByteArrayInputStream input = new ByteArrayInputStream(data)) {
			return program.getMemory().createFileBytes(source, 0, data.length, input, monitor);
		}
	}

	private static MemoryBlock map(Program program, FileBytes fileBytes, String name, String description, String source,
			long address, long offset, int size, boolean executable) throws IOException {
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(name, start, fileBytes, offset, size, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(executable);
			block.setSourceName(source);
			block.setComment(description);
			return block;
		} catch (LockException | MemoryConflictException | AddressOverflowException ex) {
			throw new IOException("Could not map firmware block " + name, ex);
		}
	}

	public static void loadIpl(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (path == null || path.isBlank())
			return;
		byte[] data = readFile(path, IPL_SIZE);
		String originalHash = hash(data, "SHA-256");
		String byteOrder = normalizeIpl(data);
		String normalizedHash = hash(data, "SHA-256");
		String identity = identifyIpl(normalizedHash);
		log.appendMsg("64DD IPL: " + identity);
		log.appendMsg("Original byte order: " + byteOrder);
		log.appendMsg("Original SHA-256: " + originalHash);
		log.appendMsg("Normalized SHA-256: " + normalizedHash);
		FileBytes fileBytes = createFileBytes(program, path, data, monitor);
		map(program, fileBytes, ".iplrom", identity, path, IPL_ADDRESS, 0, data.length, false);
		log.appendMsg(String.format("Mapped IPL ROM: 0x%X bytes at %08X", data.length, IPL_ADDRESS));
	}

	public static MemoryBlock loadPif(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (path == null || path.isBlank())
			return null;
		byte[] data = readFile(path, PIF_SIZE);
		if (data.length != PIF_SIZE)
			throw new IOException("PIF ROM must be exactly 0x7C0 bytes");
		String identity = identifyPif(data);
		log.appendMsg("PIF ROM: " + identity);
		log.appendMsg("PIF SHA-256: " + hash(data, "SHA-256"));
		FileBytes fileBytes = createFileBytes(program, path, data, monitor);
		return map(program, fileBytes, ".pifrom", identity, path, PIF_ADDRESS, 0, data.length, true);
	}

	public static void loadModem(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (path == null || path.isBlank())
			return;
		byte[] data = readFile(path, MODEM_SIZE * 2);
		if (data.length != MODEM_SIZE && data.length != MODEM_SIZE * 2) {
			throw new IOException("Modem ROM must be 4 or 8 MiB");
		}
		log.appendMsg("Modem SHA-256: " + hash(data, "SHA-256"));
		FileBytes fileBytes = createFileBytes(program, path, data, monitor);
		if (data.length == MODEM_SIZE) {
			map(program, fileBytes, ".modem", "Modem ROM", path, MODEM_ADDRESS, 0, MODEM_SIZE, false);
			map(program, fileBytes, ".modem_mirror", "Assumed 4 MiB modem ROM mirror", path, MODEM_ADDRESS + MODEM_SIZE,
					0, MODEM_SIZE, false);
			log.appendMsg("Mapped 4 MiB modem ROM with assumed mirror");
		} else {
			boolean mirrored = Arrays.equals(data, 0, MODEM_SIZE, data, MODEM_SIZE, MODEM_SIZE * 2);
			String description = mirrored ? "Modem ROM with identical second half"
					: "Modem ROM with distinct second half";
			map(program, fileBytes, ".modem", description, path, MODEM_ADDRESS, 0, data.length, false);
			log.appendMsg(description);
		}
		describeModemElf(program, data, log, monitor);
	}

	private static void describeModemElf(Program program, byte[] data, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Discovering embedded modem ELF objects");
		N64ModemElf.Scan result = N64ModemElf.scan(data);
		log.appendMsg("Embedded modem ELF objects: " + result.modules().size());
		if (result.identicalMirror())
			log.appendMsg("Skipping duplicate ELF objects in ROM mirror");
		if (result.rejected() != 0)
			log.appendMsg("Rejected ELF candidates: " + result.rejected());
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var symbols = program.getSymbolTable();
		try {
			for (var discovered : result.modules()) {
				monitor.checkCancelled();
				N64ModemNativeElf.Parsed nativeElf;
				try {
					nativeElf = N64ModemNativeElf.parse(data, discovered, monitor);
				} catch (IOException ex) {
					log.appendMsg(String.format("Skipping embedded ELF at ROM offset 0x%X: %s", discovered.romOffset(),
							ex.getMessage()));
					continue;
				}
				var module = nativeElf.module();
				var entries = nativeElf.symbols();
				var relocations = nativeElf.relocations();
				long base = MODEM_ADDRESS + module.romOffset();
				String prefix = String.format("MODEM_ELF_%08X", module.romOffset());
				log.appendMsg(String.format("ELF at %08X: MIPS ET_REL, " + "extent=0x%X, sections=%d", base,
						module.extent(), module.sections().size()));
				symbols.createLabel(space.getAddress(base), prefix, SourceType.IMPORTED);
				for (var section : module.sections()) {
					if (section.index() == 0)
						continue;
					log.appendMsg(String.format("  [%02d] %-16s offset=0x%X size=0x%X%s", section.index(),
							section.name(), section.offset(), section.size(), section.type() == 8 ? " (NOBITS)" : ""));
					if (!section.hasFileBytes())
						continue;
					String name = section.name().replaceAll("[^A-Za-z0-9_]", "_");
					String label = String.format("%s_S%02d_%s", prefix, section.index(), name);
					symbols.createLabel(space.getAddress(base + section.offset()), label, SourceType.IMPORTED);
				}
				log.appendMsg(String.format("  Native Ghidra ELF parser: %d sections, %d symbols, %d relocations",
						module.sections().size(), entries.size(), relocations.size()));
				describeModemSymbols(program, data, module, entries, relocations, nativeElf, log, monitor);
			}
		} catch (InvalidInputException ex) {
			throw new IOException("Could not create modem ELF labels", ex);
		}
	}

	private static void describeModemSymbols(Program program, byte[] data, N64ModemElf.Module module,
			List<N64ModemElf.ElfSymbol> entries, List<N64ModemElf.Relocation> relocations,
			N64ModemNativeElf.Parsed nativeElf, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (entries.isEmpty())
			return;
		var symbols = program.getSymbolTable();
		var space = program.getAddressFactory().getDefaultAddressSpace();
		Namespace namespace;
		try {
			Namespace parent = symbols.getOrCreateNameSpace(program.getGlobalNamespace(), "MODEM", SourceType.IMPORTED);
			namespace = symbols.getOrCreateNameSpace(parent, String.format("ELF_%08X", module.romOffset()),
					SourceType.IMPORTED);
		} catch (DuplicateNameException | InvalidInputException ex) {
			throw new IOException("Could not create modem ELF namespace", ex);
		}
		Set<StorageLabel> created = new HashSet<>();
		int functions = 0;
		int objects = 0;
		int other = 0;
		int skipped = 0;
		long base = MODEM_ADDRESS + module.romOffset();
		for (var entry : entries) {
			monitor.checkCancelled();
			long offset = entry.storageOffset(module);
			if (offset < 0)
				continue;
			long address = base + offset;
			StorageLabel key = new StorageLabel(address, entry.name());
			if (created.contains(key))
				continue;
			try {
				symbols.createLabel(space.getAddress(address), entry.name(), namespace, SourceType.IMPORTED);
				created.add(key);
				switch (entry.type()) {
				case 2:
					functions++;
					break;
				case 1:
					objects++;
					break;
				default:
					other++;
					break;
				}
			} catch (InvalidInputException ex) {
				skipped++;
				if (skipped <= 5)
					log.appendMsg("Invalid ELF label: " + entry.name());
			}
		}
		log.appendMsg(String.format("  ELF symbol records: %d", entries.size()));
		log.appendMsg(String.format("  ROM labels: %d functions, %d objects, %d other", functions, objects, other));
		if (skipped != 0)
			log.appendMsg("  Rejected labels: " + skipped);
		try {
			log.appendMsg("  ELF relocations: " + relocations.size());
			String[] names = { "R_MIPS_32", "R_MIPS_26", "R_MIPS_HI16", "R_MIPS_LO16" };
			int[] types = { 2, 4, 5, 6 };
			for (int i = 0; i < types.length; i++) {
				int type = types[i];
				long count = relocations.stream().filter(r -> r.type() == type).count();
				log.appendMsg("    " + names[i] + ": " + count);
			}
			long unsupported = relocations.stream()
					.filter(r -> r.type() != 2 && r.type() != 4 && r.type() != 5 && r.type() != 6).count();
			if (unsupported != 0)
				log.appendMsg("    Other relocation types: " + unsupported);
			N64ModemNativeElf.applyMetadata(program, nativeElf, monitor);
			log.appendMsg("  Native Ghidra ELF metadata created");
		} catch (IOException ex) {
			log.appendMsg("  ELF metadata processing incomplete: " + ex.getMessage());
		}
		N64ModemAnalysis.createFunctions(program, data, module, entries, relocations, log, monitor);
	}
}
