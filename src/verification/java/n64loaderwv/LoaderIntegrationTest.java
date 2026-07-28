package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public final class LoaderIntegrationTest {
	public static void main(String[] args) throws Exception {
		initializeGhidra();
		N64LoaderWVLoader loader = new N64LoaderWVLoader();
		try (LoadedProgram base = load(loader, N64LoaderWVLoader.BASE_RDRAM_SIZE);
				LoadedProgram expanded = load(loader, N64LoaderWVLoader.EXPANDED_RDRAM_SIZE)) {
			assertDumpMapping(base.program, N64LoaderWVLoader.BASE_RDRAM_SIZE);
			assertDumpMapping(expanded.program, N64LoaderWVLoader.EXPANDED_RDRAM_SIZE);
			assertProgramAddressIsolation(loader, base.program, expanded.program);
		}
		checksOverlayResolution(loader);
	}

	private static void initializeGhidra() throws Exception {
		if (!Application.isInitialized()) {
			File installDir = new File(System.getProperty("ghidra.install.dir"));
			Application.initializeApplication(new GhidraApplicationLayout(installDir),
					new HeadlessGhidraApplicationConfiguration());
		}
	}

	private static LoadedProgram load(N64LoaderWVLoader loader, int dumpSize) throws Exception {
		byte[] rom = new byte[0x2000];
		rom[0] = (byte) 0x80;
		rom[1] = 0x37;
		rom[2] = 0x12;
		rom[3] = 0x40;
		rom[8] = (byte) 0x80;
		rom[9] = 0x20;

		byte[] dump = new byte[dumpSize];
		dump[0] = 0x11;
		dump[0x3ff] = 0x22;
		dump[0x400] = 0x33;
		dump[dump.length - 1] = 0x44;
		Path dumpPath = Files.createTempFile("n64loaderwv-rdram-", ".bin");
		Files.write(dumpPath, dump);

		ByteArrayProvider provider = new ByteArrayProvider(rom);
		Object consumer = new Object();
		ProgramDB program = null;
		boolean success = false;
		try {
			Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
			LoadSpec spec = specs.iterator().next();
			LanguageCompilerSpecPair pair = spec.getLanguageCompilerSpec();
			program = new ProgramDB("rdram-" + dumpSize, pair.getLanguage(), pair.getCompilerSpec(), consumer);
			List<Option> options = loader.getDefaultOptions(provider, spec, program, true, false);
			options.stream().filter(option -> option.getName().equals("RDRAM dump file")).findFirst().orElseThrow()
					.setValue(dumpPath.toString());
			Loader.ImporterSettings settings = new Loader.ImporterSettings(provider, "synthetic.z64", null, "/", false,
					spec, options, consumer, new MessageLog(), TaskMonitor.DUMMY);
			loader.loadInto(program, settings);
			success = true;
			return new LoadedProgram(program, consumer);
		}
		finally {
			provider.close();
			Files.deleteIfExists(dumpPath);
			if (!success && program != null)
				program.release(consumer);
		}
	}

	private static void assertDumpMapping(ProgramDB program, int dumpSize) throws Exception {
		MemoryBlock ivt = requireBlock(program, ".ivt");
		MemoryBlock ram = requireBlock(program, ".ram");
		assertBlock(ivt, 0x80000000L, N64LoaderWVLoader.INTERRUPT_VECTOR_SIZE);
		assertBlock(ram, 0x80000400L, dumpSize - N64LoaderWVLoader.INTERRUPT_VECTOR_SIZE);
		assertByte(program, ivt.getStart(), 0x11);
		assertByte(program, ivt.getEnd(), 0x22);
		assertByte(program, ram.getStart(), 0x33);
		assertByte(program, ram.getEnd(), 0x44);
	}

	private static void assertProgramAddressIsolation(N64LoaderWVLoader loader, ProgramDB base, ProgramDB expanded) {
		long expandedEnd = 0x807fffffL;
		if (loader.MakeAddress(expanded, expandedEnd) == null)
			throw new AssertionError("expanded Program lost its final RDRAM address");
		if (loader.MakeAddress(base, expandedEnd) != null)
			throw new AssertionError("base Program resolved an address from another import");
	}

	private static void checksOverlayResolution(N64LoaderWVLoader loader) throws Exception {
		byte[] rom = { (byte) 0x80, 0x37, 0x12, 0x40 };
		try (ByteArrayProvider provider = new ByteArrayProvider(rom)) {
			LoadSpec spec = loader.findSupportedLoadSpecs(provider).iterator().next();
			LanguageCompilerSpecPair pair = spec.getLanguageCompilerSpec();
			Object consumer = new Object();
			ProgramDB program = new ProgramDB("overlay-resolution", pair.getLanguage(), pair.getCompilerSpec(), consumer);
			int transaction = program.startTransaction("create conflicting blocks");
			boolean commit = false;
			try {
				N64LoaderWVLoader.ImportContext first = new N64LoaderWVLoader.ImportContext(program);
				loader.MakeBlock(first, program, ".first", "first", 0x80000000L,
						new ByteArrayInputStream(new byte[4]), 4, "111", null, new MessageLog(), TaskMonitor.DUMMY);
				N64LoaderWVLoader.ImportContext second = new N64LoaderWVLoader.ImportContext(program);
				loader.MakeBlock(second, program, ".second", "second", 0x80000000L,
						new ByteArrayInputStream(new byte[4]), 4, "111", null, new MessageLog(), TaskMonitor.DUMMY);
				Address resolved = loader.MakeAddress(second, 0x80000000L);
				if (resolved == null || !resolved.getAddressSpace().isOverlaySpace())
					throw new AssertionError("import context did not preserve overlay address-space identity");
				if (resolved.equals(loader.MakeAddress(first, 0x80000000L)))
					throw new AssertionError("separate import contexts resolved the same conflicting block");
				commit = true;
			}
			finally {
				program.endTransaction(transaction, commit);
				program.release(consumer);
			}
		}
	}

	private static MemoryBlock requireBlock(ProgramDB program, String name) {
		MemoryBlock block = program.getMemory().getBlock(name);
		if (block == null)
			throw new AssertionError("missing block " + name);
		return block;
	}

	private static void assertBlock(MemoryBlock block, long start, long size) {
		if (block.getStart().getOffset() != start || block.getSize() != size ||
				block.getEnd().getOffset() != start + size - 1)
			throw new AssertionError("unexpected mapping for " + block.getName());
	}

	private static void assertByte(ProgramDB program, Address address, int expected) throws Exception {
		int actual = Byte.toUnsignedInt(program.getMemory().getByte(address));
		if (actual != expected)
			throw new AssertionError(String.format("expected %02x at %s, got %02x", expected, address, actual));
	}

	private static final class LoadedProgram implements AutoCloseable {
		private final ProgramDB program;
		private final Object consumer;

		LoadedProgram(ProgramDB program, Object consumer) {
			this.program = program;
			this.consumer = consumer;
		}

		@Override
		public void close() {
			program.release(consumer);
		}
	}
}
