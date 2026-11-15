package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemNativeRelocations {
	public record Result(Map<Integer, ByteBuffer> sections, int applied, int unresolved) {
	}

	private record Site(int section, long offset) {
	}

	private N64ModemNativeRelocations() {
	}

	private static void require(boolean valid, String message) throws IOException {
		if (!valid)
			throw new IOException(message);
	}

	private static UnsupportedOperationException unsupported() {
		return new UnsupportedOperationException("Operation outside qualified modem relocation profile");
	}

	private static final class Helper implements ElfLoadHelper {
		private final Program program;
		private final ElfHeader header;
		private final Map<ElfSymbol, Address> symbols;
		private final Map<MemoryLoadable, Address> sections;
		private final MessageLog log = new MessageLog();

		Helper(Program program, ElfHeader header, Map<ElfSymbol, Address> symbols,
				Map<MemoryLoadable, Address> sections) {
			this.program = program;
			this.header = header;
			this.symbols = symbols;
			this.sections = sections;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public <T> T getOption(String optionName, T defaultValue) {
			return defaultValue;
		}

		@Override
		public ElfHeader getElfHeader() {
			return header;
		}

		@Override
		public MessageLog getLog() {
			return log;
		}

		@Override
		public void log(String msg) {
			log.appendMsg(msg);
		}

		@Override
		public void log(Throwable t) {
			log.appendException(t);
		}

		@Override
		public void markAsCode(Address address) {
			throw unsupported();
		}

		@Override
		public Function createOneByteFunction(String name, Address address, boolean isEntry) {
			throw unsupported();
		}

		@Override
		public Function createExternalFunctionLinkage(String name, Address functionAddr, Address indirectPointerAddr) {
			throw unsupported();
		}

		@Override
		public Data createUndefinedData(Address address, int length) {
			throw unsupported();
		}

		@Override
		public Data createData(Address address, DataType dt) {
			throw unsupported();
		}

		@Override
		public void setElfSymbolAddress(ElfSymbol elfSymbol, Address address) {
			throw unsupported();
		}

		@Override
		public Address getElfSymbolAddress(ElfSymbol elfSymbol) {
			return symbols.get(elfSymbol);
		}

		@Override
		public Symbol createSymbol(Address addr, String name, boolean isPrimary, boolean pinAbsolute,
				Namespace namespace) {
			throw unsupported();
		}

		@Override
		public Address findLoadAddress(MemoryLoadable section, long byteOffsetWithinSection) {
			Address base = sections.get(section);
			return base == null ? null : base.add(byteOffsetWithinSection);
		}

		@Override
		public Address getDefaultAddress(long addressableWordOffset) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(addressableWordOffset & 0xFFFFFFFFL);
		}

		@Override
		public long getImageBaseWordAdjustmentOffset() {
			return 0;
		}

		@Override
		public Long getGOTValue() {
			return null;
		}

		@Override
		public AddressRange allocateLinkageBlock(int alignment, int size, String purpose) {
			throw unsupported();
		}

		@Override
		public long getOriginalValue(Address addr, boolean signExtend) {
			throw unsupported();
		}

		@Override
		public boolean addArtificialRelocTableEntry(Address address, int length) {
			throw unsupported();
		}
	}

	private static boolean mapped(N64ModemElf.Module module, N64ModemElf.ElfSymbol symbol,
			N64ModemLayout.Layout layout) {
		if (symbol.sectionIndex() == 0xFFF2)
			return layout.common().containsKey(symbol);
		return symbol.sectionIndex() > 0 && symbol.sectionIndex() < module.sections().size()
				&& layout.sections().containsKey(symbol.sectionIndex())
				&& symbol.value() <= module.sections().get(symbol.sectionIndex()).size();
	}

	private static int originalWord(byte[] rom, N64ModemElf.Module module, N64ModemElf.Relocation r)
			throws IOException {
		var section = module.sections().get(r.targetSectionIndex());
		long offset = module.romOffset() + section.offset() + r.offset();
		require(section.hasFileBytes() && r.offset() >= 0 && (r.offset() & 3) == 0 && r.offset() <= section.size() - 4
				&& offset >= 0 && offset <= rom.length - 4, "Invalid relocation word range");
		return ByteBuffer.wrap(rom).getInt((int) offset);
	}

	private static Set<Site> select(byte[] rom, N64ModemElf.Module module, List<N64ModemElf.Relocation> relocations,
			N64ModemLayout.Layout layout, TaskMonitor monitor) throws IOException, CancelledException {
		Set<Site> all = new HashSet<>();
		Set<Site> selected = new HashSet<>();
		for (var r : relocations) {
			monitor.checkCancelled();
			var block = layout.sections().get(r.targetSectionIndex());
			require(block != null && block.isInitialized() && all.add(new Site(r.targetSectionIndex(), r.offset())),
					"Unmapped or duplicate relocation site");
			require(r.type() == 2 || r.type() == 4 || r.type() == 5 || r.type() == 6,
					"Unsupported MIPS relocation type: " + r.type());
		}
		for (int i = 0; i < relocations.size(); i++) {
			monitor.checkCancelled();
			var r = relocations.get(i);
			boolean eligible = mapped(module, r.symbol(), layout);
			int word = originalWord(rom, module, r);
			switch (r.type()) {
			case 2:
				break;
			case 4:
				require((word >>> 26) == 2 || (word >>> 26) == 3, "R_MIPS_26 does not target J/JAL");
				if (eligible) {
					var symbol = r.symbol();
					long address = symbol.sectionIndex() == 0xFFF2 ? layout.common().get(symbol).getOffset()
							: layout.sections().get(symbol.sectionIndex()).getStart().getOffset() + symbol.value();
					int addend = (word & 0x03FFFFFF) << 2;
					if (symbol.binding() != 0 && symbol.type() != 3)
						addend = (addend << 4) >> 4;
					long destination = (address + addend) & 0xFFFFFFFFL;
					long pc = layout.sections().get(r.targetSectionIndex()).getStart().getOffset() + r.offset();
					require((destination & 3) == 0 && ((pc + 4) & 0xF0000000L) == (destination & 0xF0000000L),
							"MIPS jump target outside encodable region");
				}
				break;
			case 5:
				require(i + 1 < relocations.size(), "Unpaired HI16 relocation");
				var lo = relocations.get(++i);
				require(lo.type() == 6 && lo.sectionIndex() == r.sectionIndex()
						&& lo.targetSectionIndex() == r.targetSectionIndex() && lo.symbol().equals(r.symbol()),
						"Unsupported HI16/LO16 pairing");
				require((word >>> 26) == 15 && (originalWord(rom, module, lo) >>> 26) != 13,
						"Unsupported HI16/LO16 instruction pair");
				if (eligible)
					selected.add(new Site(lo.targetSectionIndex(), lo.offset()));
				break;
			default:
				throw new IOException("Unexpected standalone LO16 relocation");
			}
			if (eligible) {
				require(!r.symbol().name().equals("_gp_disp") && !r.symbol().name().equals("__gnu_local_gp"),
						"GP-dependent relocation excluded");
				selected.add(new Site(r.targetSectionIndex(), r.offset()));
			}
		}
		return selected;
	}

	public static Result apply(Program program, byte[] rom, N64ModemElf.Module module,
			List<N64ModemElf.Relocation> relocations, N64ModemLayout.Layout layout, TaskMonitor monitor)
			throws IOException, CancelledException {
		Set<Site> pending = select(rom, module, relocations, layout, monitor);
		int expectedApplied = pending.size();
		int expectedSkipped = relocations.size() - expectedApplied;
		Object consumer = new Object();
		ProgramDB scratch = null;
		monitor.setMessage("Applying Ghidra native MIPS relocations");
		try (var provider = new ByteArrayProvider(
				Arrays.copyOfRange(rom, module.romOffset(), module.romOffset() + module.extent()))) {
			MessageLog parserLog = new MessageLog();
			ElfHeader header = new ElfHeader(provider, parserLog::appendMsg);
			header.parse();
			require(!parserLog.hasMessages(), "Native relocation parser diagnostic: " + parserLog);
			require(header.is32Bit() && header.e_type() == 1 && header.e_machine() == 8,
					"Unexpected native ELF profile");
			var nativeSections = header.getSections();
			require(nativeSections.length == module.sections().size(), "Native section count mismatch");
			monitor.checkCancelled();
			var language = program.getLanguage();
			var compiler = language.getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID());
			scratch = new ProgramDB("Modem native relocation", language, compiler, consumer);
			int transaction = scratch.startTransaction("Native ELF relocation");
			try {
				var space = scratch.getAddressFactory().getDefaultAddressSpace();
				var memory = scratch.getMemory();
				Map<MemoryLoadable, Address> sectionAddresses = new IdentityHashMap<>();
				Map<ElfSymbol, Address> symbolAddresses = new IdentityHashMap<>();
				Map<Integer, byte[]> originals = new LinkedHashMap<>();
				for (var section : module.sections()) {
					monitor.checkCancelled();
					MemoryBlock real = layout.sections().get(section.index());
					if (real == null)
						continue;
					Address start = space.getAddress(real.getStart().getOffset() & 0xFFFFFFFFL);
					sectionAddresses.put(nativeSections[section.index()], start);
					if (!real.isInitialized())
						continue;
					byte[] original = new byte[Math.toIntExact(real.getSize())];
					require(program.getMemory().getBytes(real.getStart(), original) == original.length,
							"Incomplete source section");
					int rawStart = Math.toIntExact(module.romOffset() + section.offset());
					require(section.hasFileBytes() && section.size() == original.length && rawStart >= 0
							&& rawStart <= rom.length - original.length
							&& Arrays.equals(original, 0, original.length, rom, rawStart, rawStart + original.length),
							"Analysis section no longer matches original ELF bytes");
					originals.put(section.index(), original);
					try (var stream = new ByteArrayInputStream(original)) {
						MemoryBlock block = memory.createInitializedBlock("S" + section.index(), start, stream,
								original.length, monitor, false);
						block.setWrite(true);
					}
				}
				require(!originals.isEmpty(), "No initialized modem sections");
				scratch.getSymbolTable().createLabel(space.getAddress(0x1000), "_mips_gp_value", SourceType.IMPORTED);
				Helper helper = new Helper(scratch, header, symbolAddresses, sectionAddresses);
				int processed = 0;
				int seen = 0;
				int skipped = 0;
				for (var section : module.sections()) {
					if (section.type() != 9)
						continue;
					monitor.checkCancelled();
					var table = header.getRelocationTable(nativeSections[section.index()]);
					require(table != null && !table.hasAddendRelocations(), "Native REL table missing");
					int target = Math.toIntExact(section.info());
					int link = Math.toIntExact(section.link());
					require(table.getSectionToBeRelocated() == nativeSections[target]
							&& table.getAssociatedSymbolTable() == header.getSymbolTable(nativeSections[link]),
							"Native REL table linkage mismatch");
					var nativeSymbols = table.getAssociatedSymbolTable().getSymbols();
					var records = table.getRelocations();
					require(records.length == section.size() / 8, "Native REL table count mismatch");
					Address base = sectionAddresses.get(nativeSections[target]);
					require(base != null && originals.containsKey(target), "Unmapped native relocation section");
					for (int i = 0; i < records.length; i++) {
						var record = records[i];
						require(seen < relocations.size(), "Excess native relocation records");
						var r = relocations.get(seen++);
						require(r.sectionIndex() == section.index() && r.targetSectionIndex() == target
								&& r.symbolTableIndex() == link && r.index() == i && r.offset() == record.getOffset()
								&& r.type() == record.getType() && r.symbol().index() == record.getSymbolIndex(),
								"Native relocation identity mismatch");
						if (!pending.contains(new Site(target, r.offset())))
							continue;
						var symbol = r.symbol();
						require(!symbol.name().equals("_gp_disp") && !symbol.name().equals("__gnu_local_gp"),
								"GP-dependent relocation excluded");
						require(r.type() == 2 || r.type() == 4 || r.type() == 5 || r.type() == 6,
								"Native relocation type excluded");
						Address address;
						if (symbol.sectionIndex() == 0xFFF2) {
							Address common = layout.common().get(symbol);
							require(common != null, "Missing common symbol placement");
							address = space.getAddress(common.getOffset() & 0xFFFFFFFFL);
						} else {
							require(symbol.sectionIndex() > 0 && symbol.sectionIndex() < nativeSections.length,
									"Unsupported native symbol section");
							Address sectionBase = sectionAddresses.get(nativeSections[symbol.sectionIndex()]);
							require(sectionBase != null, "Missing native symbol section");
							address = sectionBase.add(symbol.value());
						}
						ElfSymbol nativeSymbol = nativeSymbols[record.getSymbolIndex()];
						Address previous = symbolAddresses.put(nativeSymbol, address);
						require(previous == null || previous.equals(address), "Conflicting native symbol placement");
					}
					ElfRelocationContext<?> context = ElfRelocationContext.getRelocationContext(helper,
							symbolAddresses);
					require(context.hasRelocationHandler(), "Native MIPS relocation handler unavailable");
					try {
						context.startRelocationTableProcessing(table);
						try {
							for (var record : records) {
								monitor.checkCancelled();
								if (!pending.remove(new Site(target, record.getOffset()))) {
									skipped++;
									continue;
								}
								var result = context.processRelocation(record, base.add(record.getOffset()));
								require(result.status() == Status.APPLIED
										|| (record.getType() == 5 && result.status() == Status.PARTIAL),
										"Native relocation failed at " + base.add(record.getOffset()) + ": "
												+ result.status());
								processed++;
							}
						} finally {
							context.endRelocationTableProcessing();
						}
					} finally {
						context.dispose();
					}
				}
				require(pending.isEmpty() && seen == relocations.size() && processed == expectedApplied
						&& skipped == expectedSkipped, "Native relocation coverage mismatch");
				require(!helper.getLog().hasMessages(), "Native relocation diagnostic: " + helper.getLog());
				Map<Integer, ByteBuffer> accepted = new LinkedHashMap<>();
				for (var entry : originals.entrySet()) {
					monitor.checkCancelled();
					int index = entry.getKey();
					byte[] actual = new byte[entry.getValue().length];
					Address address = sectionAddresses.get(nativeSections[index]);
					require(memory.getBytes(address, actual) == actual.length, "Incomplete native output");
					if (!Arrays.equals(actual, entry.getValue()))
						accepted.put(index, ByteBuffer.wrap(actual));
				}
				monitor.checkCancelled();
				return new Result(Collections.unmodifiableMap(accepted), processed, skipped);
			} finally {
				scratch.endTransaction(transaction, false);
			}
		} catch (CancelledException ex) {
			throw ex;
		} catch (Exception ex) {
			throw new IOException("Native relocation failed: " + ex.getMessage(), ex);
		} finally {
			if (scratch != null)
				scratch.release(consumer);
		}
	}
}
