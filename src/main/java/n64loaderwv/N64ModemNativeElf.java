package n64loaderwv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemNativeElf {
	public record Metadata(long offset, DataType type) {
	}

	public record Parsed(N64ModemElf.Module module, List<N64ModemElf.ElfSymbol> symbols,
			List<N64ModemElf.Relocation> relocations, List<Metadata> metadata) {
	}

	private N64ModemNativeElf() {
	}

	private static void require(boolean valid, String message) throws IOException {
		if (!valid)
			throw new IOException(message);
	}

	private static void addMetadata(List<Metadata> metadata, long offset, long size, DataType type, int extent)
			throws IOException {
		require(type.getLength() == size && size > 0 && offset >= 0 && offset <= extent && size <= extent - offset,
				"Native ELF data type geometry mismatch at 0x" + Long.toHexString(offset));
		for (Metadata existing : metadata)
			require(offset + size <= existing.offset() || existing.offset() + existing.type().getLength() <= offset,
					"Overlapping native ELF metadata");
		metadata.add(new Metadata(offset, type));
	}

	public static Parsed parse(byte[] data, N64ModemElf.Module discovered, TaskMonitor monitor)
			throws IOException, CancelledException {
		int start = discovered.romOffset();
		int extent = discovered.extent();
		require(start >= 0 && extent >= 52 && start <= data.length && extent <= data.length - start,
				"Discovered ELF outside modem ROM");
		for (var section : discovered.sections()) {
			monitor.checkCancelled();
			long type = section.type();
			require((section.flags() & 0x800L) == 0 && (type == 0 || type == 1 || type == 2 || type == 3 || type == 8
					|| type == 9 || type == 0x70000003L || type == 0x70000005L || type == 0x70000006L),
					"Section outside qualified modem ELF profile: " + section.name());
		}
		List<String> warnings = new ArrayList<>();
		try (var provider = new ByteArrayProvider(Arrays.copyOfRange(data, start, start + extent))) {
			ElfHeader header = new ElfHeader(provider, warnings::add);
			header.parse();
			monitor.checkCancelled();
			require(warnings.isEmpty(), "Native ELF parser diagnostic: " + String.join("; ", warnings));
			require(header.is32Bit() && header.e_type() == 1 && header.e_machine() == 8,
					"Native ELF header profile mismatch");
			var nativeSections = header.getSections();
			require(nativeSections.length == discovered.sections().size(), "Native ELF section count mismatch");
			List<N64ModemElf.Section> sections = new ArrayList<>();
			List<Metadata> metadata = new ArrayList<>();
			addMetadata(metadata, 0, 52, header.toDataType(), extent);
			DataType sectionType = nativeSections[0].toDataType();
			require(sectionType.getLength() == 40, "Native ELF section record size mismatch");
			addMetadata(metadata, header.e_shoff(), 40L * nativeSections.length,
					new ArrayDataType(sectionType, nativeSections.length, 40), extent);
			for (int i = 0; i < nativeSections.length; i++) {
				monitor.checkCancelled();
				var s = nativeSections[i];
				var expected = discovered.sections().get(i);
				String name = expected.name().isEmpty() ? "" : s.getNameAsString();
				var converted = new N64ModemElf.Section(i, name, Integer.toUnsignedLong(s.getType()), s.getFlags(),
						s.getOffset(), s.getSize(), Integer.toUnsignedLong(s.getLink()),
						Integer.toUnsignedLong(s.getInfo()), s.getAddressAlignment(), s.getEntrySize());
				require(converted.equals(expected), "Native ELF section mismatch at index " + i);
				sections.add(converted);
			}
			List<N64ModemElf.ElfSymbol> symbols = new ArrayList<>();
			Map<Integer, List<N64ModemElf.ElfSymbol>> byTable = new HashMap<>();
			int symbolTables = 0;
			for (var section : sections) {
				if (section.type() != 2)
					continue;
				monitor.checkCancelled();
				require(section.link() > 0 && section.link() < sections.size()
						&& sections.get((int) section.link()).type() == 3 && section.size() % 16 == 0
						&& section.size() / 16 <= 65536 - symbols.size() && section.info() >= 1
						&& section.info() <= section.size() / 16, "Invalid ELF symbol table geometry");
				var strings = sections.get((int) section.link());
				require(strings.hasFileBytes() && data[start + (int) strings.offset()] == 0
						&& data[start + (int) (strings.offset() + strings.size() - 1)] == 0,
						"Invalid ELF symbol string table");
				var table = header.getSymbolTable(nativeSections[section.index()]);
				require(table != null && table.getTableSectionHeader() == nativeSections[section.index()]
						&& table.getEntrySize() == 16 && table.getLength() == section.size(),
						"Native ELF symbol table mismatch");
				var entries = table.getSymbols();
				require(entries.length == section.size() / 16, "Native ELF symbol count mismatch");
				List<N64ModemElf.ElfSymbol> converted = new ArrayList<>();
				for (int i = 0; i < entries.length; i++) {
					monitor.checkCancelled();
					var s = entries[i];
					require(s.getSymbolTableIndex() == i, "Native ELF symbol index mismatch");
					long nameIndex = s.getName() & 0xFFFFFFFFL;
					require(nameIndex < strings.size(), "Invalid ELF symbol string index");
					String name = nameIndex == 0 ? "" : s.getNameAsString();
					require(name != null && name.length() <= 4096 && name.length() < strings.size() - nameIndex,
							"Invalid ELF symbol name");
					int info = Byte.toUnsignedInt(s.getInfo());
					int shndx = Short.toUnsignedInt(s.getSectionHeaderIndex());
					require(shndx != 0xFFFF && (shndx >= 0xFF00 || shndx < sections.size()),
							"Invalid ELF symbol section index");
					require(i != 0 || (s.getName() == 0 && s.getValue() == 0 && s.getSize() == 0 && info == 0
							&& s.getOther() == 0 && shndx == 0), "Invalid ELF null symbol");
					converted.add(new N64ModemElf.ElfSymbol(section.index(), i, name, s.getValue(), s.getSize(),
							info >>> 4, info & 15, Byte.toUnsignedInt(s.getOther()),
							Short.toUnsignedInt(s.getSectionHeaderIndex())));
				}
				symbols.addAll(converted);
				byTable.put(section.index(), List.copyOf(converted));
				addMetadata(metadata, section.offset(), section.size(), table.toDataType(), extent);
				symbolTables++;
			}
			require(symbolTables == header.getSymbolTables().length, "Native ELF symbol table count mismatch");
			List<N64ModemElf.Relocation> relocations = new ArrayList<>();
			int relocationTables = 0;
			for (var section : sections) {
				if (section.type() != 9)
					continue;
				monitor.checkCancelled();
				int link = Math.toIntExact(section.link());
				int target = Math.toIntExact(section.info());
				require(link > 0 && link < sections.size() && target > 0 && target < sections.size()
						&& sections.get(link).type() == 2 && section.size() % 8 == 0
						&& section.size() / 8 <= 1000000 - relocations.size(), "Invalid ELF relocation table geometry");
				var table = header.getRelocationTable(nativeSections[section.index()]);
				require(table != null && table.getTableSectionHeader() == nativeSections[section.index()]
						&& table.getSectionToBeRelocated() == nativeSections[target] && !table.hasAddendRelocations()
						&& table.getAssociatedSymbolTable() == header.getSymbolTable(nativeSections[link])
						&& table.getEntrySize() == 8 && table.getLength() == section.size(),
						"Native ELF relocation table mismatch");
				var entries = table.getRelocations();
				var lookup = byTable.get(link);
				require(lookup != null && entries.length == section.size() / 8, "Native ELF relocation count mismatch");
				for (int i = 0; i < entries.length; i++) {
					monitor.checkCancelled();
					var r = entries[i];
					int symbol = r.getSymbolIndex();
					require(symbol >= 0 && symbol < lookup.size(), "Native ELF relocation symbol index mismatch");
					long offset = r.getOffset();
					long targetSize = sections.get(target).size();
					require(offset >= 0 && offset < targetSize, "Relocation outside target section");
					int type = r.getType();
					if (type == 2 || type == 4 || type == 5 || type == 6)
						require((offset & 3) == 0 && offset <= targetSize - 4, "Invalid MIPS relocation word range");
					relocations.add(new N64ModemElf.Relocation(section.index(), target, link, i, r.getOffset(),
							r.getType(), lookup.get(symbol)));
				}
				addMetadata(metadata, section.offset(), section.size(), table.toDataType(), extent);
				relocationTables++;
			}
			require(relocationTables == header.getRelocationTables().length,
					"Native ELF relocation table count mismatch");
			var module = new N64ModemElf.Module(start, extent, List.copyOf(sections));
			return new Parsed(module, List.copyOf(symbols), List.copyOf(relocations), List.copyOf(metadata));
		} catch (ElfException | DuplicateNameException | RuntimeException ex) {
			throw new IOException("Native ELF parsing failed: " + ex, ex);
		}
	}

	public static void applyMetadata(Program program, Parsed parsed, TaskMonitor monitor)
			throws IOException, CancelledException {
		var base = program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(N64Firmware.MODEM_ADDRESS + parsed.module().romOffset());
		try {
			for (var metadata : parsed.metadata()) {
				monitor.checkCancelled();
				program.getListing().createData(base.add(metadata.offset()), metadata.type());
			}
		} catch (CodeUnitInsertionException ex) {
			throw new IOException("Could not define native Ghidra ELF structures", ex);
		}
	}
}
