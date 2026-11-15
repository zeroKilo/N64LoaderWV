package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemLayout {

	private static final long MAX_SPAN = 0x400000L;
	private static final int SHN_COMMON = 0xFFF2;
	private static final int SHT_PROGBITS = 1;
	private static final int SHT_NOBITS = 8;
	private static final int SHF_WRITE = 1;
	private static final int SHF_ALLOC = 2;
	private static final int SHF_EXECINSTR = 4;

	public record Layout(Map<Integer, MemoryBlock> sections, Map<N64ModemElf.ElfSymbol, Address> common) {
	}

	private record DataLabel(Address address, String name) {
	}

	private N64ModemLayout() {
	}

	private static long align(long value, long alignment) throws IOException {
		alignment = Math.max(1, alignment);
		if (alignment > MAX_SPAN || (alignment & (alignment - 1)) != 0)
			throw new IOException("Invalid ELF alignment: " + alignment);
		return (value + alignment - 1) & ~(alignment - 1);
	}

	private static long checkedEnd(long start, long size, long limit) throws IOException {
		if (size <= 0 || start > limit || size > limit - start)
			throw new IOException("ELF analysis layout exceeds supported range");
		return start + size;
	}

	private static boolean isLoadable(N64ModemElf.Section section) {
		return section.size() != 0 && (section.flags() & SHF_ALLOC) != 0
				&& (section.type() == SHT_PROGBITS || section.type() == SHT_NOBITS);
	}

	private static void configure(MemoryBlock block, boolean writable, boolean executable, String comment) {
		block.setRead(true);
		block.setWrite(writable);
		block.setExecute(executable);
		block.setSourceName("Embedded modem ELF");
		block.setComment(comment);
	}

	public static Layout create(Program program, byte[] data, N64ModemElf.Module module,
			List<N64ModemElf.ElfSymbol> symbols, Namespace namespace, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		List<N64ModemElf.Section> sections = module.sections().stream().filter(N64ModemLayout::isLoadable).toList();
		N64ModemElf.Section first = sections.stream()
				.filter(s -> s.type() == SHT_PROGBITS && (s.flags() & SHF_EXECINSTR) != 0).findFirst().orElse(null);
		if (first == null)
			return new Layout(Map.of(), Map.of());
		long origin = N64Firmware.MODEM_ADDRESS + module.romOffset();
		long limit = origin + MAX_SPAN;
		Map<N64ModemElf.Section, Long> placements = new LinkedHashMap<>();
		long cursor = align(origin + first.offset(), first.alignment());
		placements.put(first, cursor);
		cursor = checkedEnd(cursor, first.size(), limit);
		for (var section : sections) {
			if (section.index() == first.index())
				continue;
			cursor = align(cursor, section.alignment());
			placements.put(section, cursor);
			cursor = checkedEnd(cursor, section.size(), limit);
		}
		Map<N64ModemElf.ElfSymbol, Long> commonOffsets = new LinkedHashMap<>();
		Set<String> commonNames = new HashSet<>();
		long commonAlignment = 1;
		for (var symbol : symbols) {
			if (symbol.sectionIndex() != SHN_COMMON)
				continue;
			if (symbol.name().isEmpty() || symbol.size() == 0 || !commonNames.add(symbol.name()))
				throw new IOException("Invalid or ambiguous common symbol: " + symbol.name());
			commonAlignment = Math.max(commonAlignment, symbol.value());
		}
		long commonStart = align(cursor, commonAlignment);
		cursor = commonStart;
		for (var symbol : symbols) {
			if (symbol.sectionIndex() != SHN_COMMON)
				continue;
			cursor = align(cursor, symbol.value());
			commonOffsets.put(symbol, cursor);
			cursor = checkedEnd(cursor, symbol.size(), limit);
		}
		long commonSize = cursor - commonStart;
		String prefix = String.format("MODEM_CODE_%08X", module.romOffset());
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Map<Integer, MemoryBlock> blocks = new LinkedHashMap<>();
		Map<N64ModemElf.ElfSymbol, Address> commonAddresses = new LinkedHashMap<>();
		try {
			for (var placement : placements.entrySet()) {
				monitor.checkCancelled();
				var section = placement.getKey();
				Address start = space.getAddressInThisSpaceOnly(placement.getValue());
				String name = String.format("%s_S%02d", prefix, section.index());
				MemoryBlock block;
				if (section.type() == SHT_NOBITS) {
					block = program.getMemory().createUninitializedBlock(name, start, section.size(), blocks.isEmpty());
				} else {
					long offset = module.romOffset() + section.offset();
					if (offset < 0 || offset > data.length || section.size() > data.length - offset)
						throw new IOException("ELF section exceeds modem image");
					try (ByteArrayInputStream input = new ByteArrayInputStream(data, (int) offset,
							(int) section.size())) {
						block = program.getMemory().createInitializedBlock(name, start, input, section.size(), monitor,
								blocks.isEmpty());
					}
				}
				space = block.getStart().getAddressSpace();
				configure(block, (section.flags() & SHF_WRITE) != 0, (section.flags() & SHF_EXECINSTR) != 0,
						"ELF analysis section " + section.name() + "; not a runtime address");
				blocks.put(section.index(), block);
				log.appendMsg(String.format("  Analysis %-8s %s, size=0x%X", section.name(), block.getStart(),
						section.size()));
			}
			if (commonSize != 0) {
				MemoryBlock block = program.getMemory().createUninitializedBlock(prefix + "_COMMON",
						space.getAddressInThisSpaceOnly(commonStart), commonSize, false);
				configure(block, true, false, "Synthetic ELF common allocation; not captured runtime memory");
				for (var entry : commonOffsets.entrySet())
					commonAddresses.put(entry.getKey(), space.getAddressInThisSpaceOnly(entry.getValue()));
				log.appendMsg(String.format("  Analysis .common  %s, size=0x%X, variables=%d", block.getStart(),
						commonSize, commonAddresses.size()));
			}
		} catch (LockException | MemoryConflictException | AddressOverflowException ex) {
			throw new IOException("Could not create modem analysis layout", ex);
		}
		int labels = createDataLabels(program, symbols, namespace, blocks, commonAddresses, log, monitor);
		log.appendMsg("  Analysis data labels: " + labels);
		return new Layout(Map.copyOf(blocks), Map.copyOf(commonAddresses));
	}

	private static int createDataLabels(Program program, List<N64ModemElf.ElfSymbol> symbols, Namespace namespace,
			Map<Integer, MemoryBlock> blocks, Map<N64ModemElf.ElfSymbol, Address> common, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		Set<DataLabel> created = new HashSet<>();
		int count = 0;
		int rejected = 0;
		for (var symbol : symbols) {
			monitor.checkCancelled();
			if (symbol.name().isEmpty())
				continue;
			Address address = common.get(symbol);
			if (address == null) {
				if (symbol.type() != 0 && symbol.type() != 1)
					continue;
				MemoryBlock block = blocks.get(symbol.sectionIndex());
				if (block == null || block.isExecute() || symbol.value() >= block.getSize()
						|| symbol.size() > block.getSize() - symbol.value())
					continue;
				address = block.getStart().add(symbol.value());
			}
			if (!created.add(new DataLabel(address, symbol.name())))
				continue;
			try {
				program.getSymbolTable().createLabel(address, symbol.name(), namespace, SourceType.IMPORTED);
				count++;
			} catch (InvalidInputException ex) {
				rejected++;
				if (rejected <= 5)
					log.appendMsg("  Invalid analysis data label: " + symbol.name());
			}
		}
		if (rejected != 0)
			log.appendMsg("  Rejected analysis data labels: " + rejected);
		return count;
	}
}