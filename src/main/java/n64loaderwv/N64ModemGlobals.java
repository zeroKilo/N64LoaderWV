package n64loaderwv;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemGlobals {
	private static final int SHN_COMMON = 0xFFF2;
	private static final long MASK32 = 0xFFFFFFFFL;

	private N64ModemGlobals() {
	}

	private static Address addressOf(N64ModemElf.ElfSymbol symbol, N64ModemLayout.Layout layout) {
		if (symbol.sectionIndex() == SHN_COMMON)
			return layout.common().get(symbol);
		MemoryBlock block = layout.sections().get(symbol.sectionIndex());
		if (block == null || block.isExecute() || symbol.value() < 0 || symbol.value() >= block.getSize())
			return null;
		return block.getStart().add(symbol.value());
	}

	public static void define(Program program, List<N64ModemElf.ElfSymbol> symbols, N64ModemLayout.Layout layout,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		Map<Address, List<Long>> ranges = new TreeMap<>();
		for (var symbol : symbols) {
			monitor.checkCancelled();
			if (symbol.name().isEmpty() || symbol.size() <= 0 || symbol.size() > Integer.MAX_VALUE
					|| (symbol.type() != 1 && symbol.sectionIndex() != SHN_COMMON))
				continue;
			Address address = addressOf(symbol, layout);
			if (address == null)
				continue;
			MemoryBlock block = program.getMemory().getBlock(address);
			if (block == null || symbol.size() - 1 > block.getEnd().subtract(address))
				continue;
			ranges.computeIfAbsent(address, k -> new ArrayList<>()).add(symbol.size());
		}
		List<Map.Entry<Address, List<Long>>> entries = new ArrayList<>(ranges.entrySet());
		int defined = 0;
		int ambiguous = 0;
		int failed = 0;
		Address previousEnd = null;
		for (int i = 0; i < entries.size(); i++) {
			monitor.checkCancelled();
			var entry = entries.get(i);
			Address start = entry.getKey();
			long size = entry.getValue().stream().mapToLong(Long::longValue).max().orElseThrow();
			Address end = start.add(size - 1);
			boolean overlap = previousEnd != null && previousEnd.getAddressSpace().equals(start.getAddressSpace())
					&& previousEnd.compareTo(start) >= 0;
			if (i + 1 < entries.size()) {
				Address next = entries.get(i + 1).getKey();
				overlap |= next.getAddressSpace().equals(start.getAddressSpace()) && next.compareTo(end) <= 0;
			}
			if (previousEnd == null || previousEnd.compareTo(end) < 0)
				previousEnd = end;
			if (overlap || entry.getValue().stream().anyMatch(v -> v != size)) {
				ambiguous++;
				continue;
			}
			try {
				program.getListing().createData(start, Undefined.getUndefinedDataType(Math.toIntExact(size)));
				defined++;
			} catch (CodeUnitInsertionException ex) {
				failed++;
				if (failed <= 5)
					log.appendMsg("  Could not define modem object at " + start + ": " + ex.getMessage());
			}
		}
		log.appendMsg(
				String.format("  Sized modem objects: %d, ambiguous: %d, failed: %d", defined, ambiguous, failed));
	}

	public static void references(Program program, byte[] rom, N64ModemElf.Module module,
			List<N64ModemElf.Relocation> relocations, N64ModemLayout.Layout layout, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		ByteBuffer original = ByteBuffer.wrap(rom);
		var memory = program.getMemory();
		var listing = program.getListing();
		var manager = program.getReferenceManager();
		int added = 0;
		int conflicts = 0;
		int unreadable = 0;
		for (int i = 0; i + 1 < relocations.size(); i++) {
			monitor.checkCancelled();
			var hi = relocations.get(i);
			var lo = relocations.get(i + 1);
			if (hi.type() != 5 || lo.type() != 6 || hi.sectionIndex() != lo.sectionIndex()
					|| hi.targetSectionIndex() != lo.targetSectionIndex() || !hi.symbol().equals(lo.symbol())
					|| lo.offset() != hi.offset() + 4)
				continue;
			Address base = addressOf(hi.symbol(), layout);
			MemoryBlock code = layout.sections().get(hi.targetSectionIndex());
			if (base == null || code == null || !code.isExecute() || lo.offset() > code.getSize() - 4 || hi.offset() < 0
					|| (hi.offset() & 3) != 0)
				continue;
			var section = module.sections().get(hi.targetSectionIndex());
			long raw = module.romOffset() + section.offset() + hi.offset();
			if (!section.hasFileBytes() || raw < 0 || raw > rom.length - 8)
				continue;
			int oldHigh = original.getInt((int) raw);
			int oldLow = original.getInt((int) raw + 4);
			int opcode = oldLow >>> 26;
			if ((oldHigh >>> 26) != 15 || ((oldHigh >>> 16) & 31) == 0
					|| ((oldHigh >>> 16) & 31) != ((oldLow >>> 21) & 31))
				continue;
			RefType type;
			int operand;
			switch (opcode) {
			case 9:
				type = RefType.DATA;
				operand = 2;
				break;
			case 32:
			case 33:
			case 35:
			case 36:
			case 37:
			case 39:
			case 49:
			case 53:
			case 55:
				type = RefType.READ;
				operand = 1;
				break;
			case 40:
			case 41:
			case 43:
			case 57:
			case 61:
			case 63:
				type = RefType.WRITE;
				operand = 1;
				break;
			default:
				continue;
			}
			long addend = (long) ((oldHigh & 0xFFFF) << 16) + (short) oldLow;
			long target = (base.getOffset() + addend) & MASK32;
			Address destination = base.getAddressSpace().getAddressInThisSpaceOnly(target);
			MemoryBlock targetBlock = memory.getBlock(destination);
			if (targetBlock == null || !targetBlock.equals(memory.getBlock(base)) || targetBlock.isExecute()
					|| !destination.getAddressSpace().equals(code.getStart().getAddressSpace()))
				continue;
			Address high = code.getStart().add(hi.offset());
			Address low = code.getStart().add(lo.offset());
			var instruction = listing.getInstructionAt(low);
			if (listing.getInstructionAt(high) == null || instruction == null
					|| operand >= instruction.getNumOperands())
				continue;
			try {
				int h = memory.getInt(high, true);
				int l = memory.getInt(low, true);
				long actual = (((long) (h & 0xFFFF) << 16) + (short) l) & MASK32;
				if ((h & 0xFFFF0000) != (oldHigh & 0xFFFF0000) || (l & 0xFFFF0000) != (oldLow & 0xFFFF0000)
						|| target != actual)
					continue;
			} catch (MemoryAccessException ex) {
				unreadable++;
				continue;
			}
			var refs = manager.getReferencesFrom(low, operand);
			if (refs.length != 0) {
				boolean different = false;
				for (var reference : refs)
					different |= !reference.getToAddress().equals(destination);
				if (different)
					conflicts++;
				continue;
			}
			manager.addMemoryReference(low, destination, type, SourceType.IMPORTED, operand);
			added++;
		}
		log.appendMsg(String.format("  Modem data references added: %d, conflicts retained: %d, unreadable: %d", added,
				conflicts, unreadable));
	}
}