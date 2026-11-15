package n64loaderwv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemImports {
	private static final int R_MIPS_26 = 4;
	private static final int SHN_UNDEF = 0;
	private static final long MASK32 = 0xFFFFFFFFL;
	private static final int SLOT_SIZE = 4;

	private record CallSite(MemoryBlock block, Address address, String name) {
	}

	private record DataPair(MemoryBlock block, Address high, Address low, String name) {
	}

	private N64ModemImports() {
	}

	public static void apply(Program program, N64ModemElf.Module module, List<N64ModemElf.Relocation> relocations,
			N64ModemLayout.Layout layout, Namespace namespace, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		var memory = program.getMemory();
		List<CallSite> calls = new ArrayList<>();
		Set<String> names = new TreeSet<>();
		Set<Address> sites = new HashSet<>();
		Set<String> unresolvedNames = new TreeSet<>();
		int unresolved = 0;
		AddressSpace space = null;
		try {
			for (var relocation : relocations) {
				monitor.checkCancelled();
				var symbol = relocation.symbol();
				if (symbol.sectionIndex() != SHN_UNDEF)
					continue;
				if (relocation.type() != R_MIPS_26 || symbol.name().isEmpty() || symbol.value() != 0) {
					unresolved++;
					unresolvedNames.add(symbol.name());
					continue;
				}
				MemoryBlock block = layout.sections().get(relocation.targetSectionIndex());
				if (block == null || !block.isExecute() || !block.isInitialized()
						|| !block.getStart().getAddressSpace().isOverlaySpace() || relocation.offset() < 0
						|| relocation.offset() > block.getSize() - 4 || (relocation.offset() & 3) != 0)
					throw new IOException("Invalid external call relocation site");
				Address address = block.getStart().add(relocation.offset());
				if (memory.getInt(address, true) != 0x0C000000) {
					unresolved++;
					unresolvedNames.add(symbol.name());
					continue;
				}
				if (!sites.add(address))
					throw new IOException("Duplicate external call relocation");
				if (space == null)
					space = address.getAddressSpace();
				else if (!space.equals(address.getAddressSpace()))
					throw new IOException("External calls span multiple overlay spaces");
				calls.add(new CallSite(block, address, symbol.name()));
				names.add(symbol.name());
			}
			if (calls.isEmpty()) {
				log.appendMsg("  No eligible external call relocations");
				return;
			}
			long cursor = 0;
			for (MemoryBlock block : memory.getBlocks()) {
				if (space.equals(block.getStart().getAddressSpace()))
					cursor = Math.max(cursor, (block.getEnd().getOffset() & MASK32) + 1);
			}
			long start = (cursor + 15) & ~15L;
			long size = (long) names.size() * SLOT_SIZE;
			long limit = N64Firmware.MODEM_ADDRESS + module.romOffset() + 0x400000L;
			if (start >= limit || size > limit - start || start + size > 0x100000000L)
				throw new IOException("External linkage exceeds analysis layout");
			Map<String, Long> destinations = new LinkedHashMap<>();
			cursor = start;
			for (String name : names) {
				destinations.put(name, cursor);
				cursor += SLOT_SIZE;
			}
			for (CallSite call : calls) {
				long pc = call.address().getOffset() & MASK32;
				long target = destinations.get(call.name());
				if (((pc + 4) & 0xF0000000L) != (target & 0xF0000000L))
					throw new IOException("External call target outside MIPS jump range");
			}
			String prefix = String.format("MODEM_CODE_%08X", module.romOffset());
			MemoryBlock imports = memory.createUninitializedBlock(prefix + "_IMPORTS",
					space.getAddressInThisSpaceOnly(start), size, false);
			imports.setRead(true);
			imports.setWrite(false);
			imports.setExecute(false);
			imports.setArtificial(true);
			imports.setSourceName("Embedded modem ELF");
			imports.setComment("Artificial external function linkage; not runtime memory");
			String library = String.format("MODEM_IMPORTS_%08X", module.romOffset());
			int typed = 0;
			for (var entry : destinations.entrySet()) {
				monitor.checkCancelled();
				var external = program.getExternalManager().addExtFunction(library, entry.getKey(), null,
						SourceType.IMPORTED);
				if (N64ModemPrototypes.apply(program, external.getFunction(), entry.getKey(), log))
					typed++;
				Address address = space.getAddressInThisSpaceOnly(entry.getValue());
				var function = program.getFunctionManager().createThunkFunction(null, namespace, address,
						new AddressSet(address, address), external.getFunction(), SourceType.IMPORTED);
				if (function == null)
					throw new IOException("Could not create external linkage: " + entry.getKey());
			}
			for (CallSite call : calls) {
				monitor.checkCancelled();
				long target = destinations.get(call.name());
				int word = 0x0C000000 | (int) ((target >>> 2) & 0x03FFFFFF);
				boolean writable = call.block().isWrite();
				try {
					call.block().setWrite(true);
					memory.setInt(call.address(), word, true);
				} finally {
					call.block().setWrite(writable);
				}
			}
			log.appendMsg("  External function linkages: " + destinations.size());
			log.appendMsg("  SDK function prototypes applied: " + typed);
			log.appendMsg("  Applied external call relocations: " + calls.size());
			log.appendMsg("  Remaining undefined-symbol relocations: " + unresolved);
			for (String name : unresolvedNames)
				log.appendMsg("    Unresolved symbol: " + name);
		} catch (LockException | MemoryConflictException | AddressOverflowException | MemoryAccessException
				| InvalidInputException | DuplicateNameException | OverlappingFunctionException ex) {
			throw new IOException("Could not establish modem external linkage", ex);
		}
	}

	public static void applyData(Program program, N64ModemElf.Module module, List<N64ModemElf.Relocation> relocations,
			N64ModemLayout.Layout layout, Namespace namespace, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		Set<String> supported = Set.of("osResetType", "__osPiTable", "__osRunQueue", "__osViNext");
		List<DataPair> pairs = new ArrayList<>();
		Set<String> names = new TreeSet<>();
		Set<String> remainingNames = new TreeSet<>();
		Set<Address> sites = new HashSet<>();
		var memory = program.getMemory();
		AddressSpace space = null;
		int remaining = 0;
		try {
			for (int i = 0; i < relocations.size(); i++) {
				monitor.checkCancelled();
				var hi = relocations.get(i);
				var symbol = hi.symbol();
				if (symbol.sectionIndex() != SHN_UNDEF || hi.type() == R_MIPS_26)
					continue;
				if (!supported.contains(symbol.name())) {
					remaining++;
					remainingNames.add(symbol.name());
					continue;
				}
				if (hi.type() != 5 || i + 1 >= relocations.size())
					throw new IOException("Invalid external data HI16 relocation");
				var lo = relocations.get(++i);
				if (lo.type() != 6 || !lo.symbol().equals(symbol) || lo.sectionIndex() != hi.sectionIndex()
						|| lo.targetSectionIndex() != hi.targetSectionIndex() || lo.offset() != hi.offset() + 4)
					throw new IOException("Invalid external data HI16/LO16 pair");
				MemoryBlock block = layout.sections().get(hi.targetSectionIndex());
				if (block == null || !block.isInitialized() || !block.isExecute()
						|| !block.getStart().getAddressSpace().isOverlaySpace() || hi.offset() < 0
						|| (hi.offset() & 3) != 0 || lo.offset() > block.getSize() - 4)
					throw new IOException("Invalid external data relocation range");
				Address high = block.getStart().add(hi.offset());
				Address low = block.getStart().add(lo.offset());
				int highWord = memory.getInt(high, true);
				int lowWord = memory.getInt(low, true);
				int opcode = lowWord >>> 26;
				if ((highWord >>> 26) != 15 || (highWord & 0xFFFF) != 0 || (lowWord & 0xFFFF) != 0
						|| symbol.value() != 0 || (opcode != 9 && opcode != 35 && opcode != 43)
						|| ((highWord >>> 16) & 31) != ((lowWord >>> 21) & 31))
					throw new IOException("Unsupported external data instruction pair");
				if (!sites.add(high) || !sites.add(low))
					throw new IOException("Duplicate external data relocation site");
				if (space == null)
					space = high.getAddressSpace();
				else if (!space.equals(high.getAddressSpace()))
					throw new IOException("External data spans multiple overlays");
				pairs.add(new DataPair(block, high, low, symbol.name()));
				names.add(symbol.name());
			}
			if (!pairs.isEmpty()) {
				long cursor = 0;
				for (MemoryBlock block : memory.getBlocks()) {
					if (space.equals(block.getStart().getAddressSpace()))
						cursor = Math.max(cursor, (block.getEnd().getOffset() & MASK32) + 1);
				}
				long start = (cursor + 15) & ~15L;
				long size = names.size() * 4L;
				long limit = N64Firmware.MODEM_ADDRESS + module.romOffset() + 0x400000L;
				if (start >= limit || size > limit - start || start + size > 0x100000000L)
					throw new IOException("External data allocation exceeds analysis layout");
				String prefix = String.format("MODEM_CODE_%08X", module.romOffset());
				MemoryBlock block = memory.createUninitializedBlock(prefix + "_EXTDATA",
						space.getAddressInThisSpaceOnly(start), size, false);
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(false);
				block.setArtificial(true);
				block.setSourceName("Embedded modem ELF");
				block.setComment("Synthetic external data linkage; original addresses and values unknown");
				Map<String, Long> destinations = new LinkedHashMap<>();
				cursor = start;
				for (String name : names) {
					monitor.checkCancelled();
					destinations.put(name, cursor);
					program.getSymbolTable().createLabel(space.getAddressInThisSpaceOnly(cursor), name, namespace,
							SourceType.IMPORTED);
					cursor += 4;
				}
				for (DataPair pair : pairs) {
					monitor.checkCancelled();
					long target = destinations.get(pair.name());
					int highWord = memory.getInt(pair.high(), true);
					int lowWord = memory.getInt(pair.low(), true);
					int high = (int) (((target + 0x8000L) >>> 16) & 0xFFFF);
					int low = (int) (target & 0xFFFF);
					boolean writable = pair.block().isWrite();
					try {
						pair.block().setWrite(true);
						memory.setInt(pair.high(), (highWord & 0xFFFF0000) | high, true);
						memory.setInt(pair.low(), (lowWord & 0xFFFF0000) | low, true);
					} finally {
						pair.block().setWrite(writable);
					}
				}
			}
			log.appendMsg("  External data linkages: " + names.size());
			log.appendMsg("  Applied external data relocations: " + pairs.size() * 2);
			log.appendMsg("  Remaining external data relocations: " + remaining);
			for (String name : remainingNames)
				log.appendMsg("    Unresolved external data: " + name);
		} catch (LockException | MemoryConflictException | AddressOverflowException | MemoryAccessException
				| InvalidInputException ex) {
			throw new IOException("Could not establish modem external data linkage", ex);
		}
	}
}
