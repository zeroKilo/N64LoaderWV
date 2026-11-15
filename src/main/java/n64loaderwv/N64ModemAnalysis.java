package n64loaderwv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class N64ModemAnalysis {
	private N64ModemAnalysis() {
	}

	public static void createFunctions(Program program, byte[] data, N64ModemElf.Module module,
			List<N64ModemElf.ElfSymbol> symbols, List<N64ModemElf.Relocation> relocations, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		Namespace namespace;
		try {
			var table = program.getSymbolTable();
			Namespace parent = table.getOrCreateNameSpace(program.getGlobalNamespace(), "MODEM_CODE",
					SourceType.IMPORTED);
			namespace = table.getOrCreateNameSpace(parent, String.format("ELF_%08X", module.romOffset()),
					SourceType.IMPORTED);
		} catch (DuplicateNameException | InvalidInputException ex) {
			throw new IOException("Could not create modem code namespace", ex);
		}
		N64ModemLayout.Layout layout = N64ModemLayout.create(program, data, module, symbols, namespace, log, monitor);
		boolean relocated = applyRelocations(program, data, module, relocations, layout, log, monitor);
		if (relocated) {
			N64ModemImports.apply(program, module, relocations, layout, namespace, log, monitor);
			N64ModemImports.applyData(program, module, relocations, layout, namespace, log, monitor);
		}
		N64ModemGlobals.define(program, symbols, layout, log, monitor);
		int created = 0;
		int unknownSize = 0;
		int invalid = 0;
		int overlapping = 0;
		int incomplete = 0;
		int failed = 0;
		for (var section : module.sections()) {
			monitor.checkCancelled();
			if (!section.hasFileBytes() || section.type() != 1 || (section.flags() & 6) != 6)
				continue;
			List<N64ModemElf.ElfSymbol> functions = new ArrayList<>();
			for (var symbol : symbols) {
				if (symbol.type() != 2 || symbol.name().isEmpty() || symbol.sectionIndex() != section.index())
					continue;
				if (symbol.size() == 0) {
					unknownSize++;
					continue;
				}
				long offset = symbol.storageOffset(module);
				if (offset < 0 || (symbol.size() & 3) != 0 || ((module.romOffset() + offset) & 3) != 0) {
					invalid++;
					continue;
				}
				functions.add(symbol);
			}
			if (functions.isEmpty())
				continue;
			functions.sort(Comparator.comparingLong(N64ModemElf.ElfSymbol::value)
					.thenComparing(Comparator.comparingLong(N64ModemElf.ElfSymbol::size).reversed())
					.thenComparingInt(s -> s.binding() == 1 ? 0 : 1).thenComparingInt(N64ModemElf.ElfSymbol::tableIndex)
					.thenComparingInt(N64ModemElf.ElfSymbol::index));
			MemoryBlock block = layout.sections().get(section.index());
			if (block == null)
				continue;
			long previousEnd = 0;
			for (var symbol : functions) {
				monitor.checkCancelled();
				if (symbol.value() < previousEnd) {
					overlapping++;
					continue;
				}
				previousEnd = symbol.value() + symbol.size();
				monitor.setMessage("Creating modem function: " + symbol.name());
				Address entry = block.getStart().add(symbol.value());
				Address end = entry.add(symbol.size() - 1);
				AddressSet body = new AddressSet(entry, end);
				DisassembleCommand command = new DisassembleCommand(body, body, false);
				command.enableCodeAnalysis(false);
				command.applyTo(program, monitor);
				monitor.checkCancelled();
				if (program.getListing().getInstructionAt(entry) == null) {
					failed++;
					if (failed <= 5)
						log.appendMsg("Could not disassemble " + symbol.name());
					continue;
				}
				long decoded = command.getDisassembledAddressSet().getNumAddresses();
				try {
					var function = program.getFunctionManager().createFunction(symbol.name(), namespace, entry, body,
							SourceType.IMPORTED);
					if (function == null) {
						failed++;
						continue;
					}
					function.setComment(String.format(
							"Original ELF function: %s%nDeclared size: 0x%X%nDecoded bytes: 0x%X%n%s; not a runtime address.",
							symbol.name(), symbol.size(), decoded,
							relocated ? "Partially relocated analysis copy" : "Unrelocated analysis copy"));
					if (decoded < symbol.size())
						incomplete++;
					created++;
				} catch (InvalidInputException | OverlappingFunctionException ex) {
					failed++;
					if (failed <= 5)
						log.appendMsg("Could not create modem function " + symbol.name() + ": " + ex.getMessage());
				}
			}
		}
		log.appendMsg(String.format("  Modem analysis functions: %d", created));
		log.appendMsg(String.format("  Unknown size: %d, invalid range: %d, " + "overlapping: %d, failed: %d",
				unknownSize, invalid, overlapping, failed));
		log.appendMsg(String.format("  Functions with incomplete disassembly: %d", incomplete));
		if (relocated)
			N64ModemGlobals.references(program, data, module, relocations, layout, log, monitor);
	}

	private static boolean applyRelocations(Program program, byte[] data, N64ModemElf.Module module,
			List<N64ModemElf.Relocation> relocations, N64ModemLayout.Layout layout, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		N64ModemNativeRelocations.Result result;
		try {
			result = N64ModemNativeRelocations.apply(program, data, module, relocations, layout, monitor);
		} catch (IOException ex) {
			log.appendMsg("  Native MIPS relocation rejected; analysis copy remains unrelocated: " + ex.getMessage());
			return false;
		}
		var memory = program.getMemory();
		try {
			for (var entry : result.sections().entrySet()) {
				monitor.checkCancelled();
				MemoryBlock block = layout.sections().get(entry.getKey());
				boolean writable = block.isWrite();
				try {
					block.setWrite(true);
					memory.setBytes(block.getStart(), entry.getValue().array());
				} finally {
					block.setWrite(writable);
				}
			}
		} catch (MemoryAccessException ex) {
			throw new IOException("Could not update modem analysis sections", ex);
		}
		log.appendMsg("  Native Ghidra MIPS relocations applied: " + result.applied());
		log.appendMsg("  Applied analysis relocations: " + result.applied());
		log.appendMsg("  Unresolved analysis relocations: " + result.unresolved());
		return true;
	}
}
