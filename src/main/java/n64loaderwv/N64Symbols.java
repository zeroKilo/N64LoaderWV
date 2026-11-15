package n64loaderwv;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
public final class N64Symbols {
	
	private N64Symbols() {
	}
	
	private record AddressSymbol(long address, String name) {
	}
	
	public static void apply(Program program, String path, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (path == null || path.isBlank())
			return;
		List<AddressSymbol> symbols = new ArrayList<>();
		List<SigPattern> patterns = new ArrayList<>();
		int lineNumber = 0;
		for (String raw : Files.readAllLines(Path.of(path))) {
			monitor.checkCancelled();
			lineNumber++;
			String line = raw.strip();
			if (line.isEmpty() || line.startsWith("#") || line.startsWith("//"))
				continue;
			String[] parts = line.split("\\s+");
			if (parts.length != 2)
				throw new IOException("Invalid signature line " + lineNumber);
			if (parts[0].matches("(?i)(?:0x)?[0-9a-f]{8}")) {
				long offset = Long.parseLong(parts[0].replaceFirst("(?i)^0x", ""), 16);
				symbols.add(new AddressSymbol(offset, parts[1]));
			} else if (parts[1].matches("(?i)(?:[0-9a-f]{2}|\\?\\?)+") && !parts[1].matches("(?:\\?\\?)+")) {
				patterns.add(new SigPattern(parts[0], parts[1]));
			} else {
				throw new IOException("Invalid signature line " + lineNumber);
			}
		}
		int matched = 0;
		int skipped = 0;
		try {
			for (AddressSymbol symbol : symbols) {
				monitor.checkCancelled();
				Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(symbol.address());
				if (!program.getMemory().contains(addr)) {
					skipped++;
					continue;
				}
				addSymbol(program, addr, symbol.name());
				matched++;
			}
			MemoryBlock ram = program.getMemory().getBlock(".ram");
			if (!patterns.isEmpty() && ram != null && ram.isInitialized()) {
				byte[] bytes = new byte[Math.toIntExact(ram.getSize())];
				if (program.getMemory().getBytes(ram.getStart(), bytes) != bytes.length)
					throw new IOException("Could not read entire .ram block");
				monitor.setMessage("Scanning N64 RAM signatures");
				monitor.initialize(bytes.length);
				int first = (int) ((-ram.getStart().getOffset()) & 3L);
				for (int i = first; i < bytes.length; i += 4) {
					if ((i & 0xFFF) == first) {
						monitor.checkCancelled();
						monitor.setProgress(i);
					}
					for (SigPattern pattern : patterns) {
						if (pattern.pattern.length <= bytes.length - i && pattern.Match(bytes, i)) {
							addSymbol(program, ram.getStart().add(i), pattern.name);
							matched++;
							break;
						}
					}
				}
				monitor.setProgress(bytes.length);
			} else if (!patterns.isEmpty()) {
				log.appendMsg("N64 signatures: no initialized .ram to scan");
			}
		} catch (MemoryAccessException | InvalidInputException ex) {
			throw new IOException("Could not apply N64 symbols", ex);
		}
		log.appendMsg("N64 signatures: " + matched + " matches, " + skipped + " unmapped address symbols");
	}
	
	private static void addSymbol(Program program, Address address, String name) throws InvalidInputException {
		SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, address, null, name, SourceType.ANALYSIS);
	}
}