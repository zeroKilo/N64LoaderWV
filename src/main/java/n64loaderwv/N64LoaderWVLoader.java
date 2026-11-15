/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package n64loaderwv;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class N64LoaderWVLoader extends AbstractLibrarySupportLoader {

	static final int BASE_RDRAM_SIZE = 4 * 1024 * 1024;
	static final int EXPANDED_RDRAM_SIZE = 8 * 1024 * 1024;
	static final int INTERRUPT_VECTOR_SIZE = 0x400;

	static final class ImportContext {
		private final AddressSpace defaultAddressSpace;
		private final List<MemoryBlock> blocks = new ArrayList<>();

		ImportContext(Program program) {
			defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		}

		Address defaultAddress(long offset) {
			return defaultAddressSpace.getAddress(offset);
		}

		void add(MemoryBlock block) {
			blocks.add(block);
		}

		Address resolve(long offset) {
			for (MemoryBlock block : blocks) {
				Address candidate = block.getStart().getAddressSpace().getAddress(offset);
				if (block.contains(candidate))
					return candidate;
			}
			return null;
		}
	}

	class BlockInfo {
		long start, end;
		String desc, name;

		BlockInfo(long s, long e, String n, String d) {
			start = s;
			end = e;
			desc = d;
			name = n;
		}
	}

	List<BlockInfo> initSections = List.of(new BlockInfo(0x80000000L, 0x800003FFL, "Interrupt Vector Table", ".ivt"));

	public N64LoaderWVLoader() {
		Msg.info(this, "N64 Loader: Loaded class");
	}

	@Override
	public String getName() {
		return "N64 Loader by Warranty Voider";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Msg.info(this, "N64 Loader: Checking Signature");
		BinaryReader br = new BinaryReader(provider, false);
		int header = br.readInt(0);
		boolean valid = false;
		switch (header) {
		case 0x80371240:
		case 0x80270740:
			Msg.info(this, "N64 Loader: Found matching header for big endian");
			valid = true;
			break;
		case 0x37804012:
			Msg.info(this, "N64 Loader: Found matching header for mixed endian");
			valid = true;
			break;
		case 0x40123780:
			Msg.info(this, "N64 Loader: Found matching header for little endian");
			valid = true;
			break;
		default:
			Msg.info(this, String.format("N64 Loader: Found unknown header 0x%08X", header));
			break;
		}
		if (valid)
			loadSpecs.add(new LoadSpec(this, N64Memory.KSEG0,
					new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true));
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		this.load(settings.provider(), settings.loadSpec(), settings.options(), program, settings.monitor(),
				settings.log());
	}

	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		loadProgram(provider, loadSpec, options, program, monitor, log);
	}

	private void loadProgram(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		ImportContext context = new ImportContext(program);
		Msg.info(this, "N64 Loader: Checking Endianess");
		BinaryReader br = new BinaryReader(provider, false);
		int header = br.readInt(0);
		byte[] buffROM = provider.getInputStream(0).readAllBytes();
		switch (header) {
		case 0x80371240:
		case 0x80270740:
			break;
		case 0x37804012:
			Msg.info(this, "N64 Loader: Fixing mixed endian");
			MixedSwap(buffROM);
			break;
		case 0x40123780:
			Msg.info(this, "N64 Loader: Fixing little endian");
			LittleSwap(buffROM);
			break;
		}
		Msg.info(this, "N64 Loader: Loading header");
		N64Header h = new N64Header(buffROM);
		String rdramPath = getStringOption(options, "RDRAM dump file");
		try (ByteArrayProvider bapROM = new ByteArrayProvider(buffROM);
				ByteArrayProvider bapRDRAM = rdramPath.isEmpty() ? null
						: new ByteArrayProvider(readRdramDump(Paths.get(rdramPath)))) {
			N64Memory.BootRange bootRange = null;
			if (bapRDRAM == null) {
				bootRange = N64Memory.getCartridgeBootRange(buffROM, h.loadAddress);
				log.appendMsg(String.format("IPL3 CRC32: %08X", bootRange.ipl3CRC()));
			}
			long ramEntry = bootRange != null ? bootRange.loadAddress() : h.loadAddress;
			for (BlockInfo bli : initSections) {
				long size = (bli.end + 1) - bli.start;
				monitor.setMessage("N64 Loader: Creating segment " + bli.name);
				Msg.info(this, "N64 Loader: Creating segment " + bli.name);
				if (bootRange != null && bli.desc.equals(".ivt")) {
					try {
						MemoryBlock ivt = program.getMemory().createUninitializedBlock(".ivt",
								context.defaultAddress(0x80000000L), INTERRUPT_VECTOR_SIZE, false);
						ivt.setRead(true);
						ivt.setWrite(true);
						ivt.setExecute(true);
						ivt.setComment("Interrupt vectors and boot parameters; " + "contents not reconstructed");
						context.add(ivt);

					} catch (Exception ex) {
						throw new IOException("Could not create interrupt vector block", ex);
					}
					continue;
				}
				ByteArrayProvider bapBlock = new ByteArrayProvider(new byte[(int) size]);
				boolean borrowedRdram = false;
				if (bli.desc.equals(".ivt") && bapRDRAM != null) {
					bapBlock.close();
					bapBlock = bapRDRAM;
					borrowedRdram = true;
				}
				MakeBlock(context, program, bli.desc, bli.name, bli.start, bapBlock.getInputStream(0), (int) size,
						"111", null, log, monitor);
				if (!borrowedRdram)
					bapBlock.close();
			}
			MemoryBlock pif = N64Firmware.loadPif(program, getStringOption(options, "PIF file"), log, monitor);
			if (pif != null)
				context.add(pif);
			Msg.info(this, "N64 Loader: Creating segment ROM");
			Structure header_struct = N64Header.getDataStructure();
			MakeBlock(context, program, ".rom", "ROM image", 0xB0000000, bapROM.getInputStream(0),
					(int) bapROM.length(), "100", header_struct, log, monitor);
			MakeBlock(context, program, ".bootheader", "ROM header copied into SP DMEM", 0xA4000000L,
					bapROM.getInputStream(0), 0x40, "110", header_struct, log, monitor);
			Msg.info(this, "N64 Loader: Creating segment BOOT");
			MakeBlock(context, program, ".boot", "ROM bootloader", 0xA4000040, bapROM.getInputStream(0x40), 0xFC0,
					"111", null, log, monitor);
			Msg.info(this, "N64 Loader: Creating segment RAM");
			if (bapRDRAM != null) {
				MakeBlock(context, program, ".ram", "Captured RDRAM content", 0x80000400L,
						bapRDRAM.getInputStream(INTERRUPT_VECTOR_SIZE), rdramRamLength((int) bapRDRAM.length()), "111",
						null, log, monitor);
			} else {
				MakeBlock(context, program, ".ram", "IPL3-loaded RDRAM content", bootRange.loadAddress(),
						bapROM.getInputStream(0x1000), bootRange.byteCount(), "111", null, log, monitor);
				log.appendMsg(String.format("Reconstructed IPL3 transfer: " + "0x%X bytes at 0x%08X",
						bootRange.byteCount(), bootRange.loadAddress()));
			}
			try {
				N64Hardware.addHardware(program, true);
				for (MemoryBlock block : program.getMemory().getBlocks()) {
					if (!context.blocks.contains(block))
						context.add(block);
				}
			} catch (Exception ex) {
				throw new IOException("Failed to map N64 hardware", ex);
			}
			N64Firmware.loadModem(program, getStringOption(options, "Modem.bin file"), log, monitor);
			try {
				Address addr = MakeAddress(context, 0xBFC00000L);
				if (addr != null) {
					program.getSymbolTable().addExternalEntryPoint(addr);
					program.getSymbolTable().createLabel(addr, "pifMain", SourceType.ANALYSIS);
				}
				addr = MakeAddress(context, 0xA4000040L);
				if (addr != null) {
					program.getSymbolTable().addExternalEntryPoint(addr);
					program.getSymbolTable().createLabel(addr, "bootMain", SourceType.ANALYSIS);
				}
				addr = MakeAddress(context, ramEntry);
				if (addr != null) {
					program.getSymbolTable().addExternalEntryPoint(addr);
					program.getSymbolTable().createLabel(addr, "ramMain", SourceType.ANALYSIS);
				}
			} catch (Exception ex) {
			    log.appendMsg("Failed to register N64 entry points");
			    log.appendException(ex);
			}
			if (N64Memory.isEnabled(options, N64Memory.OPTION_ALIASES)) {
				N64Memory.addRdramAliases(program, log);
			}
			N64DDMedia.loadIpl(program, getStringOption(options, N64DDMedia.OPTION_IPL), log, monitor);
			N64DDMedia.loadExpansionDisk(program, getStringOption(options, N64DDMedia.OPTION_DISK), log, monitor);
			N64Symbols.apply(program, (String) options.get(0).getValue(), log, monitor);
			Msg.info(this, "N64 Loader: Done Loading");
		}
	}

	public void MakeBlock(ImportContext context, Program program, String name, String desc, long address, InputStream s,
			int size, String flags, Structure struc, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			byte[] bf = flags.getBytes();
			Address addr = context.defaultAddress(address);
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name, addr, s, size, desc, null,
					bf[0] == '1', bf[1] == '1', bf[2] == '1', log, monitor);
			if (block == null) {
				monitor.checkCancelled();
				throw new IOException("block creation returned no memory block");
			}
			context.add(block);
			if (struc != null)
				DataUtilities.createData(program, block.getStart(), struc, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			throw new IOException("N64 Loader: failed to create block " + name, e);
		}
	}

	static int checkedRdramDumpLength(long length) throws IOException {
		if (length != BASE_RDRAM_SIZE && length != EXPANDED_RDRAM_SIZE) {
			throw new IOException(String.format("RDRAM dump must be exactly 4 MiB or 8 MiB, got %d bytes", length));
		}
		return (int) length;
	}

	static byte[] readRdramDump(Path path) throws IOException {
		try (InputStream input = Files.newInputStream(path)) {
			byte[] data = input.readNBytes(EXPANDED_RDRAM_SIZE + 1);
			checkedRdramDumpLength(data.length);
			return data;
		}
	}

	static int rdramRamLength(int dumpLength) throws IOException {
		return checkedRdramDumpLength(dumpLength) - INTERRUPT_VECTOR_SIZE;
	}

	Address MakeAddress(ImportContext context, long address) {
		return context.resolve(address);
	}

	public Address MakeAddress(Program program, long address) {
		Address result = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		return program.getMemory().getBlock(result) == null ? null : result;
	}

	public void MixedSwap(byte[] buff) {
		for (int i = 0; i < buff.length; i += 4) {
			Swap(buff, i + 0, i + 1);
			Swap(buff, i + 2, i + 3);
		}
	}

	public void LittleSwap(byte[] buff) {
		for (int i = 0; i < buff.length; i += 4) {
			Swap(buff, i + 0, i + 3);
			Swap(buff, i + 1, i + 2);
		}
	}

	public void Swap(byte[] buff, int a, int b) {
		byte t = buff[a];
		buff[a] = buff[b];
		buff[b] = t;
	}

	public void ApplyN64sym(ImportContext context, byte[] rom, long loadAddress, String sigPath, Program program,
			TaskMonitor monitor) throws IOException, InvalidInputException {
		Msg.info(this, "N64 Loader: Trying to loading signature file as N64sym format");
		List<String> lines = Files.readAllLines(Paths.get(sigPath));
		for (String line : lines) {
			String[] parts = line.split(" ");
			if (parts.length != 2)
				continue;
			long address = Long.parseLong(parts[0], 16);
			String name = parts[1];
			if (address >= loadAddress) {
				SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, MakeAddress(context, address), null, name,
						SourceType.ANALYSIS);
				Msg.info(this, "N64 Loader: Loaded Symbol at " + String.format("0x%08X", address) + " Name=" + name);
			}
		}
	}

	public void ScanPatterns(ImportContext context, byte[] rom, long loadAddress, String sigPath, Program program,
			TaskMonitor monitor) throws IOException, InvalidInputException {
		Msg.info(this, "N64 Loader: Trying to loading signature file as default format");
		ArrayList<SigPattern> patterns = new ArrayList<SigPattern>();
		List<String> lines = Files.readAllLines(Paths.get(sigPath));
		int maxPatLen = 32;
		for (String line : lines) {
			String[] parts = line.split(" ");
			if (parts.length != 2)
				continue;
			SigPattern pat = new SigPattern(parts[0], parts[1]);
			if (pat.pattern.length > maxPatLen)
				maxPatLen = pat.pattern.length;
			patterns.add(pat);
		}
		Msg.info(this, "N64 Loader: Scanning for patterns (" + patterns.size() + ")...");
		monitor.initialize(rom.length - maxPatLen);
		monitor.setMessage("Scanning for patterns (" + patterns.size() + ")...");
		for (int i = 0; i < rom.length - maxPatLen; i += 4) {
			if ((i % 0x1000) == 0)
				monitor.setProgress(i);
			for (int j = 0; j < patterns.size(); j++) {
				SigPattern sig = patterns.get(j);
				if (sig.Match(rom, i)) {
					long address = loadAddress + i - 0x1000;
					Address addr = MakeAddress(context, address);
					if (addr != null) {
						SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, sig.name,
								SourceType.ANALYSIS);
						Msg.info(this, "N64 Loader: Found Symbol at " + String.format("0x%08X", address) + " Name="
								+ sig.name);
					}
					break;
				}
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new FileOption("Signature file", "", Loader.COMMAND_LINE_ARG_PREFIX + "-signature"));
		list.add(new FileOption("Modem.bin file", "", Loader.COMMAND_LINE_ARG_PREFIX + "-modem"));
		list.add(new FileOption("PIF file", "", Loader.COMMAND_LINE_ARG_PREFIX + "-pif"));
		list.add(new FileOption("RDRAM dump file", "", Loader.COMMAND_LINE_ARG_PREFIX + "-rdram"));
		list.add(new FileOption(N64DDMedia.OPTION_IPL, "", Loader.COMMAND_LINE_ARG_PREFIX + "-ipl"));
		list.add(new FileOption(N64DDMedia.OPTION_DISK, "", Loader.COMMAND_LINE_ARG_PREFIX + "-disk"));
		list.add(N64Memory.aliasOption());
		return list;
	}

	private String getStringOption(List<Option> options, String name) {
		for (Option option : options) {
			if (name.equals(option.getName()) && option.getValue() instanceof String value)
				return value.trim();
		}
		return "";
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
