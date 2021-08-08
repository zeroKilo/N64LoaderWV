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
import java.nio.file.Paths;
import java.util.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.python.jline.internal.Log;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
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

	class BlockInfo
	{
		long start, end;
		String desc, name;
		BlockInfo(long s, long e, String n, String d)
		{
			start = s;
			end = e;
			desc = d;
			name = n;
		}
	}
	
	ArrayList<MemoryBlock> blocks = new ArrayList<MemoryBlock>();
	ArrayList<BlockInfo> initSections = new ArrayList<N64LoaderWVLoader.BlockInfo>()
	{
		{
			//add(new BlockInfo(0x00000000, 0x03EFFFFF, "RDRAM Memory",".rdram"));
			add(new BlockInfo(0xA3F00000, 0xA3F00027, "RDRAM Registers",".rdreg"));
			add(new BlockInfo(0xa4040000, 0xa404001f, "SP Registers",".spreg"));
			add(new BlockInfo(0xa4080000, 0xa4080003, "SP_PC_Reg",".spcreg"));
			add(new BlockInfo(0xA4100000, 0xA410001F, "DP Command Registers",".dpcreg"));
			add(new BlockInfo(0xA4200000, 0xa420000F, "DP Span Registers",".dpsreg"));
			add(new BlockInfo(0xa4300000, 0xa430000F, "MIPS Interface (MI) Registers",".mireg"));
			add(new BlockInfo(0xa4400000, 0xa4400037, "Video Interface (VI) Registers",".vireg"));
			add(new BlockInfo(0xa4500000, 0xa4500017, "Audio Interface (AI) Registers",".aireg"));
			add(new BlockInfo(0xa4600000, 0xa4600034, "Peripheral Interface (PI) Registers",".pireg"));
			add(new BlockInfo(0xa4700000, 0xa470001F, "RDRAM Interface (RI) Registers",".rireg"));
			add(new BlockInfo(0xa4800000, 0xa480001b, "Serial Interface (SI) Registers",".sireg"));
			add(new BlockInfo(0xa5000500, 0xa500054b, "N64 Disk Drive (DD) Registers",".ddreg"));
			add(new BlockInfo(0x1FC00000, 0x1FC007BF, "PIF Boot ROM",".pifrom"));
			add(new BlockInfo(0x1FC007C0, 0x1FC007FF, "PIF RAM",".pifram"));
			add(new BlockInfo(0x80000000, 0x800003FF, "Interrupt Vector Table",".ivt"));
		}
	};
	
	
	@Override
	public String getName() {
		return "N64 Loader by Warranty Voider";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Log.info("N64 Loader: Checking Signature" );
		BinaryReader br = new BinaryReader(provider, false);
		int header = br.readInt(0);
		boolean valid = false;
		switch(header)
		{
			case 0x80371240:
				Log.info( "N64 Loader: Found matching header for big endian" );
				valid = true;
				break;
			case 0x37804012:
				Log.info( "N64 Loader: Found matching header for mixed endian" );
				valid = true;
				break;
			case 0x40123780:
				Log.info( "N64 Loader: Found matching header for little endian" );
				valid = true;
				break;
			default:
				Log.info(String.format("N64 Loader: Found unknown header 0x%08X", header));
				break;
		}
		if(valid)
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true));
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
			Log.info("N64 Loader: Checking Endianess" );
			BinaryReader br = new BinaryReader(provider, false);
			int header = br.readInt(0);
			byte[] buffROM = provider.getInputStream(0).readAllBytes();
			switch(header)
			{
				case 0x80371240:						
					break;
				case 0x37804012:
					Log.info( "N64 Loader: Fixing mixed endian" );
					MixedSwap(buffROM);
					break;
				case 0x40123780:
					Log.info( "N64 Loader: Fixing little endian" );
					LittleSwap(buffROM);
					break;
			}

			ByteArrayProvider bapROM = new ByteArrayProvider(buffROM);
			Log.info("N64 Loader: Loading header");
			N64Header h = new N64Header(buffROM);
			
			for(BlockInfo bli : initSections)
			{
				long size = (bli.end + 1) - bli.start;
				monitor.setMessage("N64 Loader: Creating segment " + bli.name);
				Log.info("N64 Loader: Creating segment " + bli.name);
				ByteArrayProvider bapBlock = new ByteArrayProvider(new byte[(int)size]);
				if(bli.desc.equals(".pifrom"))
				{
					byte[] data = this.getClass().getClassLoader().getResourceAsStream("pifdata.bin").readAllBytes();
					bapBlock.close();
					bapBlock = new ByteArrayProvider(data);
				}
				MakeBlock(program, bli.desc, bli.name, bli.start, bapBlock.getInputStream(0), (int)size, "111", null, log, monitor);
				bapBlock.close();
			}

			Log.info("N64 Loader: Creating segment ROM");
			Structure header_struct = N64Header.getDataStructure();
			MakeBlock(program, ".rom", "ROM image", 0xB0000000, bapROM.getInputStream(0), (int)bapROM.length(), "100", header_struct, log, monitor);

			Log.info("N64 Loader: Creating segment BOOT");
			MakeBlock(program, ".boot", "ROM bootloader", 0xA4000040, bapROM.getInputStream(0x40),  0xFC0, "111", null, log, monitor);

			Log.info("N64 Loader: Creating segment RAM");
			MakeBlock(program, ".ram", "RAM content", h.loadAddress, bapROM.getInputStream(0x1000),  buffROM.length - 0x1000, "111", null, log, monitor);
			
			bapROM.close();
			
			if(!((String)options.get(0).getValue()).isEmpty())
				ScanPatterns(buffROM, h.loadAddress, (String)options.get(0).getValue(), program, monitor);
			
			try
			{
				Address addr = MakeAddress(0x1FC00000L);
				if(addr != null)
				{
					program.getSymbolTable().addExternalEntryPoint(addr);
				    program.getSymbolTable().createLabel(addr, "pifMain", SourceType.ANALYSIS);
				}
				addr = MakeAddress(0xA4000040L);
				if(addr != null)
				{
					program.getSymbolTable().addExternalEntryPoint(addr);
				    program.getSymbolTable().createLabel(addr, "bootMain", SourceType.ANALYSIS);
				}
				addr = MakeAddress(h.loadAddress);
				if(addr != null)
				{
					program.getSymbolTable().addExternalEntryPoint(addr);
				    program.getSymbolTable().createLabel(addr, "romMain", SourceType.ANALYSIS);
				}
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00000L), "RDRAM_CONFIG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00004L), "RDRAM_DEVICE_ID", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00008L), "RDRAM_DELAY", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f0000CL), "RDRAM_MODE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00010L), "RDRAM_REF_INTERVAL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00014L), "RDRAM_REF_ROW", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00018L), "RDRAM_RAS_INTERVAL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f0001CL), "RDRAM_MIN_INTERVAL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00020L), "RDRAM_ADDR_SELECT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA3f00024L), "RDRAM_DEVICE_MANUF", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040000L), "SP_MEM_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040004L), "SP_DRAM_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040008L), "SP_RD_LEN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA404000CL), "SP_WR_LEN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040010L), "SP_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040014L), "SP_DMA_FULL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4040018L), "SP_DMA_BUSY", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA404001CL), "SP_SEMAPHORE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4080000L), "SP_PC", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100000L), "DCP_START", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100004L), "DCP_END", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100008L), "DCP_CURRENT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA410000cL), "DCP_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100010L), "DCP_CLOCK", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100014L), "DCP_BUFBUSY", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4100018L), "DCP_PIPEBUSY", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA410001cL), "DCP_START", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4300000L), "MI_INIT_MODE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4300004L), "MI_VERSION", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4300008L), "MI_INTR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA430000CL), "MI_INTR_MASK", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400000L), "VI_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400004L), "VI_ORIGIN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400008L), "VI_WIDTH", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA440000CL), "VI_INTR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400010L), "VI_CURRENT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400014L), "VI_BURST", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400018L), "VI_V_SYNC", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA440001CL), "VI_H_SYNC", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400020L), "VI_LEAP", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400024L), "VI_H_START", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400028L), "VI_V_START", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA440002CL), "VI_V_BURST", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400030L), "VI_X_SCALE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4400034L), "VI_Y_SCALE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4500000L), "AI_DRAM_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4500004L), "AI_LEN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4500008L), "AI_CONTROL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA450000CL), "AI_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4500010L), "AI_DACRATE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4500014L), "AI_BITRATE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600000L), "PI_DRAM_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600004L), "PI_CART_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600008L), "PI_RD_LEN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA460000CL), "PI_WR_LEN", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600010L), "PI_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600014L), "PI_BSD_DOM1_LAT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600018L), "PI_BSD_DOM1_PWD", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA460001CL), "PI_BSD_DOM1_PGS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600020L), "PI_BSD_DOM1_RLS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600024L), "PI_BSD_DOM2_LAT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600028L), "PI_BSD_DOM2_PWD", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA460002CL), "PI_BSD_DOM2_PGS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4600030L), "PI_BSD_DOM2_RLS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700000L), "RI_MODE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700004L), "RI_CONFIG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700008L), "RI_CURRENT_LOAD", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA470000CL), "RI_SELECT", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700010L), "RI_REFRESH", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700014L), "RI_LATENCY", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4700018L), "RI_RERROR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA470001CL), "RI_WERROR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4800000L), "SI_DRAM_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4800004L), "SI_PIF_ADDR_RD64B_REG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4800010L), "SI_PIF_ADDR_WR64B_REG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA4800018L), "SI_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000500L), "ASIC_DATA", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000504L), "ASIC_MISC_REG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000508L), "ASIC_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA500050CL), "ASIC_CUR_TK", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000510L), "ASIC_BM_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000514L), "ASIC_ERR_SECTOR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000518L), "ASIC_SEQ_STATUS", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA500051CL), "ASIC_CUR_SECTOR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000520L), "ASIC_HARD_RESET", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000524L), "ASIC_C1_SO", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000528L), "ASIC_HOST_SECBYTE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA500052CL), "ASIC_C1_S2", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000530L), "ASIC_SEC_BYTE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000534L), "ASIC_C1_S4", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000538L), "ASIC_C1_S6", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA500053CL), "ASIC_CUR_ADDR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000540L), "ASIC_ID_REG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000544L), "ASIC_TEST_REG", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0xA5000548L), "ASIC_TEST_PIN_SEL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000000L), "TLB_REFILL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000080L), "XTLB_REFILL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000100L), "CACHE_ERROR", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000180L), "GEN_EXCEPTION", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000300L), "NTSC_PAL", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000304L), "CART_DD", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000308L), "ROM_BASE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x8000030cL), "RESET", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000310L), "CIC_ID", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000314L), "VERSION", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x80000318L), "RDRAM_SIZE", SourceType.ANALYSIS);
				program.getSymbolTable().createLabel(MakeAddress(0x8000031cL), "NMI_BUFFER", SourceType.ANALYSIS);
			}catch(Exception ex) {}
			
			Log.info("N64 Loader: Done Loading");
	}
	
	public void MakeBlock(Program program, String name, String desc, long address, InputStream s, int size, String flags, Structure struc, MessageLog log, TaskMonitor monitor)
	{
		try
		{
			byte[] bf = flags.getBytes();
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name, addr, s, size, desc, null, bf[0] == '1', bf[1] == '1', bf[2] == '1', log, monitor);
			blocks.add(block);
			if(struc != null)
				DataUtilities.createData(program, block.getStart(), struc, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			Msg.error(this, ExceptionUtils.getStackTrace(e));
		}
	}
	
	public Address MakeAddress(long address)
	{
	    for(MemoryBlock block : blocks)
	    {
	        if(address >= block.getStart().getAddressableWordOffset() &&
	           address <= block.getEnd().getAddressableWordOffset())
	        {
	            Address addr = block.getStart();
	            return addr.add(address - addr.getAddressableWordOffset());            
	        }
	    }
	    return null;
	}
	
	public void MixedSwap(byte[] buff)
	{
		for(int i = 0; i < buff.length; i += 4)
		{
			Swap(buff, i + 0, i + 1);
			Swap(buff, i + 2, i + 3);
		}
	}
	
	public void LittleSwap(byte[] buff)
	{
		for(int i = 0; i < buff.length; i += 4)
		{
			Swap(buff, i + 0, i + 3);
			Swap(buff, i + 1, i + 2);
		}
	}
	
	public void Swap(byte[] buff, int a, int b)
	{
		byte t = buff[a];
		buff[a] = buff[b];
		buff[b] = t;
	}
	
	public void ScanPatterns(byte[] rom, long loadAddress, String sigPath, Program program, TaskMonitor monitor)
	{
		try
		{
			Log.info("N64 Loader: Loading patterns");
			ArrayList<SigPattern> patterns = new ArrayList<SigPattern>();
			List<String> lines = Files.readAllLines(Paths.get(sigPath));
			int maxPatLen = 32;
			for(String line : lines)
			{
				String[] parts = line.split(" ");
				if(parts.length != 2)
					continue;
				SigPattern pat = new SigPattern(parts[0], parts[1]);
				if(pat.pattern.length > maxPatLen)
					maxPatLen = pat.pattern.length;
				patterns.add(pat);
			}			
			Log.info("N64 Loader: Scanning for patterns (" + patterns.size() + ")...");
			monitor.initialize(rom.length - maxPatLen);
			monitor.setMessage("Scanning for patterns (" + patterns.size() + ")...");
			for(int i = 0; i < rom.length - maxPatLen; i += 4)
			{				
				if((i % 0x1000) == 0)
					monitor.setProgress(i);
				for(int j = 0; j < patterns.size(); j++)
				{
					SigPattern sig = patterns.get(j);
					if(sig.Match(rom, i))
					{
						long address = loadAddress + i - 0x1000;
						Address addr = MakeAddress(address);                       
						if(addr != null)
						{
						    SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, sig.name, SourceType.ANALYSIS);
						    Log.info("N64 Loader: Found Symbol at " + String.format("0x%08X", address) + " Name=" + sig.name);
						}
						break;
					}
				}
			}
		} catch (IOException | InvalidInputException e) 
		{
			Msg.error(this, e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option("Signature file", ""));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
