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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import org.python.jline.internal.Log;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class N64LoaderWVLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "N64 Loader by Warranty Voider";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Log.info("N64 Loader: Checking Signature" );
		byte[] header = provider.readBytes(0, 4);
		if(header[0] == (byte)0x80 &&
		   header[1] == (byte)0x37 &&
		   header[2] == (byte)0x12 &&
		   header[3] == (byte)0x40)
		{
			Log.info( "N64 Loader: Found matching header for big endian" );
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:32:default", "default"), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
			MemoryBlockUtil mbu = new MemoryBlockUtil(program, handler);
			try
			{
				Log.info("N64 Loader: Loading header");
				N64Header h = new N64Header(provider.readBytes(0, 0x40));
				Structure header_struct = N64Header.getDataStructure();
				Address begin_header = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
				Log.info("N64 Loader: Creating header segment");
				mbu.createInitializedBlock(".header", begin_header, provider.getInputStream(0), 0x40, "The ROM header", "ROM Header", true, false, false, monitor);
				DataUtilities.createData(program, begin_header, header_struct, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				byte[] rom = provider.getInputStream(0x1000).readAllBytes();
				Address begin_rom = program.getAddressFactory().getDefaultAddressSpace().getAddress(h.loadAddress);
				Log.info("N64 Loader: Creating rom segment");
				mbu.createInitializedBlock(".rom", begin_rom, provider.getInputStream(0x1000), rom.length, "ROM content", "ROM content", true, true, true, monitor);
				//ScanPatterns(rom, h, monitor);
				Log.info("N64 Loader: Done Loading");
			}
			catch (Exception e)
			{
				Log.info("Error!");
				e.printStackTrace();
			}
	}
	
	public void ScanPatterns(byte[] rom, N64Header h, TaskMonitor monitor)
	{
		try
		{
			Log.info("N64 Loader: Loading patterns");
			String fileName = "pattern/SDK.pat";			 
			ClassLoader classLoader = ClassLoader.getSystemClassLoader();			 
			File file = new File(classLoader.getResource(fileName).getFile());
			BufferedReader b = new BufferedReader(new FileReader(file));
			String line = b.readLine();
			ArrayList<PATLine> patterns = new ArrayList<PATLine>();
			while(line != null)
			{
				patterns.add(new PATLine(line));
				line = b.readLine();
			}
			b.close();
			Log.info("N64 Loader: Scanning for patterns");
			monitor.initialize(100);
			monitor.setMessage("Scanning for patterns...");
			for(int i = 0; i < rom.length - 32; i += 16)
			{				
				if((i % 0x1000) == 0)
				{
					monitor.setProgress(((i * 100) / rom.length));
					monitor.checkCanceled();
				}
				for(int j = 0; j < patterns.size(); j++)
				{
					PATLine pline = patterns.get(j);
					if(pline.Match(rom, i))
					{
						Log.info("N64 Loader: Found Symbol at " + String.format("0x%08X",h.loadAddress + i) + " Name=" + pline.symbol);
					}
				}
			}
			
		}
		catch(Exception e)
		{
			Log.info("Error!");
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {
		return super.validateOptions(provider, loadSpec, options);
	}
}
