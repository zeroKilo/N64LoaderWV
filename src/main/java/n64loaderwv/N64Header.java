package n64loaderwv;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;

public class N64Header {
	public byte[] raw;
	public int magic;
	public int loadAddress;
	public String title;
	public String gameCode;
	public byte maskRomVersion;
	
	public N64Header(byte[] data) {
		raw = data;
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		try {
			magic = b.readInt(0);
			loadAddress = b.readInt(8);
			title = b.readFixedLenAsciiString(0x20, 0x14);
			gameCode = b.readFixedLenAsciiString(0x3B, 0x4);
			maskRomVersion = b.readByte(0x3F);
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}
	
	public static Structure getDataStructure()
	{
		Structure header_struct = new StructureDataType("Internal_Header", 0);		
		header_struct.add(StructConverter.DWORD,  0x04, "Magic", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 1", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Load Address", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 2", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 3", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 4", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 5", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 6", null);
		header_struct.add(StructConverter.STRING, 0x14, "Game Title", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Zeroed", null);
		header_struct.add(StructConverter.WORD,   0x02, "Zeroed", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Zeroed", null);
		header_struct.add(StructConverter.STRING, 0x04, "Game Code", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Mask ROM Version", null);
		return header_struct;
	}
}
