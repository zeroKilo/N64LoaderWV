package n64loaderwv;

import java.io.IOException;
import java.util.zip.CRC32;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;

public class N64Header {
	public byte[] raw;
	public int magic;
	public long loadAddress;
	public String title;
	public String gameCode;
	public byte maskRomVersion;
	
	public N64Header(byte[] data) {
		raw = data;
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		try {
			magic = b.readInt(0);
			loadAddress = b.readInt(8) & 0xFFFFFFFFL;
			title = b.readFixedLenAsciiString(0x20, 0x14);
			gameCode = b.readFixedLenAsciiString(0x3c, 0x2);
			maskRomVersion = b.readByte(0x3F);
			byte[] bootLoader = b.readByteArray(0x40, 0xFC0);
			CRC32 crc32 = new CRC32();
			crc32.update(bootLoader);
			long value = crc32.getValue();
			if(value == 0x0B050EE0L) //"ntsc-name": "6103", "pal-name": "7103"
				loadAddress -= 0x100000;
			if(value == 0xACC8580AL) //"ntsc-name": "6106", "pal-name": "7106"
				loadAddress -= 0x200000;
		} catch (IOException e) {
			Msg.error(this, e);
		}
	}
	
	public static Structure getDataStructure()
	{
		Structure header_struct = new StructureDataType("Internal_Header", 0);		
		header_struct.add(StructConverter.DWORD,  0x04, "Magic", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Clock Rate", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Load Address", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Release Offset", null);
		header_struct.add(StructConverter.DWORD,  0x04, "CRC1", null);
		header_struct.add(StructConverter.DWORD,  0x04, "CRC2", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 5", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Unknown 6", null);
		header_struct.add(StructConverter.STRING, 0x14, "Game Title", null);
		header_struct.add(StructConverter.DWORD,  0x04, "Zeroed", null);
		header_struct.add(StructConverter.WORD,   0x02, "Zeroed", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Zeroed", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Media Type", null);
		header_struct.add(StructConverter.STRING, 0x02, "Game Code", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Region", null);
		header_struct.add(StructConverter.BYTE,   0x01, "Mask ROM Version", null);
		return header_struct;
	}
}
