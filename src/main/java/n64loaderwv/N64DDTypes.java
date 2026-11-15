package n64loaderwv;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

public final class N64DDTypes {
	
	private static final CategoryPath CATEGORY = new CategoryPath("/N64/64DD");
	private static final DataType U8 = ByteDataType.dataType;
	private static final DataType U16 = WordDataType.dataType;
	private static final DataType U32 = DWordDataType.dataType;
	private static final DataType CHAR = CharDataType.dataType;
	
	private N64DDTypes() {
	}
	
	private static void field(StructureDataType type, int offset, DataType dataType, String name, String comment) {
		type.replaceAtOffset(offset, dataType, dataType.getLength(), name, comment);
	}
	
	private static DataType array(DataType type, int count) {
		return new ArrayDataType(type, count, type.getLength());
	}
	
	public static StructureDataType createSystemData(N64DDHeader header) {
		boolean master = header.format == N64DDHeader.Format.D64;
		boolean dev = header.development;
		int size = dev ? 0xC0 : 0xE8;
		String name = master ? "N64DDMasterSystemData" : dev ? "N64DDDevSystemData" : "N64DDSystemData";
		StructureDataType type = new StructureDataType(CATEGORY, name, size);
		if (!master) {
			field(type, 0x00, U32, "region", "Disk region identifier");
			field(type, 0x04, U8, "formatType", "Disk formatting type");
			field(type, 0x08, array(U8, 16), "defectOffsets", "Cumulative defect-track table offsets");
			field(type, 0x18, U32, "reserved18", null);
			field(type, 0x20, array(U8, dev ? 160 : 192), "defectTracks", "Defect-track table storage");
		}
		field(type, 0x05, U8, "diskType", "Encoded disk type");
		field(type, 0x06, U16, "iplLoadBlocks", "Number of blocks loaded by IPL");
		field(type, 0x1C, U32, "iplLoadAddress", "Initial RDRAM load address");
		if (!dev) {
			field(type, 0xE0, U16, "romEndLba", null);
			field(type, 0xE2, U16, "ramStartLba", null);
			field(type, 0xE4, U16, "ramEndLba", null);
			if (!master)
				field(type, 0xE6, U16, "reservedE6", null);
		}
		return type;
	}
	
	public static StructureDataType createDiskID() {
		StructureDataType time = new StructureDataType(CATEGORY, "LEODiskTime", 8);
		field(time, 0, U8, "pad", null);
		field(time, 1, U8, "yearhi", "BCD");
		field(time, 2, U8, "yearlo", "BCD");
		field(time, 3, U8, "month", "BCD");
		field(time, 4, U8, "day", "BCD");
		field(time, 5, U8, "hour", "BCD");
		field(time, 6, U8, "minute", "BCD");
		field(time, 7, U8, "second", "BCD");
		StructureDataType serial = new StructureDataType(CATEGORY, "LEOSerialNum", 16);
		field(serial, 0, array(U8, 8), "lineNumber", "Factory line number");
		field(serial, 8, time, "time", null);
		StructureDataType id = new StructureDataType(CATEGORY, "LEODiskID", 0x20);
		field(id, 0x00, array(CHAR, 4), "gameName", null);
		field(id, 0x04, U8, "gameVersion", "BCD");
		field(id, 0x05, U8, "diskNumber", "BCD");
		field(id, 0x06, U8, "ramUsage", null);
		field(id, 0x07, U8, "diskUsage", "BCD");
		field(id, 0x08, serial, "serialNumber", null);
		field(id, 0x18, array(CHAR, 2), "company", null);
		field(id, 0x1A, array(U8, 6), "freeArea", null);
		return id;
	}
	
	public static void apply(Program program, Address diskStart, N64DDHeader header)
			throws IOException, InvalidInputException {
		try {
			StructureDataType system = createSystemData(header);
			StructureDataType id = createDiskID();
			program.getListing().createData(diskStart.add(header.headerOffset), system);
			if (header.format == N64DDHeader.Format.D64) {
				program.getListing().createData(diskStart.add(0x100), id);
			} else {
				// Both redundant disk ID blocks.
				for (int block : new int[] { 14, 15 }) {
					Address addr = diskStart.add((long) block * N64DDHeader.SYSTEM_BLOCK_SIZE);
					program.getListing().createData(addr, id);
					program.getSymbolTable().createLabel(addr, header.format.name() + "_DISK_ID_" + block,
							SourceType.IMPORTED);
				}
			}
		} catch (CodeUnitInsertionException ex) {
			throw new IOException("Could not define 64DD data structures", ex);
		}
	}
}