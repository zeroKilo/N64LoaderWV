package n64loaderwv;

import java.io.IOException;

public final class N64DDDisk {

	public static final int SYSTEM_BLOCKS = 24;
	public static final int USER_BLOCKS = 4292;
	public static final int IMAGE_BLOCKS = SYSTEM_BLOCKS + USER_BLOCKS;
	public static final int MAX_RDRAM_SIZE = 8 * 1024 * 1024;
	private static final int[] BLOCK_BYTES = { 19720, 18360, 17680, 16320, 14960, 13600, 12240, 10880, 9520 };
	private static final int[] HEAD0_BLOCKS = { 268, 292, 274, 274, 274, 274, 274, 204, 0 };
	private static final int[] HEAD1_BLOCKS = { 0, 292, 292, 274, 274, 274, 274, 274, 204 };
	private static final int[] RAM_START_LBA = { 0x58A, 0x7AE, 0x9D2, 0xBF6, 0xE1A, 0xFF8, 0x10C4 };

	private final N64DDHeader header;
	private final N64DDPhysical physical;

	private final long[] offsets = new long[IMAGE_BLOCKS + 1];
	private int nextBlock;

	public N64DDDisk(N64DDHeader header) {
		if (header == null || header.diskType < 0 || header.diskType > 6)
			throw new IllegalArgumentException("Unsupported NDD disk type");
		this.header = header;
		appendBlocks(SYSTEM_BLOCKS, BLOCK_BYTES[0]);
		int lastRomZone = header.diskType + 2;
		appendZones(HEAD0_BLOCKS, 0, Math.min(lastRomZone, 7), 1);
		appendZones(HEAD1_BLOCKS, lastRomZone, 1, -1);
		appendZones(HEAD0_BLOCKS, lastRomZone + 1, 7, 1);
		appendZones(HEAD1_BLOCKS, 8, lastRomZone + 1, -1);
		if (nextBlock != IMAGE_BLOCKS || offsets[nextBlock] != N64DDHeader.IMAGE_SIZE)
			throw new IllegalStateException("NDD geometry does not cover the image");
		if (header.format == N64DDHeader.Format.D64)
			validateD64();
		physical = header.format == N64DDHeader.Format.MAME ? new N64DDPhysical(header) : null;
	}

	private void appendZones(int[] counts, int first, int last, int step) {
		for (int zone = first; step > 0 ? zone <= last : zone >= last; zone += step)
			appendBlocks(counts[zone], BLOCK_BYTES[zone]);
	}

	private void appendBlocks(int count, int size) {
		for (int i = 0; i < count; i++) {
			offsets[nextBlock + 1] = offsets[nextBlock] + size;
			nextBlock++;
		}
	}

	public long getImageBlockOffset(int block) {
		if (block < 0 || block >= IMAGE_BLOCKS)
			throw new IndexOutOfBoundsException("Invalid NDD image block: " + block);
		if (physical != null)
			return physical.getBlockOffset(block);
		return offsets[block];
	}

	public long getLbaOffset(int lba) {
		if (lba < 0 || lba >= USER_BLOCKS)
			throw new IndexOutOfBoundsException("Invalid user LBA: " + lba);
		if (header.format == N64DDHeader.Format.D64) {
			long dataOffset = N64DDHeader.D64_DATA_OFFSET;
			if (lba <= header.romEndLba)
				return dataOffset + getLbaRangeSize(0, lba);
			if (lba >= header.ramStartLba && lba <= header.ramEndLba) {
				long romSize = getLbaRangeSize(0, header.romEndLba + 1);
				return dataOffset + romSize + getLbaRangeSize(header.ramStartLba, lba - header.ramStartLba);
			}
			throw new IndexOutOfBoundsException("LBA not stored in D64 image: " + lba);
		}
		if (physical != null)
			return physical.getBlockOffset(SYSTEM_BLOCKS + lba);
		return offsets[SYSTEM_BLOCKS + lba];
	}

	public int getLbaSize(int lba) {
		if (lba < 0 || lba >= USER_BLOCKS)
			throw new IndexOutOfBoundsException("Invalid user LBA: " + lba);
		int index = SYSTEM_BLOCKS + lba;
		return (int) (offsets[index + 1] - offsets[index]);
	}

	public long getLbaRangeSize(int firstLba, int count) {
		if (firstLba < 0 || firstLba > USER_BLOCKS || count < 0 || count > USER_BLOCKS - firstLba)
			throw new IndexOutOfBoundsException("Invalid user LBA range");
		int first = SYSTEM_BLOCKS + firstLba;
		return offsets[first + count] - offsets[first];
	}

	public BootRange getBootRange() throws IOException {
		int count = header.iplLoadBlocks;
		if (header.format == N64DDHeader.Format.D64 && count > header.romEndLba + 1)
			throw new IOException("IPL load range exceeds stored D64 ROM area");
		if (count <= 0 || count > USER_BLOCKS)
			throw new IOException("Invalid IPL load block count: " + count);
		long length = getLbaRangeSize(0, count);
		long address = header.iplLoadAddress;
		long physicalAddress;
		if (address >= 0x80000000L && address < 0x80000000L + MAX_RDRAM_SIZE)
			physicalAddress = address - 0x80000000L;
		else if (address >= 0xA0000000L && address < 0xA0000000L + MAX_RDRAM_SIZE)
			physicalAddress = address - 0xA0000000L;
		else
			throw new IOException(String.format("Unsupported IPL load address: 0x%08X", address));
		if ((address & 3) != 0 || length > MAX_RDRAM_SIZE - physicalAddress)
			throw new IOException("IPL load range is unaligned or exceeds RDRAM");
		return new BootRange(getLbaOffset(0), (int) length, address);
	}

	private void validateD64() {
		int romEnd = header.romEndLba;
		int ramStart = header.ramStartLba;
		int ramEnd = header.ramEndLba;
		int firstRam = RAM_START_LBA[header.diskType];
		if (romEnd < 0 || romEnd >= firstRam)
			throw new IllegalArgumentException("Invalid D64 ROM area");
		long expectedSize = N64DDHeader.D64_DATA_OFFSET + getLbaRangeSize(0, romEnd + 1);
		boolean noRam = ramStart == 0xFFFF && ramEnd == 0xFFFF;
		if (!noRam) {
			if (header.diskType == 6 || ramStart < firstRam || ramEnd < ramStart || ramEnd >= USER_BLOCKS)
				throw new IllegalArgumentException("Invalid D64 RAM area");
			expectedSize += getLbaRangeSize(ramStart, ramEnd - ramStart + 1);
		}
		if (header.imageSize != expectedSize)
			throw new IllegalArgumentException(
					String.format("Invalid D64 size: expected 0x%X, got 0x%X", expectedSize, header.imageSize));
	}

	public static final class BootRange {
		public final long fileOffset;
		public final int byteCount;
		public final long loadAddress;

		private BootRange(long fileOffset, int byteCount, long loadAddress) {
			this.fileOffset = fileOffset;
			this.byteCount = byteCount;
			this.loadAddress = loadAddress;
		}
	}
}