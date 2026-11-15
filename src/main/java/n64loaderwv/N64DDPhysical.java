package n64loaderwv;
public final class N64DDPhysical {
	
	private static final int[] SECTOR_BYTES = { 232, 216, 208, 192, 176, 160, 144, 128, 112 };
	private static final int[] TRACK_COUNTS = { 158, 158, 149, 149, 149, 149, 149, 114 };
	private static final int SECTORS_PER_BLOCK = 85;
	private static final int DEFECT_TRACKS = 12;
	private final long[] blockOffsets = new long[N64DDDisk.IMAGE_BLOCKS];
	private final long[] zoneOffsets = new long[16];
	private final byte[] system;
	private int nextBlock;
	
	public N64DDPhysical(N64DDHeader header) {
		if (header.format != N64DDHeader.Format.MAME)
			throw new IllegalArgumentException("Not a MAME disk image");
		if (header.development)
			throw new IllegalArgumentException("Physical development disks not yet supported");
		system = header.getSystemSector();
		long offset = 0;
		for (int zone = 0; zone < 16; zone++) {
			zoneOffsets[zone] = offset;
			offset += (long) getTrackCount(zone) * getBlockSize(zone) * 2;
		}
		if (offset != N64DDHeader.MAME_IMAGE_SIZE)
			throw new IllegalStateException("Invalid physical disk geometry");
		int lastRomZone = header.diskType + 2;
		for (int z = 0; z <= Math.min(lastRomZone, 7); z++)
			appendZone(z);
		for (int z = lastRomZone; z >= 1; z--)
			appendZone(z + 7);
		for (int z = lastRomZone + 1; z <= 7; z++)
			appendZone(z);
		for (int z = 8; z > lastRomZone; z--)
			appendZone(z + 7);
		if (nextBlock != blockOffsets.length)
			throw new IllegalStateException("Incomplete physical disk mapping");
	}
	
	private int getTrackCount(int zone) {
		return TRACK_COUNTS[zone % 8];
	}
	
	private int getBlockSize(int zone) {
		int sizeIndex = zone < 8 ? zone : zone - 7;
		return SECTOR_BYTES[sizeIndex] * SECTORS_PER_BLOCK;
	}
	
	private boolean[] getDefectiveTracks(int zone) {
		int start = zone == 0 ? 0 : Byte.toUnsignedInt(system[0x08 + zone - 1]);
		int end = Byte.toUnsignedInt(system[0x08 + zone]);
		if (end - start != DEFECT_TRACKS || end > system.length - 0x20)
			throw new IllegalArgumentException("Invalid defect table for zone " + zone);
		boolean[] defective = new boolean[getTrackCount(zone)];
		int previous = -1;
		for (int i = start; i < end; i++) {
			int track = Byte.toUnsignedInt(system[0x20 + i]);
			if (track >= defective.length || track <= previous)
				throw new IllegalArgumentException("Invalid defect track in zone " + zone);
			defective[track] = true;
			previous = track;
		}
		return defective;
	}
	
	private void appendZone(int zone) {
		boolean[] defective = getDefectiveTracks(zone);
		int tracks = getTrackCount(zone);
		int blockSize = getBlockSize(zone);
		boolean reverse = zone >= 8;
		for (int i = 0; i < tracks; i++) {
			int track = reverse ? tracks - 1 - i : i;
			if (defective[track])
				continue;
			long trackOffset = zoneOffsets[zone] + (long) track * blockSize * 2;
			boolean swapped = (nextBlock & 2) != 0;
			blockOffsets[nextBlock++] = trackOffset + (swapped ? blockSize : 0);
			blockOffsets[nextBlock++] = trackOffset + (swapped ? 0 : blockSize);
		}
	}
	
	public long getBlockOffset(int imageBlock) {
		if (imageBlock < 0 || imageBlock >= blockOffsets.length)
			throw new IndexOutOfBoundsException("Invalid disk block: " + imageBlock);
		return blockOffsets[imageBlock];
	}
}