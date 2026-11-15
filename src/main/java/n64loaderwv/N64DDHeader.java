package n64loaderwv;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public final class N64DDHeader {

	public enum Format {
		NDD, D64, MAME
	}

	public static final long IMAGE_SIZE = 0x3DEC800L;
	public static final int SECTOR_SIZE = 232;
	public static final int DEV_SECTOR_SIZE = 192;
	public static final int SYSTEM_BLOCK_SIZE = SECTOR_SIZE * 85;
	public static final int PREFIX_SIZE = SYSTEM_BLOCK_SIZE * 12;
	public static final int D64_DATA_OFFSET = 0x200;
	private static final int[] RETAIL_BLOCKS = { 0, 1, 8, 9 };
	private static final int[] DEV_BLOCKS = { 2, 3, 10, 11 };
	public static final long MAME_IMAGE_SIZE = 0x435B0C0L;

	private final byte[] systemSector;
	public final Format format;
	public final boolean development;
	public final long imageSize;
	public final long headerOffset;
	public final long region;
	public final int formatType;
	public final int diskTypeByte;
	public final int diskType;
	public final int iplLoadBlocks;
	public final long iplLoadAddress;
	public final int romEndLba;
	public final int ramStartLba;
	public final int ramEndLba;
	public final int matchingCopies;

	private N64DDHeader(byte[] sector, Format format, boolean development, long imageSize, long headerOffset,
			int copies) {
		ByteBuffer b = ByteBuffer.wrap(sector).order(ByteOrder.BIG_ENDIAN);
		this.format = format;
		this.development = development;
		this.imageSize = imageSize;
		this.headerOffset = headerOffset;
		this.systemSector = sector.clone();
		region = Integer.toUnsignedLong(b.getInt(0));
		formatType = Byte.toUnsignedInt(b.get(4));
		diskTypeByte = Byte.toUnsignedInt(b.get(5));
		diskType = diskTypeByte & 0x0F;
		iplLoadBlocks = Short.toUnsignedInt(b.getShort(6));
		iplLoadAddress = Integer.toUnsignedLong(b.getInt(0x1C));
		if (sector.length >= 0xE6) {
			romEndLba = Short.toUnsignedInt(b.getShort(0xE0));
			ramStartLba = Short.toUnsignedInt(b.getShort(0xE2));
			ramEndLba = Short.toUnsignedInt(b.getShort(0xE4));
		} else {
			romEndLba = -1;
			ramStartLba = -1;
			ramEndLba = -1;
		}
		matchingCopies = copies;
	}

	public static N64DDHeader parse(byte[] prefix, long imageSize) throws IOException {
		if (prefix == null)
			throw new IOException("Missing disk header");
		if (imageSize == IMAGE_SIZE || imageSize == MAME_IMAGE_SIZE) {
			if (prefix.length < PREFIX_SIZE)
				throw new IOException("Incomplete NDD system area");
			N64DDHeader retail = parseRepeated(prefix, imageSize, false);
			N64DDHeader dev = parseRepeated(prefix, imageSize, true);
			if (retail != null && dev != null)
				throw new IOException("Ambiguous disk system data");
			if (retail != null)
				return retail;
			if (dev != null)
				return dev;
			throw new IOException("No valid NDD system header");
		}
		if (imageSize > D64_DATA_OFFSET && imageSize < IMAGE_SIZE && prefix.length >= D64_DATA_OFFSET) {
			N64DDHeader h = new N64DDHeader(Arrays.copyOf(prefix, SECTOR_SIZE), Format.D64, false, imageSize, 0, 1);
			if (h.region == 0 && (h.formatType == 0 || h.formatType == 0x10)
					&& ((h.diskTypeByte & 0xF0) == 0 || (h.diskTypeByte & 0xF0) == 0x10) && h.plausibleBoot()) {
				return h;
			}
		}
		throw new IOException("Unsupported 64DD disk image");
	}

	private static N64DDHeader parseRepeated(byte[] prefix, long imageSize, boolean development) throws IOException {
		Format format = imageSize == MAME_IMAGE_SIZE ? Format.MAME : Format.NDD;
		int[] blocks = development ? DEV_BLOCKS : RETAIL_BLOCKS;
		int sectorSize = development ? DEV_SECTOR_SIZE : SECTOR_SIZE;
		byte[] accepted = null;
		long acceptedOffset = 0;
		int copies = 0;
		for (int block : blocks) {
			int start = block * SYSTEM_BLOCK_SIZE;
			byte[] sector = Arrays.copyOfRange(prefix, start, start + sectorSize);
			boolean repeated = true;
			for (int i = sectorSize; i < sectorSize * 85; i++) {
				if (prefix[start + i] != sector[i % sectorSize]) {
					repeated = false;
					break;
				}
			}
			if (!repeated)
				continue;
			N64DDHeader h = new N64DDHeader(sector, format, development, imageSize, start, 1);
			boolean validRegion = development ? h.region == 0 : h.region == 0xE848D316L || h.region == 0x2263EE56L;
			if (!validRegion || h.formatType != 0x10 || (h.diskTypeByte & 0xF0) != 0x10 || !h.plausibleBoot())
				continue;
			if (accepted != null && !Arrays.equals(accepted, sector))
				throw new IOException("Conflicting NDD system headers");
			if (accepted == null) {
				accepted = sector;
				acceptedOffset = start;
			}
			copies++;
		}
		if (copies < 2)
			return null;
		return new N64DDHeader(accepted, format, development, imageSize, acceptedOffset, copies);
	}

	private boolean plausibleBoot() {
		long segment = iplLoadAddress & 0xE0000000L;
		long physical = iplLoadAddress & 0x1FFFFFFFL;
		return diskType <= 6 && iplLoadBlocks > 0 && iplLoadBlocks <= 4292
				&& (segment == 0x80000000L || segment == 0xA0000000L) && physical < 0x800000L
				&& (iplLoadAddress & 3) == 0;
	}

	public byte[] getSystemSector() {
		return systemSector.clone();
	}

	@Override
	public String toString() {
		String result = String.format(
				"Image format=%s%n" + "Region=0x%08X format=0x%02X " + "diskType=%d (0x%02X)%n"
						+ "IPL blocks=%d loadAddress=0x%08X%n" + "System header offset=0x%X",
				format, region, formatType, diskType, diskTypeByte, iplLoadBlocks, iplLoadAddress, headerOffset);
		if (romEndLba >= 0) {
			result += String.format("%nROM end LBA=0x%04X " + "RAM start LBA=0x%04X " + "RAM end LBA=0x%04X", romEndLba,
					ramStartLba, ramEndLba);
		}
		if (format != Format.D64) {
			result += String.format("%nDevelopment disk=%s" + "%nMatching system header copies=%d/4", development,
					matchingCopies);
		} else {
			result += "\nMaster disk image; " + "physical disk region unknown";
		}
		return result;
	}
}