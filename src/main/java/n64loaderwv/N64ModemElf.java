package n64loaderwv;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class N64ModemElf {
	public record ElfSymbol(int tableIndex, int index, String name, long value, long size, int binding, int type,
			int other, int sectionIndex) {
		public long storageOffset(Module module) {
			if (name.isEmpty() || sectionIndex <= 0 || sectionIndex >= 0xFF00
					|| sectionIndex >= module.sections().size() || (type != 0 && type != 1 && type != 2))
				return -1;
			Section section = module.sections().get(sectionIndex);
			if (!section.hasFileBytes() || (section.flags() & 2) == 0 || (type == 2 && (section.flags() & 4) == 0)
					|| value >= section.size() || size > section.size() - value)
				return -1;
			return section.offset() + value;
		}
	}

	private static final int BANK_SIZE = 0x400000;
	private static final int SHT_NOBITS = 8;
	private static final int SHT_STRTAB = 3;

	public record Section(int index, String name, long type, long flags, long offset, long size, long link, long info,
			long alignment, long entrySize) {
		public boolean hasFileBytes() {
			return index != 0 && type != 0 && type != SHT_NOBITS && size != 0;
		}
	}

	public record Module(int romOffset, int extent, List<Section> sections) {
	}

	public record Scan(List<Module> modules, int rejected, boolean identicalMirror) {
	}

	private N64ModemElf() {
	}

	private static long u32(ByteBuffer b, int p) {
		return Integer.toUnsignedLong(b.getInt(p));
	}

	private static int u16(ByteBuffer b, int p) {
		return Short.toUnsignedInt(b.getShort(p));
	}

	private static void require(boolean ok, String message) throws IOException {
		if (!ok)
			throw new IOException(message);
	}

	private static boolean fits(long off, long len, long limit) {
		return off >= 0 && len >= 0 && off <= limit && len <= limit - off;
	}

	private static String readName(ByteBuffer b, long base, long size, long offset) throws IOException {
		require(offset < size, "Invalid ELF string offset");
		int start = (int) (base + offset);
		int end = start;
		int limit = (int) (base + size);
		while (end < limit && end - start < 4096 && b.get(end) != 0)
			end++;
		require(end < limit && b.get(end) == 0, "Invalid ELF string");
		byte[] bytes = new byte[end - start];
		b.get(start, bytes);
		return new String(bytes, StandardCharsets.ISO_8859_1);
	}

	private static Module parse(ByteBuffer b, int start, int end) throws IOException {
		int limit = end - start;
		require(limit >= 52, "Truncated ELF header");
		require(b.get(start + 4) == 1 && b.get(start + 5) == 2 && b.get(start + 6) == 1, "Not big-endian ELF32");
		require(u16(b, start + 16) == 1 && u16(b, start + 18) == 8 && u32(b, start + 20) == 1, "Not MIPS ET_REL");
		require(u32(b, start + 28) == 0 && u16(b, start + 44) == 0 && u16(b, start + 40) == 52
				&& u16(b, start + 46) == 40, "Unsupported ELF header layout");
		long shoff = u32(b, start + 32);
		int count = u16(b, start + 48);
		int names = u16(b, start + 50);
		require(count > 1 && count <= 4096 && names > 0 && names < count && shoff >= 52
				&& fits(shoff, 40L * count, limit), "Invalid section header table");
		int table = start + (int) shoff;
		int strings = table + 40 * names;
		long nameOff = u32(b, strings + 16);
		long nameSize = u32(b, strings + 20);
		require(u32(b, table + 4) == 0 && u32(b, strings + 4) == SHT_STRTAB && nameSize > 0
				&& fits(nameOff, nameSize, limit) && b.get(start + (int) nameOff) == 0
				&& b.get(start + (int) (nameOff + nameSize - 1)) == 0, "Invalid section name table");
		long extent = shoff + 40L * count;
		List<Section> sections = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			int p = table + 40 * i;
			long type = u32(b, p + 4);
			long offset = u32(b, p + 16);
			long size = u32(b, p + 20);
			if (i != 0 && type != SHT_NOBITS && type != 0 && size != 0) {
				require(fits(offset, size, limit), "Section outside ROM bank");
				extent = Math.max(extent, offset + size);
			}
			String name = readName(b, start + nameOff, nameSize, u32(b, p));
			sections.add(new Section(i, name, type, u32(b, p + 8), offset, size, u32(b, p + 24), u32(b, p + 28),
					u32(b, p + 32), u32(b, p + 36)));
		}
		return new Module(start, (int) extent, List.copyOf(sections));
	}

	public static Scan scan(byte[] data) {
		if (data.length != BANK_SIZE && data.length != BANK_SIZE * 2)
			throw new IllegalArgumentException("Expected 4 or 8 MiB modem ROM");
		boolean mirror = data.length == BANK_SIZE * 2
				&& Arrays.equals(data, 0, BANK_SIZE, data, BANK_SIZE, BANK_SIZE * 2);
		int limit = mirror ? BANK_SIZE : data.length;
		ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
		List<Module> modules = new ArrayList<>();
		int rejected = 0;
		for (int bank = 0; bank < limit; bank += BANK_SIZE) {
			int end = bank + BANK_SIZE;
			for (int p = bank; p <= end - 4; p++) {
				if (b.getInt(p) != 0x7F454C46)
					continue;
				try {
					Module m = parse(b, p, end);
					modules.add(m);
					p += m.extent() - 1;
				} catch (IOException ex) {
					rejected++;
				}
			}
		}
		return new Scan(List.copyOf(modules), rejected, mirror);
	}

	public record Relocation(int sectionIndex, int targetSectionIndex, int symbolTableIndex, int index, long offset,
			int type, ElfSymbol symbol) {
	}
}
