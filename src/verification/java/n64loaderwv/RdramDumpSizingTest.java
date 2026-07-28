package n64loaderwv;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.Option;

public final class RdramDumpSizingTest {
	public static void main(String[] args) throws Exception {
		accepts(N64LoaderWVLoader.BASE_RDRAM_SIZE);
		accepts(N64LoaderWVLoader.EXPANDED_RDRAM_SIZE);
		rejects(0);
		rejects(N64LoaderWVLoader.BASE_RDRAM_SIZE - 1L);
		rejects(N64LoaderWVLoader.BASE_RDRAM_SIZE + 1L);
		rejects(N64LoaderWVLoader.EXPANDED_RDRAM_SIZE + 1L);
		checksHeadlessArguments();
	}

	private static void accepts(int length) throws IOException {
		if (N64LoaderWVLoader.checkedRdramDumpLength(length) != length)
			throw new AssertionError("accepted RDRAM size changed");
	}

	private static void rejects(long length) throws Exception {
		try {
			N64LoaderWVLoader.checkedRdramDumpLength(length);
			throw new AssertionError("accepted invalid RDRAM size " + length);
		} catch (IOException expected) {
			if (!expected.getMessage().contains("exactly 4 MiB or 8 MiB"))
				throw new AssertionError("unexpected error message", expected);
		}
	}

	private static void checksHeadlessArguments() {
		List<Option> options = new N64LoaderWVLoader().getDefaultOptions(null, null, null, false, false);
		String[] expected = {
			"-loader-signature", "-loader-modem", "-loader-pif", "-loader-rdram"
		};
		if (options.size() != expected.length)
			throw new AssertionError("unexpected loader option count");
		for (int index = 0; index < expected.length; index++) {
			if (!expected[index].equals(options.get(index).getArg()))
				throw new AssertionError("missing headless argument " + expected[index]);
		}
	}
}
