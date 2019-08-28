package n64loaderwv;

public class PATLine {
	
	public String raw;
	public String startPattern;
	public String symbol;
	public int[] pattern;
	public PATLine(String s) {
		raw = s;
		startPattern = s.substring(0, 64);
		pattern = new int[32];
		for(int i=0; i<32; i++)
		{
			String sub = startPattern.substring(i * 2, i * 2 + 2);
			if(sub.equals(".."))
				pattern[i] = -1;
			else
				pattern[i] = Integer.parseInt(sub, 16);
		}
		
		String[] parts = s.split(" ");
		if(parts.length > 7)
			symbol = parts[7];
		else
			symbol = parts[5];
	}
	
	public Boolean Match(byte[] buff, int index)
	{			
		for(int i = 0; i < 32; i++)
			if(pattern[i] != -1 && pattern[i] != buff[i + index])
				return false;
		return true;
	}
}
