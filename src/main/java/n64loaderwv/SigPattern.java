package n64loaderwv;

public class SigPattern {
	
	public String name;
	public int[] pattern;
	public SigPattern(String n, String p) {
		name = n;
		pattern = new int[p.length() / 2];
		for(int i = 0; i < p.length() / 2; i ++)
		{
			int pos = i * 2;
			String sub = p.substring(pos, pos + 2);
			if(sub.equals("??"))
				pattern[i] = -1;
			else
				pattern[i] = Integer.parseInt(sub, 16);
		}
	}
	
	public Boolean Match(byte[] buff, int index)
	{			
		for(int i = 0; i < pattern.length; i++)
		{
			if(pattern[i] != -1 && (byte)pattern[i] != buff[i + index])
				return false;
		}
		return true;
	}
}
