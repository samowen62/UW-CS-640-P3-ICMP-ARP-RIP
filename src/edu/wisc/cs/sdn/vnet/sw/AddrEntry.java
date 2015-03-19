package edu.wisc.cs.sdn.vnet.sw;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.*;

public class AddrEntry
{
	public Iface intFace;
	public Long timeLeft;
	
	public AddrEntry(Iface i)
	{
		intFace = i;
		timeLeft = System.currentTimeMillis() + 15000;
	}


}
