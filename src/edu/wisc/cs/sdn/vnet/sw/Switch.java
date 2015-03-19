package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	//the table of mac addrs with their interface and timeouts
	Map<MACAddress, AddrEntry> table;

	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		table = new HashMap<MACAddress, AddrEntry>();
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		//System.out.println("*** -> Received packet: " +
                //etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		/********************************************************************/
	
		MACAddress src = etherPacket.getSourceMAC();
		MACAddress dst = etherPacket.getDestinationMAC();
		System.out.println("src: "+src+" dst: "+dst);

		if(!table.containsKey(src)){
			table.put(src, new AddrEntry(inIface));
		} 
		else{
			AddrEntry source = table.get(src);
			System.out.println("Elapsed time for source "+src+" : "+(source.timeLeft - System.currentTimeMillis())+" ms");
		}
		if(table.containsKey(dst)){
			AddrEntry dest = table.get(dst);
			if(dest.timeLeft <= System.currentTimeMillis()){
				table.remove(dst);
				for(Map.Entry<String, Iface> intface: getInterfaces().entrySet()) {
					if(intface.getValue() != inIface) {
						sendPacket(etherPacket, intface.getValue());
					}
				}
			}
			else{
				sendPacket(etherPacket, dest.intFace);
			}
		}
		else{
			for(Map.Entry<String, Iface> intface: getInterfaces().entrySet()) {
                                if(intface.getValue() != inIface) {
                                        sendPacket(etherPacket, intface.getValue());
                                }
                        }
		}
	}
}
