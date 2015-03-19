package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
//import edu.wisc.cs.sdn.vnet.LinkListQueue;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.MACAddress;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Queue;
import java.util.LinkedList;


/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	
	/** Hashmap of queues HOLY SHIT */
	private HashMap<Integer, Queue>  packetQueues; 

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.packetQueues = new HashMap<Integer, Queue>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleARPPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void sendError(Ethernet etherPacket, Iface inIface, int type, int code, boolean echo){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);	

		ether.setEtherType(Ethernet.TYPE_IPv4);
		IPv4 IpPacket = (IPv4)(etherPacket.getPayload());

		int payLoadLen = (int)(((IPv4)(etherPacket.getPayload())).getTotalLength());
		byte original[] = IpPacket.serialize();	
		byte dataBytes[] = new byte[4 + (echo ? payLoadLen : IpPacket.getHeaderLength() * 4 + 8)];

		System.out.println("echo: "+echo+ " lens: "+original.length+" | "+dataBytes.length);
	
		for( int i = 0; i < (echo ? payLoadLen : (IpPacket.getHeaderLength() * 4 + 8)); i++)
			dataBytes[i + 4] = original[i];
		data.setData(dataBytes);
		
		byte d = 64;
		ip.setTtl(d);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		//ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(((IPv4)(etherPacket.getPayload())).getSourceAddress());

		icmp.setIcmpType((byte)type);
		icmp.setIcmpCode((byte)code);
	
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getSourceAddress();
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
		if (null == bestMatch)
		{ return; }
		// Make sure we don't sent a packet back out the interface it came in
        	Iface outIface = bestMatch.getInterface();
        	//if (outIface == inIface)
        	//{ return; }
		ip.setSourceAddress(echo ? ipPacket.getDestinationAddress() : outIface.getIpAddress());

        	// Set source MAC address in Ethernet header
        	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		
        	// If no gateway, then nextHop is IP destination
        	int nextHop = bestMatch.getGatewayAddress();
        	if (0 == nextHop)
        	{ nextHop = dstAddr; }

        	// Set destination MAC address in Ethernet header
        	ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        	if (null == arpEntry)
        	{ return; }
        	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		//System.out.println("ether src: "+outIface.getMacAddress().toBytes()+"ether dest: "+arpEntry.getMac().toBytes());
		//System.out.println("ether src: "+ip.getSourceAddress()+"ip dest: "+ip.getDestinationAddress()); 
		System.out.println("sent packet:" + ether);
        	this.sendPacket(ether, outIface);
	}

	private void handleARPPacket(Ethernet etherPacket, Iface inIface)
	{
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
                {
                                return;
                }

                // Get IP header
                ARP arpPacket = (ARP)etherPacket.getPayload();
        	System.out.println("Handle ARP packet");

		if(arpPacket.getOpCode() != ARP.OP_REQUEST){
			if(arpPacket.getOpCode() == ARP.OP_REPLY){
				ByteBuffer senderProtocol = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress());
				arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), senderProtocol.getInt());					
				
				Queue packetsToSend = packetQueues.get(new Integer(senderProtocol.getInt()));
				while(packetsToSend != null && packetsToSend.peek() != null){
					Ethernet packet = (Ethernet)packetsToSend.poll();
					packet.setDestinationMACAddress(arpPacket.getSenderHardwareAddress());
					this.sendPacket(packet, inIface);
				}

			}else
				return;
		}

		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
        	if (targetIp != inIface.getIpAddress())
			return;

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());	
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

		ether.setPayload(arp);
        	
		this.sendPacket(ether, inIface);
		return;
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ 
				return; 
		}
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        {
		this.sendError(etherPacket, inIface, 11, 0, false);
		return; 
	}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ 
			byte protocol = ipPacket.getProtocol();
			if(protocol == IPv4.PROTOCOL_UDP || protocol == IPv4.PROTOCOL_TCP)
				this.sendError(etherPacket, inIface, 11, 3, false);
			else if(protocol == IPv4.PROTOCOL_ICMP){
				ICMP icmp = (ICMP)ipPacket.getPayload();
				if(icmp.getIcmpType() == 8)
					this.sendError(etherPacket, inIface, 0, 0, true);
			}
			return; 
		}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        { 
		this.sendError(etherPacket, inIface, 3, 0, false);
		return; 
	}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { 
		ARP arp = new ARP();
                arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
                arp.setProtocolType(ARP.PROTO_TYPE_IP);
                arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
                arp.setProtocolAddressLength((byte)4);
                arp.setOpCode(ARP.OP_REQUEST);
                arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
                arp.setSenderProtocolAddress(inIface.getIpAddress());
                arp.setTargetHardwareAddress(null);
                arp.setTargetProtocolAddress(nextHop);

                etherPacket.setPayload(arp);
		etherPacket.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");	

		Integer next = new Integer(nextHop);

		if(!packetQueues.containsKey(next)){
			packetQueues.put(next, new LinkedList());
		}	
		Queue nextHopQueue = packetQueues.get(next);
		nextHopQueue.offer(etherPacket);
		//return; 
	}
	else //added
        	etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
