package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.IPv4;
import edu.wisc.cs.sdn.vnet.Iface;

import java.util.Timer;
import java.util.TimerTask;

/**
 * An entry in a route table.
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class RouteEntry 
{
	/** Destination IP address */
	private int destinationAddress;
	
	/** Gateway IP address */
	private int gatewayAddress;
	
	/** Subnet mask */
	private int maskAddress;
	
	/** Router interface out which packets should be sent to reach
	 * the destination or gateway */
	private Iface iface;
	
	private RouteTable parent;
	private Timer timer;
	private int cost;

	/**
	 * Create a new route table entry.
	 * @param destinationAddress destination IP address
	 * @param gatewayAddress gateway IP address
	 * @param maskAddress subnet mask
	 * @param iface the router interface out which packets should 
	 *        be sent to reach the destination or gateway
	 */
	public RouteEntry(int destinationAddress, int gatewayAddress, 
			int maskAddress, Iface iface)
	{
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.iface = iface;
	}
	
	/**
	 * @return destination IP address
	 */
	public int getDestinationAddress()
	{ return this.destinationAddress; }
	
	/**
	 * @return gateway IP address
	 */
	public int getGatewayAddress()
	{ return this.gatewayAddress; }

    public void setGatewayAddress(int gatewayAddress)
    { this.gatewayAddress = gatewayAddress; }
	
	/**
	 * @return subnet mask 
	 */
	public int getMaskAddress()
	{ return this.maskAddress; }
	
	/**
	 * @return the router interface out which packets should be sent to 
	 *         reach the destination or gateway
	 */
	public Iface getInterface()
	{ return this.iface; }

	public RouteTable getParent()
	{ return this.parent; }
	
	public void setParent(RouteTable parent)
	{ this.parent = parent; }
	
	public int getCost()
	{ return this.cost; }
	
	public void setCost(int cost)
	{ this.cost = cost; }

    public void setInterface(Iface iface)
    { this.iface = iface; }
	
	public void start()
	{
		this.timer = new Timer();
		this.timer.schedule(new removeTiming(), 10000);
	}
	
	/**
	 * Starts the deletion timer back at 30 seconds
	 */
	public void reset()
	{
		this.timer.cancel();
		this.timer.purge();
		this.timer = new Timer();
		this.timer.schedule(new removeTiming(), 30000);
	}
	
	/**
	 * Deletes self from parent list
	 */
	public void timedRemove()
	{
		parent.remove(this.getDestinationAddress(), this.getMaskAddress());
	}
	
	/**
	 * Deletes self from parent list if 30 seconds pass
	 */
    	class removeTiming extends TimerTask
    	{
		public void run()
		{
			timedRemove();
		}
	}

	public String toString()
	{
		return String.format("%s \t%s \t%s \t%s",
				IPv4.fromIPv4Address(this.destinationAddress),
				IPv4.fromIPv4Address(this.gatewayAddress),
				IPv4.fromIPv4Address(this.maskAddress),
				this.iface.getName());
	}

	
}
