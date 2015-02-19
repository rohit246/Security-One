/* 
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details. 
 */
package report;

/*import core.ConnectionListener;
import core.Connection;
import core.DTNHost;
import core.Message;
import core.MessageListener;
import input.StandardEventsReader;
import core.Connection;
import core.SimClock;*/
import core.*;
import input.StandardEventsReader;

import java.util.*;

/**
 * Report that creates same output as the GUI's event log panel but formatted
 * like {@link input.StandardEventsReader} input. Message relying event has
 * extra one-letter identifier to tell whether that message was delivered to
 * final destination, delivered there again, or just normally relayed 
 * (see the public constants).
 */
public class MaliciousDetectDataReport extends Report 
	implements ConnectionListener, MessageListener {

	/** Extra info for message relayed event ("relayed"): {@value} */
	public static final String MESSAGE_TRANS_RELAYED = "R";
	/** Extra info for message relayed event ("delivered"): {@value} */
	public static final String MESSAGE_TRANS_DELIVERED = "D";
	/** Extra info for message relayed event ("delivered again"): {@value} */
	public static final String MESSAGE_TRANS_DELIVERED_AGAIN = "A";
	
	//public static int sprayMaliciousIncreased = false;
	
	private int malnodes = 0;
	private int checkH1 = 0;
	private int checkH2 = 0;
	private String msg;
	private int chk = 0;
	private int chk1 = 0;
	private int chk3 = 0;
	private int mal = 0;
	private int cnt;
	private int size;
	private double time1,time2,time3,tt,occ;
	private DTNHost malDetected[] = new DTNHost[150];
	private ArrayList<DTNHost> allMalNodes = new ArrayList<DTNHost>();
	Message MSG;
	
	
	/**
	 * Processes a log event by writing a line to the report file
	 * @param action The action as a string
	 * @param host1 First host involved in the event (if any, or null)
	 * @param host2 Second host involved in the event (if any, or null)
	 * @param message The message involved in the event (if any, or null)
	 * @param extra Extra info to append in the end of line (if any, or null)
	 */
	private void processEvent(final String action, final DTNHost host1, 
			final DTNHost host2, final Message message, final String extra) {
			
			boolean flag;
		
		if(host1!=null){
			for(int i = 0; i < host1.detectedNodes.size(); i++){
				if(!allMalNodes.contains(host1.detectedNodes.get(i))){
					allMalNodes.add(host1.detectedNodes.get(i));
					malnodes++;
					/**Overhead */
					host1.msg_overhead++;
					//System.out.println(SimClock.getTime() + "\t"+ host1.msg_overhead + "\t" + host1.detectedNodes.get(i).toString() + "\tMalNode Info Transfer between\t" + host1.toString() + " " + host2.toString());
					
					write((float)getSimTime() + "\t\t" + host1.detectedNodes.get(i)
					+ "\t\t" + (this.malnodes));
				}
			}
		}
		
		if(host2!=null){
			for(int j = 0; j < host2.detectedNodes.size(); j++){
				if(!allMalNodes.contains(host2.detectedNodes.get(j))){
					allMalNodes.add(host2.detectedNodes.get(j));
					malnodes++;
					
					/**Overhead */
					host2.msg_overhead++;
					System.out.println(SimClock.getTime() + "\t"+ host1.msg_overhead + "\t" + host2.detectedNodes.get(j).toString() + "\tMalNode Info Transfer between\t" + host1.toString() + " " + host2.toString());
					
					write((float)getSimTime() + "\t\t" + host2.detectedNodes.get(j)
					+ "\t\t" + (this.malnodes));
				}
			}
		}
	}
	
	public void hostsConnected(DTNHost host1, DTNHost host2, Connection con) {
		SimClock time = new SimClock();
		con.conup = time.getTime();
		this.time1 = con.conup;
		
		processEvent(StandardEventsReader.CONNECTION, host1, host2, null,
				StandardEventsReader.CONNECTION_UP);
	}

	public void hostsDisconnected(DTNHost host1, DTNHost host2, Connection con) {
		
		//for spray phase
		double transmit;
		SimClock time1 = new SimClock();
		double condown = time1.getTime();
		con.contime = condown - con.conup;
		this.time2 = condown;
		this.time3 = con.contime;
		Message msg1 = null;
		int st_size = host2.spray_table.size();
		if(host2.malnode_spray == 1 && st_size > 0
                        && MaliciousDecisionEngine.DecideMaliciousness(DTNHost.malPercentSpray)){
			msg1 = host2.spray_table.get(st_size - 1).msg;
			
			//host2.spray_table_msgsize[host2.rowcount] = 0;
		}
		//msg1 = host2.spray_table_msg[host2.rowcount];
		if(msg1 != null){
			//this.chk1++;
			this.msg = msg1.ID;
			transmit = msg1.size/(250000);
			this.size = msg1.size;
			this.cnt = host2.spray_table.get(st_size - 1).msgsize ;
			if(this.cnt > 0 && transmit < con.contime && msg1.getTtl() > 0 && host1.ferry == 1){
			
				if(!host1.detectedNodes.contains(host2)){
					host1.detectedNodes.add(host2);
				}
				this.mal = host2.mal_cnt;
			}
			maliciousadd(host1);
			
			/**Overhead*/
			if(this.cnt > 0 && host1.ferry == 1){
				host1.msg_overhead+=host2.rowcount;
				System.out.println(SimClock.getTime() + "\t"+ host1.msg_overhead + "\t" + msg1.getId() + "\tMessage Info Transfer between\t" + host1.toString() + " and " + host2.toString());
			}
		}
		
		//for focus phase
		SimClock time = new SimClock();
		int brktime = time.getIntTime();
		host1.tau_brk[host2.nodenumber] = brktime;
		host2.tau_brk[host1.nodenumber] = brktime;
		
		if(host2.ferry != 1){
			String H=host1.toString()+host2.toString();
			String G=host2.toString()+host1.toString();
			host2.LT.put(H,brktime);
			host2.LT.put(G,brktime);
			if(host1.ferry != 1){
				host1.LT.put(H,brktime);
				host1.LT.put(G,brktime);
			
			}
		}
		
		//int tmp = host1.msg_overhead;
		if(host1.detectedNodes.size() > 0){
			//System.out.println(host1.detectedNodes.size() + " " + host2.detectedNodes.size());
		
			if(!host1.informedNodes.contains(host2)){
				host1.informedNodes.add(host2);
				host1.msg_overhead+=host1.detectedNodes.size();
				if(host1.detectedNodes.size() > 0){
					System.out.println(SimClock.getTime() + "\t"+ 
										host1.msg_overhead + 
										"\tMalNode Info Transfer between\t" + 
										host1.toString() + " " 
										+ host2.toString()
										);
				}
			}
			if(!host2.informedNodes.contains(host1)){
				host2.informedNodes.add(host1);
				host2.msg_overhead+=host2.detectedNodes.size();
				if(host1.detectedNodes.size() > 0){
					System.out.println(SimClock.getTime() + "\t"+ 
										host1.msg_overhead + 
										"\tMalNode Info Transfer between\t" + 
										host1.toString() + " " 
										+ host2.toString()
										);
				}
			}
		}
		processEvent(StandardEventsReader.CONNECTION, host1, host2, null,
				StandardEventsReader.CONNECTION_DOWN);
	}
	
	public void maliciousadd(DTNHost from)
	{
		for(Connection c : from.router.getConnections())
		{
			int i,j,chk, test1 = 0, test2 = 0;
			DTNHost other = c.getOtherNode(from.router.getHost());
			
			
			if(!from.detectedNodes.contains(other)){
				for(i = 0; i<from.detectedNodes.size(); i++){
					if(!other.detectedNodes.contains(from.detectedNodes.get(i))){
						other.maloverhead++;
						other.detectedNodes.add(from.detectedNodes.get(i));
						
						/**Overhead */
						other.msg_overhead++;
						System.out.println(SimClock.getTime() + "\t"+ other.msg_overhead + "\t" + from.detectedNodes.get(i).toString() + "\tMalNode Info Transfer between\t" + from.toString() + " " + other.toString());
					}
				}
			}
			
			if(!other.detectedNodes.contains(from)){
				for(i = 0; i<other.detectedNodes.size(); i++){
					if(!from.detectedNodes.contains(other.detectedNodes.get(i))){
						from.maloverhead++;
						from.detectedNodes.add(other.detectedNodes.get(i));
						
						/**Overhead */
						from.msg_overhead++;
						System.out.println(SimClock.getTime() + "\t"+ from.msg_overhead + "\t" + other.detectedNodes.get(i).toString() + "\tMalNode Info Transfer between\t" + from.toString() + " " + other.toString());
					}
				}
			}
			
		}
	}
	
	public void messageDeleted(Message m, DTNHost where, boolean dropped) {
	//	this.MSG = m;
		processEvent((dropped ? StandardEventsReader.DROP : 
			StandardEventsReader.REMOVE), where, null, m, null);
	}

	public void messageTransferred(Message m, DTNHost from, DTNHost to,
			boolean firstDelivery) {
		String extra;
		if (firstDelivery) {
			extra = MESSAGE_TRANS_DELIVERED;
		}
		else if (to == m.getTo()) {
			extra = MESSAGE_TRANS_DELIVERED_AGAIN;
		}
		else {
			extra = MESSAGE_TRANS_RELAYED;
		}
		
		processEvent(StandardEventsReader.DELIVERED, from, to, m, extra);
	}

	public void newMessage(Message m) {
		processEvent(StandardEventsReader.CREATE, m.getFrom(), null, m, null);
	}
	
	public void messageTransferAborted(Message m, DTNHost from, DTNHost to) {
		processEvent(StandardEventsReader.ABORT, from, to, m, null);
	}
	
	public void messageTransferStarted(Message m, DTNHost from, DTNHost to) {
		processEvent(StandardEventsReader.SEND, from, to, m, null);		
	}
}
