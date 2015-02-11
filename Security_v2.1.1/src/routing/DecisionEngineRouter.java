package routing;

import java.util.*;

import core.*;

/**
 * This class overrides ActiveRouter in order to inject calls to a 
 * DecisionEngine object where needed add extract as much code from the update()
 * method as possible. 
 * 
 * <strong>Forwarding Logic:</strong> 
 * 
 * A DecisionEngineRouter maintains a List of Tuple<Message, Connection> in 
 * support of a call to ActiveRouter.tryMessagesForConnected() in 
 * DecisionEngineRouter.update(). Since update() is called so frequently, we'd 
 * like as little computation done in it as possible; hence the List that gets
 * updated when events happen. Four events cause the List to be updated: a new 
 * message from this host, a new received message, a connection goes up, or a 
 * connection goes down. On a new message (either from this host or received 
 * from a peer), the collection of open connections is examined to see if the
 * message should be forwarded along them. If so, a new Tuple is added to the
 * List. When a connection goes up, the collection of messages is examined to 
 * determine to determine if any should be sent to this new peer, adding a Tuple
 * to the list if so. When a connection goes down, any Tuple in the list
 * associated with that connection is removed from the List.
 * 
 * <strong>Decision Engines</strong>
 * 
 * Most (if not all) routing decision making is provided by a 
 * RoutingDecisionEngine object. The DecisionEngine Interface defines methods 
 * that enact computation and return decisions as follows:
 * 
 * <ul>
 *   <li>In createNewMessage(), a call to RoutingDecisionEngine.newMessage() is 
 * 	 made. A return value of true indicates that the message should be added to
 * 	 the message store for routing. A false value indicates the message should
 *   be discarded.
 *   </li>
 *   <li>changedConnection() indicates either a connection went up or down. The
 *   appropriate connectionUp() or connectionDown() method is called on the
 *   RoutingDecisionEngine object. Also, on connection up events, this first
 *   peer to call changedConnection() will also call
 *   RoutingDecisionEngine.doExchangeForNewConnection() so that the two 
 *   decision engine objects can simultaneously exchange information and update 
 *   their routing tables (without fear of this method being called a second
 *   time).
 *   </li>
 *   <li>Starting a Message transfer, a protocol first asks the neighboring peer
 *   if it's okay to send the Message. If the peer indicates that the Message is
 *   OLD or DELIVERED, call to RoutingDecisionEngine.shouldDeleteOldMessage() is
 *   made to determine if the Message should be removed from the message store.
 *   <em>Note: if tombstones are enabled or deleteDelivered is disabled, the 
 *   Message will be deleted and no call to this method will be made.</em>
 *   </li>
 *   <li>When a message is received (in messageTransferred), a call to 
 *   RoutingDecisionEngine.isFinalDest() to determine if the receiving (this) 
 *   host is an intended recipient of the Message. Next, a call to 
 *   RoutingDecisionEngine.shouldSaveReceivedMessage() is made to determine if
 *   the new message should be stored and attempts to forward it on should be
 *   made. If so, the set of Connections is examined for transfer opportunities
 *   as described above.
 *   </li>
 *   <li> When a message is sent (in transferDone()), a call to 
 *   RoutingDecisionEngine.shouldDeleteSentMessage() is made to ask if the 
 *   departed Message now residing on a peer should be removed from the message
 *   store.
 *   </li>
 * </ul>
 * 
 * <strong>Tombstones</strong>
 * 
 * The ONE has the the deleteDelivered option that lets a host delete a message
 * if it comes in contact with the message's destination. More aggressive 
 * approach lets a host remember that a given message was already delivered by
 * storing the message ID in a list of delivered messages (which is called the
 * tombstone list here). Whenever any node tries to send a message to a host 
 * that has a tombstone for the message, the sending node receives the 
 * tombstone.
 * 
 * @author PJ Dillon, University of Pittsburgh
*/


//Class to store the contents of the vertex in the format (node, utility_value)
	
class Node{
	String node_name;
	int ut_value;
	
	Node(String host, int tau_calculated){
		this.node_name = host;
		this.ut_value = tau_calculated;
	}
}


//Class to store the neighbours of each vertex in the linked list format


class Vertex{
	int t;
	LinkedList<Node> vrtx = new LinkedList<Node>();	
	Vertex(Node n,int time){
		vrtx.add(n);
		t=time;
	}
	
}

//Class for the graph data structure in a HashMap<int,Vertex> form



class Graph{
	HashMap<String,Vertex> graph = new HashMap<String,Vertex>();
	
	
	public int get_t(String host1, String host2){
		if(graph.containsKey(host1)){
			Vertex vtx=graph.get(host1);
			int len= vtx.vrtx.size();
			/*for(int i=0;i<len;i++){
				//System.out.println("                    vtx values " + vtx.vrtx.get(i).ut_value);
			}*/
			for(int i=0;i<len;i++){
				if(vtx.vrtx.get(i).node_name.equals(host2)){
					//System.out.println("In get_t " + vtx.vrtx.get(i).node_name + " " + host1.toString() + " " + host2.toString() 
								//+ " " + i + " " + vtx.t);
					return vtx.vrtx.get(i).ut_value;
				}
			}		
		}
		return 0;
	}
	
	public int get_time(String host1, String host2){
		if(graph.containsKey(host1)){
			Vertex vtx=graph.get(host1);
			int len= vtx.vrtx.size();
			for(int i=0;i<len;i++){
				if(vtx.vrtx.get(i).node_name.equals(host2)){
					//System.out.println("HUNNY BUNNY " + vtx.t);
					return vtx.t;
				}
			}		
		}
		//System.out.println("HUNNY BUNNY FUNNY " + vtx.t);
		return 0;
	}
	
	public void printGraph(){
		
//		for(String key : graph.keySet()){
//			String host1 = key;	
//			
//			Vertex gVertex = graph.get(key);
//			int gTime = gVertex.t;
//			LinkedList<Node> gvNode = gVertex.vrtx;
//			for(int j = 0; j < gvNode.size(); j++){
//				System.out.println(host1 + " " + gvNode.get(j).node_name + " " + gvNode.get(j).ut_value + " " + gTime);
//			}
//		}		
	}
	
	// Function to add a new edge to the graph.

	
	public void addEdge(String u, String v, int w){
		//System.out.println("In addedge " + u + " " + v + " " + w);
		Node n1 = new Node(u,w);
		Node n2 = new Node(v,w);
		String u1 = u;
		String v1 = v;
		SimClock time = new SimClock();
		int thistime = time.getIntTime();
		if(!graph.containsKey(u1)){
			Vertex neighbour = new Vertex(n2,thistime);
			//System.out.println("                       checking"+neighbour.t);
			graph.put(u1,neighbour);
			//System.out.println("if !graph.containsKey u1" + u1 + " " + thistime);
			
		}
		else{
			Vertex neighbour = graph.get(u1);
			neighbour.vrtx.add(n2);
			graph.put(u1,neighbour);
			//System.out.println("if graph.containsKey u1" + u1 + " " + thistime);
		}
	
		if(!graph.containsKey(v1)){
			Vertex neighbour = new Vertex(n1,thistime);
			graph.put(v1,neighbour);
			//System.out.println("if !graph.containsKey v1" + v1 + " " + thistime);
		}
		else{ 
			Vertex neighbour = graph.get(v1);
			neighbour.vrtx.add(n1);
			graph.put(v1,neighbour);
		}
	}
}

	
public class DecisionEngineRouter extends ActiveRouter
{
	public int flag1;
	public int flag2;
	public int flag3;
	public int flag4;


	public static final String PUBSUB_NS = "DecisionEngineRouter";
	public static final String ENGINE_SETTING = "decisionEngine";
	public static final String TOMBSTONE_SETTING = "tombstones";
	public static final String CONNECTION_STATE_SETTING = "";
	public static final String COPY_COUNT_PROP = "SprayAndFocus.copies";
	
	protected boolean tombstoning;
	protected RoutingDecisionEngine decider;
	protected List<Tuple<Message, Connection>> outgoingMessages;
	
	protected Set<String> tombstones;
	
	Graph CT = new Graph();
	Graph tau_vector = new Graph();
	
	/** 
	 * Used to save state machine when new connections are made. See comment in
	 * changedConnection() 
	 */
	protected Map<Connection, Integer> conStates;
	
	public DecisionEngineRouter(Settings s)
	{
		super(s);
		
		Settings routeSettings = new Settings(PUBSUB_NS);
		
		outgoingMessages = new LinkedList<Tuple<Message, Connection>>();
		
		decider = (RoutingDecisionEngine)routeSettings.createIntializedObject(
				"routing." + routeSettings.getSetting(ENGINE_SETTING));
		
		if(routeSettings.contains(TOMBSTONE_SETTING))
			tombstoning = routeSettings.getBoolean(TOMBSTONE_SETTING);
		else
			tombstoning = false;
		
		if(tombstoning)
			tombstones = new HashSet<String>(10);
		conStates = new HashMap<Connection, Integer>(4);
		
	}

	public DecisionEngineRouter(DecisionEngineRouter r)
	{
		super(r);
		outgoingMessages = new LinkedList<Tuple<Message, Connection>>();
		decider = r.decider.replicate();
		tombstoning = r.tombstoning;
		
		if(this.tombstoning)
			tombstones = new HashSet<String>(10);
		conStates = new HashMap<Connection, Integer>(4);
	}

	@Override
	public MessageRouter replicate()
	{
		return new DecisionEngineRouter(this);
	}

	@Override
	public boolean createNewMessage(Message m)
	{
		if(decider.newMessage(m))
		{
			makeRoomForNewMessage(m.getSize());
			addToMessages(m, true);
			
			findConnectionsForNewMessage(m, getHost());
			return true;
		}
		return false;
	}
	
	@Override
	public void changedConnection(Connection con)
	{
		DTNHost myHost = getHost();
		DTNHost otherNode = con.getOtherNode(myHost);
		MessageRouter mRouter = otherNode.getRouter();
		DecisionEngineRouter otherRouter = (DecisionEngineRouter)otherNode.getRouter();
		if(con.isUp())
		{
			decider.connectionUp(myHost, otherNode);
			//if(myHost.ferry==1)				
			//setcon(myHost, otherNode);
				
			
			/*
			 * This part is a little confusing because there's a problem we have to
			 * avoid. When a connection comes up, we're assuming here that the two 
			 * hosts who are now connected will exchange some routing information and
			 * update their own based on what the get from the peer. So host A updates
			 * its routing table with info from host B, and vice versa. In the real
			 * world, A would send its *old* routing information to B and compute new
			 * routing information later after receiving B's *old* routing information.
			 * In ONE, changedConnection() is called twice, once for each host A and
			 * B, in a serial fashion. If it's called for A first, A uses B's old info
			 * to compute its new info, but B later uses A's *new* info to compute its
			 * new info.... and this can lead to some nasty problems. 
			 * 
			 * To combat this, whichever host calls changedConnection() first calls
			 * doExchange() once. doExchange() interacts with the DecisionEngine to
			 * initiate the exchange of information, and it's assumed that this code
			 * will update the information on both peers simultaneously using the old
			 * information from both peers.
			 */
			if(shouldNotifyPeer(con))
			{
				this.doExchange(con, otherNode);
				otherRouter.didExchange(con);
			}
		
			/*
			 * Once we have new information computed for the peer, we figure out if
			 * there are any messages that should get sent to this peer.
			 */
			Collection<Message> msgs = getMessageCollection();
			/*int test1 = 0;
			for(int p = 0; p<myHost.malnode_cnt; p++){
				if(myHost.malnode[p]==otherNode){
					test1 = 1;
					break;
				}
			}*/
			if(!myHost.detectedNodes.contains(otherNode)){
				for(Message m : msgs)
				{
					if(decider.shouldSendMessageToHost(m, otherNode, myHost))
						outgoingMessages.add(new Tuple<Message,Connection>(m, con));
				}
			}
		}
		else
		{
			decider.connectionDown(myHost, otherNode);
			//myHost.tau_brk[otherNode.nodenumber] = SimClock.getIntTime();
			//otherNode.tau_brk[myHost.nodenumber] = SimClock.getIntTime();
			
			conStates.remove(con);
		
			/*
			 * If we  were trying to send message to this peer, we need to remove them
			 * from the outgoing List.
			 */
			for(Iterator<Tuple<Message,Connection>> i = outgoingMessages.iterator(); 
					i.hasNext();)
			{
				Tuple<Message, Connection> t = i.next();
				if(t.getValue() == con)
					i.remove();
			}
		}
	}
	
/**
	 * host1 checks if it has interacted with host2 or not, both modifies its value according to their previous interaction with other nodes.
	 */	
			
	
	public void setcon(DTNHost host1, DTNHost host2)			
	{
		int chk1 = 0, chk2 = 0;
		int i,j;
		SimClock time = new SimClock();
		int thistime = time.getIntTime();
		host1.tau_utl[host2.nodenumber] = 0;				
		host2.tau_utl[host1.nodenumber] = 0;
		
		//World bhool_bhal = new World(); 
		//List<DTNHost> allNodes = bhool_bhal.getNodes();
		
		for(int p = 0; p<host1.nodecount; p++){
			if(host1.connected_nodes[p] == host2)
				chk1 = 1;
		}
		if(chk1 == 0)
			host1.connected_nodes[host1.nodecount++] = host2;
		for(int q = 0; q<host2.nodecount; q++){
			if(host2.connected_nodes[q] == host1)
				chk2 = 1;
		}
		
		if(chk2 == 0)
			host2.connected_nodes[host2.nodecount++] = host1; 
		for(i = 0; i<host2.nodecount-1; i++){
			
			String local_host = host2.toString()+host2.connected_nodes[i].toString();
			String local_T = host2.connected_nodes[i].toString()+host2.toString();
			
			if(host2.toString().startsWith("m_f")){
			        host2.tau_utl[host2.connected_nodes[i].nodenumber] = thistime - host2.tau_brk[host2.connected_nodes[i].nodenumber];
			        host2.LT.put(local_host,host2.tau_utl[host2.connected_nodes[i].nodenumber]);
				//System.out.println("FALSE "+local_host+" "+host2.tau_utl[host2.connected_nodes[i].nodenumber]);				
				host2.connected_nodes[i].tau_utl[host2.nodenumber] = host2.tau_utl[host2.connected_nodes[i].nodenumber]-1;				
				host2.connected_nodes[i].LT.put(local_T,host2.connected_nodes[i].tau_utl[host2.nodenumber]);
				//System.out.println("TRUE "+local_T+" "+host2.connected_nodes[i].tau_utl[host2.nodenumber]);
			}
			
			else{
			        host2.tau_utl[host2.connected_nodes[i].nodenumber] = thistime - host2.tau_brk[host2.connected_nodes[i].nodenumber];
			        host2.LT.put(local_host,host2.tau_utl[host2.connected_nodes[i].nodenumber]);
			        host2.connected_nodes[i].tau_utl[host2.nodenumber] = host2.tau_utl[host2.connected_nodes[i].nodenumber];
		                host2.connected_nodes[i].LT.put(local_T,host2.connected_nodes[i].tau_utl[host2.nodenumber]);
		        	//System.out.println("NORMAL "+local_T+host2.tau_utl[host2.connected_nodes[i].nodenumber]+" "+host2.connected_nodes[i].tau_utl[host2.nodenumber]);
			}
		}
	}
		
	public void testmalicious(Message m, DTNHost otherHost, DTNHost from){
		
		int i,j,k;
		int tau_calc = 0, f_tau_calc=0,tau_calc2 = 0;
		int enc_time,block,bum_block;
		int dec_tau=0;
		DTNHost host1 = from;
		World bhool_bhal = new World(); 
		List<DTNHost> allNodes = bhool_bhal.getNodes();
		SimClock time = new SimClock();
		int thistime = time.getIntTime();
		
		for(int z=0; z<=otherHost.nodecount-1;z++){
			String local_host = otherHost.toString()+otherHost.connected_nodes[z].toString(); //TO CHANGE
			String local_T = otherHost.connected_nodes[z].toString()+otherHost.toString();
			if((otherHost.LT.get(local_host)!=null) && (otherHost.connected_nodes[z].LT.get(local_T)!=null)){
				block=otherHost.LT.get(local_host);
				bum_block=otherHost.connected_nodes[z].LT.get(local_T);
				
				enc_time= bum_block;
				if(bum_block==block){
					host1.LER.put(local_host,block);
					//System.out.println("IF "+local_host+" "+block);
					otherHost.LT.remove(local_host);
				}
				else{ 
					if(bum_block>block){
						otherHost.LT.remove(local_host);
						host1.LER.put(local_host,block);
						otherHost.connected_nodes[z].modmalicious=1;
						if(!from.detectedNodes.contains(otherHost.connected_nodes[z])){
							//System.out.println("IF "+local_T+" "+bum_block+" "+block);	
							from.detectedNodes.add(otherHost.connected_nodes[z]);
						}
					}
					else if(bum_block<block){
						otherHost.LT.remove(local_host);
						host1.LER.put(local_host,enc_time);
						otherHost.modmalicious=1;
						if(!from.detectedNodes.contains(otherHost)){
							//System.out.println("Else IF "+local_host+" "+bum_block+" "+block);
							from.detectedNodes.add(otherHost);
														
						}
					}
				}
			}
		}
		for(i = 0; i<otherHost.nodecount-1; i++){
		
					/**Overhead*/
					otherHost.msg_overhead++;
					//System.out.println(SimClock.getTime() + "\t"+ otherHost.msg_overhead + "\tContact Info Transfer between\t" + from.toString() + " " + otherHost.toString());
					
					if(otherHost.malnode_focus==1 &&
                                                    MaliciousDecisionEngine.DecideMaliciousness(0.0)){
						tau_vector.addEdge(otherHost.toString(),otherHost.connected_nodes[i].toString(),
									otherHost.tau_utl[otherHost.connected_nodes[i].nodenumber]);
					}
					else{
						tau_vector.addEdge(otherHost.toString(),otherHost.connected_nodes[i].toString(),
									otherHost.tau_utl[otherHost.connected_nodes[i].nodenumber]);
					}
		}

		for(int z=0; z<=otherHost.nodecount-1;z++){
		
			String ot_host = otherHost.toString()+otherHost.connected_nodes[z].toString(); 
			DTNHost X = otherHost.connected_nodes[z];
			int enc_time2;
			
			if(host1.LER.get(ot_host)!=null){
				enc_time2 = host1.LER.get(ot_host);
				
			}
			else{
				enc_time2=0;
			}	
			if(otherHost.LT.get(ot_host)!=null){
				int wiki=otherHost.LT.get(ot_host);
			
			
				if(enc_time2<=wiki){
					host1.LER.put(ot_host,wiki);

					for(i = 0; i<otherHost.nodecount-1; i++){
					
						if(otherHost.tau_utl[otherHost.connected_nodes[i].nodenumber] > X.tau_utl[otherHost.connected_nodes[i].nodenumber]){
							otherHost.tau_utl[otherHost.connected_nodes[i].nodenumber] = X.tau_utl[otherHost.connected_nodes[i].nodenumber];					
						}
						else{
							X.tau_utl[otherHost.connected_nodes[i].nodenumber] = otherHost.tau_utl[otherHost.connected_nodes[i].nodenumber];
						}
					}
				}	
			}		
			tau_calc = X.tau_utl[m.getTo().nodenumber];
				
			CT.addEdge(otherHost.toString(),otherHost.connected_nodes[i].toString(),tau_calc);
		}

		//CASE 2---------------------------------------------------------------------------------------	
		
		
		if(thistime>80000){
			flag1=0;
			flag2=0;
			flag3=0;
			flag4++;
		}
		
		else if(thistime>60000){
			flag1=0;
			flag2=0;
			flag3++;
		}
		
		else if(thistime>40000){
			flag1=0;
			flag2++;
		}
		
		else if(thistime>20000){
			flag1++;
		}
		
		

		if( thistime > 10000/*flag1==1 || flag2==1 || flag3==1 || flag4==1*/){
			for(i=0;i<allNodes.size();i++){
				String tmp_host1 = allNodes.get(i).toString();	
				
				for(j=0;j<allNodes.size();j++){
					if(i!=j){
						String tmp_host2 = allNodes.get(j).toString();
						String ij = tmp_host1 + tmp_host2;
			    
			
						int blocker_ut= tau_vector.get_t(tmp_host1,tmp_host2);
						int blocker_time;
						blocker_time = tau_vector.get_time(tmp_host1,tmp_host2);
						int blockest_ut= CT.get_t(tmp_host1,tmp_host2);
						int blockest_time= CT.get_time(tmp_host1,tmp_host2);
		
						if(host1.LER.get(ij)!=null){
							block = host1.LER.get(ij);
				
							if(blocker_ut!=0){
								if(MaliciousDecisionEngine.DecideMaliciousness(0.0) && 
                                                                        allNodes.get(i).malnode_focus == 1){
									dec_tau = (thistime-blocker_time)+tau_vector.get_t(tmp_host1,tmp_host2) - 1;
									//System.out.println("\t\t\t\tMalicious" + allNodes.get(i).toString() + " " + dec_tau);
								}
								else{
									dec_tau = (thistime-blocker_time)+tau_vector.get_t(tmp_host1,tmp_host2);
									//System.out.println("\t\t\t\tNot malicious" + allNodes.get(i).toString() + " " + dec_tau);
								}
								if(block >= blockest_time){
									f_tau_calc = thistime-block;
								}
								else if(block < blockest_time){
									f_tau_calc = blockest_ut+(thistime-blockest_time);
								}
							}
							else{
								dec_tau=0;						
							}
					
						} 
						//System.out.println(ij + " dec_tau " + dec_tau+" "+f_tau_calc);
						
						if(f_tau_calc>dec_tau && host1.LER.get(ij)!=null){
							otherHost.modmalicious=1;
							if(allNodes.get(i).ferry != 1 && dec_tau!=0){
								if(!from.detectedNodes.contains(allNodes.get(i))){
									/*
									if(allNodes.get(i).toString().startsWith("c8") || allNodes.get(i).toString().startsWith("c6") || allNodes.get(i).toString().startsWith("t19") || allNodes.get(i).toString().startsWith("p0") || allNodes.get(i).toString().startsWith("m_f54") || allNodes.get(i).toString().startsWith("c7")){
										
										System.out.println(allNodes.get(i).toString() 
															+ " " + f_tau_calc 
															+ " " + dec_tau
															+ " " + blocker_time
															+ " " + tau_vector.get_t(tmp_host1,tmp_host2)
															+ " " + thistime
															+ " " + blockest_ut
															+ " " + blockest_time
															);
									}
									System.out.println(allNodes.get(i).toString() + " is malicious");
									*/
									//from.detectedNodes.add(allNodes.get(i));
								}
							}
						}
						else{
							continue;
						}
					}	
				}
			}
		flag1=0;
		}
		
		/**Overhead*/
		host1.msg_overhead+=otherHost.LT.size();
		host1.msg_overhead+=otherHost.LER.size();
		//System.out.println(SimClock.getTime() + "\t"+ host1.msg_overhead + "\tLER nd LT Info Transfer between\t" + host1.toString() + " " + otherHost.toString());
	}
	protected void doExchange(Connection con, DTNHost otherHost)
	{
		conStates.put(con, 1);
		decider.doExchangeForNewConnection(con, otherHost);
	}
	
	/**
	 * Called by a peer DecisionEngineRouter to indicated that it already 
	 * performed an information exchange for the given connection.
	 * 
	 * @param con Connection on which the exchange was performed
	 */
	protected void didExchange(Connection con)
	{
		conStates.put(con, 1);
	}
	@Override
	public void deleteAckedMessages() {
		for (String id : this.ackedMessageIds) {
			if (this.hasMessage(id) && !isSending(id)) {
				this.deleteMessage(id, false);
			}
		}
	}
	
	@Override
	protected int startTransfer(Message m, Connection con)
	{
		int retVal;
		
		if (!con.isReadyForTransfer()) {
			return TRY_LATER_BUSY;
		}
		
		retVal = con.startTransfer(getHost(), m);
		if (retVal == RCV_OK) { // started transfer
			addToSendingConnections(con);
		}
		else if(tombstoning && retVal == DENIED_DELIVERED)
		{
			this.deleteMessage(m.getId(), false);
			tombstones.add(m.getId());
		}
		else if (deleteDelivered && (retVal == DENIED_OLD || retVal == DENIED_DELIVERED) && 
				decider.shouldDeleteOldMessage(m, con.getOtherNode(getHost()))) {
			/* final recipient has already received the msg -> delete it */
			this.deleteMessage(m.getId(), false);
		}
		
		return retVal;
	}

	@Override
	public int receiveMessage(Message m, DTNHost from)
	{
		if(isDeliveredMessage(m) || (tombstoning && tombstones.contains(m.getId())))
			return DENIED_DELIVERED;
			
		return super.receiveMessage(m, from);
	}

	@Override
	public Message messageTransferred(String id, DTNHost from)
	{
		Message incoming = removeFromIncomingBuffer(id, from);
	
		if (incoming == null) {
			throw new SimError("No message with ID " + id + " in the incoming "+
					"buffer of " + getHost());
		}
		
		incoming.setReceiveTime(SimClock.getTime());
		
		Message outgoing = incoming;
		for (Application app : getApplications(incoming.getAppID())) {
			// Note that the order of applications is significant
			// since the next one gets the output of the previous.
			outgoing = app.handle(outgoing, getHost());
			if (outgoing == null) break; // Some app wanted to drop the message
		}
		
		Message aMessage = (outgoing==null)?(incoming):(outgoing);
		
		boolean isFinalRecipient = decider.isFinalDest(aMessage, getHost());
		boolean isFirstDelivery =  isFinalRecipient && 
			!isDeliveredMessage(aMessage);
		
		if (outgoing!=null && decider.shouldSaveReceivedMessage(aMessage, getHost())) 
		{
			// not the final recipient and app doesn't want to drop the message
			// -> put to buffer
			addToMessages(aMessage, false);
			
			// Determine any other connections to which to forward a message
			findConnectionsForNewMessage(aMessage, from);
		}
		
		if (isFirstDelivery)
		{
			this.deliveredMessages.put(id, aMessage);
		}
		
		for (MessageListener ml : this.mListeners) {
			ml.messageTransferred(aMessage, from, getHost(),
					isFirstDelivery);
		}
		
		return aMessage;
	}

	@Override
	protected void transferDone(Connection con)
	{
		Message transferred = this.getMessage(con.getMessage().getId());
		if(transferred == null) return;
		for(Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator(); 
		i.hasNext();)
		{

			Tuple<Message, Connection> t = i.next();
			
			if(t.getKey().getId().equals(transferred.getId()) && 
					t.getValue().equals(con))
			{
				i.remove();
				break;
			}
		}
		if(decider.shouldDeleteSentMessage(transferred, con.getOtherNode(getHost())))
		{
			this.deleteMessage(transferred.getId(), false);
			
			for(Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator(); 
			i.hasNext();)
			{
				Tuple<Message, Connection> t = i.next();
				if(t.getKey().getId().equals(transferred.getId()))
				{
					i.remove();
				}
			}
		}
	}

	@Override
	public void update()
	{
		super.update();
		if (!canStartTransfer() || isTransferring()) {
			return; // nothing to transfer or is currently transferring 
		}
		tryMessagesForConnected(outgoingMessages);
	
		for(Iterator<Tuple<Message, Connection>> i = outgoingMessages.iterator(); 
		i.hasNext();)
		{
			Tuple<Message, Connection> t = i.next();
			if(!this.hasMessage(t.getKey().getId()))
			{
				i.remove();
			}
		}
	}
	
	public RoutingDecisionEngine getDecisionEngine()
	{
		return this.decider;
	}

	protected boolean shouldNotifyPeer(Connection con)
	{
		Integer i = conStates.get(con);
		return i == null || i < 1;
	}
	
	protected void findConnectionsForNewMessage(Message m, DTNHost from)
	{
		for(Connection c : getConnections())
		{
			int i,j, chk, test1 = 0, test2 = 0;
			DTNHost other = c.getOtherNode(getHost());
			setcon(getHost(), other);
			
			/**
			* Compare the malicious list of the two nodes 
			* and update accordingly
			*/
			compareMaliciousList(from, other);
			
			
			if((Integer)m.getProperty(COPY_COUNT_PROP)==1 && getHost().ferry == 1 && other.ferry!= 1 ){
				if(!from.detectedNodes.contains(other)){
					testmalicious(m, other, getHost());
					addmalicious(from);
				}
			}
			if(!from.detectedNodes.contains(other)){
				if(other != from && decider.shouldSendMessageToHost(m, other, from))
				{
					outgoingMessages.add(new Tuple<Message, Connection>(m, c));
				}
			}
		}
	}
	public void addmalicious(DTNHost from){
		for(Connection c : getConnections()){
			int i,j,chk, test1 = 0, test2 = 0;
			DTNHost other = c.getOtherNode(getHost());
			compareMaliciousList(from, other);
		}
	}
	
	public void compareMaliciousList(DTNHost from, DTNHost other){
		int i;
		if(!from.detectedNodes.contains(other)){
			
			for(i = 0; i<from.detectedNodes.size(); i++){
				if(!other.detectedNodes.contains(from.detectedNodes.get(i))){
					//System.out.println("================");
					other.maloverhead++;
					other.detectedNodes.add(from.detectedNodes.get(i));
					
					/**Overhead */
					other.msg_overhead++;
					//System.out.println(SimClock.getTime() + "\t"+ other.msg_overhead + "\t" + from.detectedNodes.get(i).toString() + "\tmalNode Info Transfer between\t" + from.toString() + " " + other.toString()+ "kartikeya");
				}
			}
		}
		
		if(!other.detectedNodes.contains(from)){
			for(i = 0; i<other.detectedNodes.size(); i++){
				if(!from.detectedNodes.contains(other.detectedNodes.get(i))){
					//System.out.println("------------------");
					from.maloverhead++;
					from.detectedNodes.add(other.detectedNodes.get(i));
					
					/**Overhead */
					from.msg_overhead++;
					//System.out.println(SimClock.getTime() + "\t"+ from.msg_overhead + "\t" + other.detectedNodes.get(i).toString() + "\tmalNode Info Transfer between\t" + from.toString() + " " + other.toString()+ "wiki");
				}
			}
		}
	}
}

