package core;
import java.util.*;

public class MessageInfo{
	public String id;		// Id of message
	public Message msg;		// The message
	public String other;	// The other node
	public int ttl;			// TTL of message
	public int msgsize;		// Message size
	public int noms;		// Number of copies remaining with sender
	public int nomr;		// Number of copies with receiver
	
	public MessageInfo(String i, Message m, String o, 
						int t, int size, int ns, int nr){
		this.id = i;
		this.msg = m;
		this.other = o;
		this.ttl = t;
		this.msgsize = size;
		this.noms = ns;
		this.nomr = nr;
	}
}
