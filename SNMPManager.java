/*
 * Implementation of SNMP Manager for GetRequest PDU 
 */

import java.net.*;
import java.io.*;
import java.util.Scanner;

class Dgram 
{
	public static DatagramPacket toDatagram(byte buf[], InetAddress destIA, int destPort) 
	{
		return new DatagramPacket(buf, buf.length,destIA, destPort);
	}

	public static String toString(DatagramPacket p)
	{
		return new String(p.getData(), 0, p.getLength());
	}
} 

public class SNMPManager
{
	private DatagramSocket s;
	private InetAddress hostAddress;
	private byte[] buf = new byte[1000];
	private byte snmp_message[];
	private DatagramPacket dp =new DatagramPacket(buf, buf.length);
	private DatagramPacket dp1 = new DatagramPacket(buf, buf.length);
	int x,y; //Temporary Variables for storing the first two bytes of OID (for iso, x = 1 and y = 3)

	public SNMPManager(String hostname) 
	{
		try  
		{
			// Construct and Bind Datagram Socket to port 161
			s = new DatagramSocket(161);      

			// Get IP address of host if hostname is specified
			hostAddress =InetAddress.getByName(hostname);
		} 
		catch(UnknownHostException e) 
		{
			System.err.println("Cannot find host");
			System.exit(1);
		} 
		catch(SocketException e) 
		{
			System.err.println("Can't open socket");
			e.printStackTrace();
			System.exit(1);
		}

		System.out.println("SNMP Manager is running !!\n");
	}

	// Encode the SNMP Message based on TLV format [Type,Length,Value]
	public void encode(SNMPMessage data)
	{
		/* 
		 * Length of each field based on TLV format where 
		 * T & L occupy the first two bytes of a field and
		 * the remaining is occupied by V which is of variable length
		 */

		// SNMP Version {0,1,2} => {v1,v2,v3}
		byte version[] = new byte[3];

		version[0] = Data_Types.INTEGER.getIdentifer(); 
		version[1] = 1; 
		version[2] = (byte)data.getVersion();

		// SNMP Community String {public,private,...}
		byte community_string[] = new byte[data.getCommunity_String().length() + 2];

		community_string[0] = Data_Types.OCTET_STRING.getIdentifer();
		community_string[1] = (byte)data.getCommunity_String().length();

		char [] temp = data.getCommunity_String().toCharArray(); // Convert string to a character array
		for(int i = 0; i < temp.length ;i++)	// Store character array in byte format
			community_string[2+i] = (byte)temp[i];	 

		// Request ID {1,2,...}
		byte request[] = new byte[3];

		request[0] = Data_Types.INTEGER.getIdentifer();
		request[1] = 1;
		request[2] = (byte)data.getRequest_ID();

		// Error Type {0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
		byte error[] = new byte[3];

		error[0] = Data_Types.INTEGER.getIdentifer();
		error[1] = 1;
		error[2] = (byte)data.getError_Type();

		// Error Index
		byte error_index[] = new byte[3];

		error_index[0] = Data_Types.INTEGER.getIdentifer();
		error_index[1] = 1;
		error_index[2] = (byte)data.getError_Index();

		// Object Identifier (OID)
		String[] bytes = data.getOID().split("\\.");	// Split input OID based on '.'

		// Count the no. of big numbers in OID (i.e above 127)
		int big_number_count = 0;
		for (int i = 0; i < bytes.length; i++)
			if(Integer.decode(bytes[i]) > 127) // less than 0 condition not required
				big_number_count ++;

		byte oid[] = new byte[bytes.length + 1 + big_number_count];
		oid[0] = Data_Types.OID.getIdentifer();
		oid[1] = (byte)(bytes.length - 1 + big_number_count);

		// Parse Initial 2 bytes to encode the first number of OID according to BER [Basic Encoding Rule]
		x = Integer.parseInt(bytes[0]); 
		y = Integer.parseInt(bytes[1]);
		int first_byte = 40 * x + y;

		// Convert the first number to HEX
		String first_byte_hex = Integer.toHexString(first_byte); 
		oid[2] = Integer.decode("0x"+first_byte_hex).byteValue();

		// Store the remaining numbers in OID in byte format
		for(int i = 0,j = 0; i < oid[1] && j < bytes.length - 2; i++)
			// Encode big numbers according to BER if above 127
			if(Integer.decode(bytes[2 + j]) > 127)
			{
				/*
				 * If a number in OID is 1002,  then it is encoded as 0x87 and 0x6A
				 * The first octet (first byte) is obtained by right shifting the number by 0x07 and ORing the result with 0x80
				 * The second octet (second byte) is obtained by ANDing the number with 0x7F
				 */
				// Counters: i -> oid array and j -> byte array (excluding the first 2 elements)
				oid[3 + i] = Integer.decode("0x" + Integer.toHexString(((Integer.decode(bytes[2 + j]) >> 0x07 )| 0x80))).byteValue(); //First byte
				oid[3 + (i++) + 1] = Integer.decode("0x" + Integer.toHexString(Integer.decode(bytes[2 + (j++)]) & 0x7F)).byteValue();	// Second byte
				// i and j is incremented within the array index 
			}
			else
				oid[3 + i] = Integer.decode(bytes[2 + (j++)]).byteValue();	

		// Value
		byte value[] = new byte[2];
		value[0] = Data_Types.NULL.getIdentifer();
		value[1] = 0; // Length : 0

		// Varbind : {OID,Value}
		byte varbind[] = new byte[oid.length + value.length + 2];
		varbind[0] = Data_Types.SEQUENCE.getIdentifer();
		// Calculate length of oid and value bytearrays and convert it to HEX string and then to byte format
		varbind[1] = Integer.decode("0x" +Integer.toHexString(oid.length + value.length)).byteValue();
		System.arraycopy(oid, 0, varbind, 2, oid.length);	// Copy the byte array oid to byte array varbind at pos 0 
		System.arraycopy(value, 0, varbind, oid.length + 2, value.length);	// Copy the byte array value to byte array varbind at pos "oid.length + 2"

		// Varbind List : {Varbind1, Varbind2, ...}
		byte varbindlist[] = new byte[varbind.length + 2];
		varbindlist[0] = Data_Types.SEQUENCE.getIdentifer();
		varbindlist[1] = Integer.decode("0x" + Integer.toHexString(varbind.length)).byteValue();
		System.arraycopy(varbind, 0, varbindlist, 2, varbind.length);

		// SNMP PDU {Request_ID, Error, Error_Index, Varbind List}
		// PDU -> {GetRequest,SetRequest,...}
		byte snmp_pdu[] = new byte[request.length + error.length + error_index.length + varbindlist.length + 2];
		snmp_pdu[0] = Data_Types.GETREQUEST.getIdentifer(); // For GET_REQUEST PDU
		snmp_pdu[1] = Integer.decode("0x" +Integer.toHexString(request.length + error.length + error_index.length + varbindlist.length)).byteValue();
		System.arraycopy(request, 0, snmp_pdu, 2, request.length);
		System.arraycopy(error, 0, snmp_pdu, 2 + request.length, error.length);
		System.arraycopy(error_index, 0, snmp_pdu, 2 + request.length + error.length, error_index.length);
		System.arraycopy(varbindlist, 0, snmp_pdu, 2 + request.length + error.length + error_index.length, varbindlist.length);

		// SNMP message {SNMP Version, SNMP Community String, SNMP PDU}
		byte snmp_message[] = new byte[version.length + community_string.length + snmp_pdu.length + 2];
		snmp_message[0] = Data_Types.SEQUENCE.getIdentifer();
		snmp_message[1] = Integer.decode("0x" +Integer.toHexString(version.length + community_string.length + snmp_pdu.length)).byteValue();
		System.arraycopy(version, 0, snmp_message, 2, version.length);
		System.arraycopy(community_string, 0, snmp_message, 2 + version.length, community_string.length);
		System.arraycopy(snmp_pdu, 0, snmp_message, 2 + version.length + community_string.length, snmp_pdu.length);

		this.snmp_message = snmp_message;	
	}

	public void getRequest() 
	{
		try
		{
			// Construct Datagram Packet with snmp message, host address and port number
			dp = Dgram.toDatagram(snmp_message, hostAddress,161);

			// Send the Datagram Packet from Datagram Socket 
			s.send(dp);

			// Prints detailed description of the message sent from the SNMP Manager 
			SNMPMessage.print_message(snmp_message,x,y); //For OID, x=1 and y=3 ex: 1.3.6.1.2.1.1.5.0 or iso.3.6.1.2.1.1.5.0

			// Print the message sent in string format
			System.out.println("\nMessage sent to agent");
			System.out.printf("Message : %s%n",Dgram.toString(dp));
			System.out.println("\nWaiting for reply .....\n");

			// Receive the Datagram Packet from Datagram Socket from SNMP Agent
			s.receive(dp1);
			byte[] a = dp1.getData();

			// Print the message received in string format
			System.out.println("Message received from agent !!");
			System.out.println("Agent IP address: " + dp1.getAddress() + ":" + dp1.getPort());
			System.out.printf("Message : %s%n%n",Dgram.toString(dp1));

			// Prints detailed description of the message received from the SNMP Agent 
			SNMPMessage.print_message(a,x,y);

		} 
		catch(IOException e) 
		{
			e.printStackTrace();
			System.exit(1);
		}
	}

	public static void main(String[] args)
	{
		// Read the destination hostName or hostAddress
		Scanner reader = new Scanner(System.in);

		System.out.print("Enter Destination Address/HostName: ");

		// Initialize object of SNMPManager
		SNMPManager s = new SNMPManager(reader.nextLine());

		// Initialize object of SNMPMessage
		SNMPMessage m = new SNMPMessage();
		m.getData();	// Get Input data for constructing the message from the user

		s.encode(m);	// Encode the SNMP message 
		s.getRequest(); // Send GET_REQUEST to SNMP Agent and Print response

		reader.close();
	}
} 
