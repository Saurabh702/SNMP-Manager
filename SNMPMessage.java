import java.util.Scanner;

enum Data_Types
{
	// ASN.1 Data Type and their respective identifiers
	INTEGER(0x02),OCTET_STRING(0x04),NULL(0x05),OID(0x06),SEQUENCE(0x30),GETREQUEST(0xA0);
	private int identifier;
	private String data_type;

	Data_Types(int i)
	{
		identifier = i;
		data_type = this.name();
	}

	// To return identifier(in byte format) for specific ASN.1 Data Type
	public byte getIdentifer()
	{
		return (byte)identifier;
	}

	// To return ASN.1 Data Type for a given identifier
	public static String getData_Type(int i)
	{
		for(Data_Types x : Data_Types.values())
		{
			if(x.identifier == i)
				return x.data_type;
		}
		return "UNKNOWN";
	}
}

public class SNMPMessage
{
	private int Version,Request_ID,Error_Type,Error_Index;
	private String Community_String,OID,Value;

	// Initialize all fields of the SNMP Message
	public SNMPMessage()
	{
		setVersion(0);	// SNMP Version(1) : 0
		setCommunity_String("public");	// Default community string for v1 : public 
		setRequest_ID(1);	// Request ID : 1
		setError_Type(0);	// Error Type : 0
		setError_Index(0);	// Error Index : 0
		setOID("");	// Object Identifier : NULL
		setValue(""); // Value : NULL
	}

	// Get Version, Community String and Object Identifier inputs from user
	public void getData()
	{
		System.out.println("Input SNMP Field Details");

		Scanner reader = new Scanner(System.in);

		System.out.print("Version : ");
		setVersion(reader.nextInt());

		reader.nextLine();

		System.out.print("Community String : ");
		setCommunity_String(reader.nextLine());

		System.out.print("OID : ");
		setOID(reader.nextLine());

		reader.close();
	}

	public int getVersion() {
		return Version;
	}

	public void setVersion(int version) {
		Version = version;
	}

	public String getCommunity_String() {
		return Community_String;
	}

	public void setCommunity_String(String community_String) {
		Community_String = community_String;
	}

	public int getRequest_ID() {
		return Request_ID;
	}

	public void setRequest_ID(int request_id) {
		Request_ID = request_id;
	}

	public int getError_Type() {
		return Error_Type;
	}

	public void setError_Type(int error_type) {
		Error_Type = error_type;
	}

	public int getError_Index() {
		return Error_Index;
	}

	public void setError_Index(int error_index) {
		Error_Index = error_index;
	}

	public String getOID() {
		return OID;
	}

	public void setOID(String oid) {
		OID = oid;
	}

	public String getValue() {
		return Value;
	}

	public void setValue(String value) {
		Value = value;
	}

	public static void print_message(byte[] b, int x, int y)
	{
		/* 
		 * Detailed SNMP Message Description using TLV format 
		 */

		String temp = "";
		int i,j,k;

		System.out.println("Message Description: \n");

		String format_title = "%1$-20s%2$-15s%3$-10s%4$-7s\n"; // Define formatting for title of the table
		String format = "%1$-20s%2$-15s%3$-10s%4$-7s\n";	// Define formatting for the data in the table

		System.out.format(format_title,"Field","Type","Length","Value");
		System.out.println("---------------------------------------------------------");

		// SNMP Message
		System.out.format(format,"Version",Data_Types.getData_Type(b[2]),b[3],b[4]);

		for(i = 0; i < b[6]; i++)
			temp += (char)b[7+i];
		System.out.format(format,"Community String",Data_Types.getData_Type(b[5]),b[6],temp);

		i += 7 + 2; //	index variable for the following fields (skipping Tag and Length for SNMP PDU)

		// SNMP PDU
		System.out.format(format,"Request ID",Data_Types.getData_Type(b[i]),b[i+1],b[i+2]);
		System.out.format(format,"Error",Data_Types.getData_Type(b[i+3]),b[i+4],b[i+5]);
		System.out.format(format,"Error Index",Data_Types.getData_Type(b[i+6]),b[i+7],b[i+8]);

		i += 8 + 4 + 2; //	index variable (skipping Tag and Length for Varbind List, Varbind)

		int bit_pos = 7, temp_x, temp_y, p = 1, m = 7;

		for(j = 1, temp = x + "." + y; j < b[i]; j++)	//	Initial OID is "x.y"

			//	Handles OID's with numbers upto 16383 (2^14 - 1) upto two octets
			if((b[i + 1 + j] & ((byte)1 << bit_pos)) != 0)	// Check if 8th bit in the first byte of the big number is set or not
			{
				temp_x = (((1 << m) - 1) & (b[i + 1 + j] >> (p - 1)));	//	Store m bits from position p in the first byte where m = 7,p = 1
				temp_y = b[i + 1 + j + 1];	// Store second byte 
				temp += "." + ((temp_x * 128) + temp_y);	// Decode the bytes into big number
				j++;
			}
			else
				temp += "." + b[i + 1 + j];
		System.out.format(format,"Object ID",Data_Types.getData_Type(b[i - 1]),b[i],temp);

		for(k = 1, temp = ""; k <= b[i + 1 + j + 1]; k++)
			if(b[i + 1 + j] == Data_Types.OCTET_STRING.getIdentifer())	//	If value type is string, convert ASCII value to character type
				temp += (char)b[i + 1 + j + 1 + k];
			else
				temp += b[ i + 1 + j + 1 + k];
		System.out.format(format,"Value",Data_Types.getData_Type(b[i + 1 + j]),b[i + 1 + j + 1],temp);
	}
}