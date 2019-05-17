# SNMP-Manager
Implementation of Simple Network Management Protocol (SNMP) in Java for GetRequest PDU

## Usage
* Make sure the SNMP-agent on the destination device is running.

  * For Linux platform, snmpd service should be running
  
  * For Windows platform, enable the SNMP service in Program Features
  
* If IDE is being used to execute the program, use Eclipse IDE preferably

* For CLI based execution, one can use javac command to compile the program and java command to execute the same

* Required inputs for the program are as follows:
  * Destination Address or HostName (SNMP-Agent)
  * SNMP version
  * SNMP community string
  * Object Identifier (OID) 
  
  [If SNMP-Agent is on a Linux platform, one can obtain the list of OIDs using snmpwalk command] 

__NOTE :__ For more info about this project, click [this](https://github.com/Saurabh702/SNMP-Manager/blob/master/Report.pdf)
