##code adapted from 
# - https://github.com/ishaansathaye/int-collector-cisco/blob/master/INTCollector.py and from
# - https://github.com/p4lang/tutorials/blob/master/exercises/mri/receive.py



from scapy.all import sniff
from scapy.all import IP, TCP, UDP
from scapy.all import raw
from scapy.all import bytes_hex
import influxdb_client, os, time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import ipaddress
from dotenv import load_dotenv, main
import array

def bits2hex(bits):
    decimal_representation = int(bits, 2)
    hexadecimal_string = hex(decimal_representation)
    return hexadecimal_string[2:]

def bits2dec(bits):
    return int(bits, 2)

def hex2bits(hexString):
    bit_string = bin(int(hexString,16))
    return bit_string  

def hex2dec(hexCode):
    decimal_string = int(hexCode, 16)
    return decimal_string

def hex2dotted(hexWord):
    addr_long = int(hexWord, 16)
    dottedFormat=str(ipaddress.ip_address(addr_long))
    return dottedFormat


global default_remaining_hop_count

default_remaining_hop_count=3



global default_metadata_stack_size

default_metadata_stack_size=8



#Ethernet
class Ethernet():  

    def __init__(self,hexStream):
        
        self.ethernetFrame = hexStream[0:28]
        self.destinationEthernet = self.ethernetFrame[0:12]
        self.sourceEthernet = self.ethernetFrame[12:24]
        self.typeFieldEthernet = self.ethernetFrame[24:28]


    def getTypeFieldIP(self):
        return self.typeFieldEthernet

    def displayEthernet(self):

        print("")
        print("--------------------- INT Report ------------------------")
        print("\n")
        print("   Ethernet  \n")
        print("   DMAC " + self.destinationEthernet)
        print("   SMAC: " +  self.sourceEthernet)
        print("   EType: " + self.typeFieldEthernet)


#IP
class ip():

    def __init__(self,hexStream,report):
        
        if(report==0):

            self.ipFrame = hexStream[(28):(68)]
            self.version_headerLength = self.ipFrame[0:1]
            self.ihl = self.ipFrame[1:2]
            self.dscp=str(hex2dec(self.ipFrame[2:4]))
            self.ecn= self.ipFrame[4:5]
            self.totalLen = str(hex2dec(self.ipFrame[5:8]))
            self.identification = str(hex2dec(self.ipFrame[8:12]))
            self.flags = self.ipFrame[12:13]
            self.fragOffset = self.ipFrame[13:14]

            self.ttl = str(hex2dec(self.ipFrame[14:18]))
            self.protocol = self.ipFrame[18:20]
            self.hdrChecksum = str(hex2dec(self.ipFrame[20:25]))
            self.sourceIP1 = self.ipFrame[25:32]
            self.destinationIP1 = self.ipFrame[32:40]
            self.sourceIP = hex2dotted(self.sourceIP1)
            self.destinationIP = hex2dotted(self.destinationIP1)
  

        if(report==1):

            

            self.ipFrame = hexStream[(184):(224)]
            self.version_headerLength = self.ipFrame[0:1]
            self.ihl = self.ipFrame[1:2]
            self.dscp=str(bits2dec(hex2bits(self.ipFrame[2:4])[0:7]))
            self.ecn= str(bits2dec(hex2bits(self.ipFrame[2:4])[7:9]))
            self.totalLen = str(hex2dec(self.ipFrame[5:8]))
            self.identification = str(hex2dec(self.ipFrame[8:12]))
            self.flags = self.ipFrame[12:13]
            self.fragOffset = self.ipFrame[13:14]

            self.ttl = str(hex2dec(self.ipFrame[14:18]))
            self.protocol = self.ipFrame[18:20]
            self.hdrChecksum = str(hex2dec(self.ipFrame[20:25]))
            self.sourceIP1 = self.ipFrame[25:32]
            self.destinationIP1 = self.ipFrame[32:40]
            self.sourceIP = hex2dotted(self.sourceIP1)
            self.destinationIP = hex2dotted(self.destinationIP1)
   

    def getIPProtocol(self):
        return self.protocol
    
    def displayIP(self):


        print("\n")
        print("   IP  \n")

        print("   Version: "+ self.version_headerLength)
        print("   Ihl: " +  self.ihl )
        print("   Dscp: " + self.dscp)
        print("   Ecn: " +  self.ecn )
        print("   TotalLen: " +   self.totalLen )
        print("   Identification: "  + self.identification )
        print("   Flags: "+ self.flags )
        print("   FragOffset: "  + self.fragOffset )
        print("   Ttl: "  + self.ttl )
        print("   HdrChecksum: " +  self.hdrChecksum )
        print("   Protocol: " +   self.protocol )
        print("   Source: "  + self.sourceIP )
        print("   Destination: " + self.destinationIP )

    def getDSCP(self):
        return self.dscp

#UDP
class udp():
    
    def __init__(self,hexStream):
        
        self.udpFrame = hexStream[(68):(84)]
        self.sourceUDP = self.udpFrame[0:4]
        self.destinationUDP = self.udpFrame[4:8]
        self.lengthUDP = self.udpFrame[8:12]
        self.udpChecksum = self.udpFrame[12:16]


    
    def getDestinationUDP(self):
        return self.destinationUDP
    
    def displayUDP(self):
        print("\n")
        print("   UDP  \n")
        print("   Source: "  + self.sourceUDP )
        print("   Destination: "  + self.destinationUDP )
        print("   Length: "  + self.lengthUDP )
        print("   UDP Checksum: " + self.udpChecksum ) 


class tcp():

    def __init__(self,hexStream):
        
        self.tcpFrameAux = hexStream[(224):(264)]
        self.tcpFrame= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.tcpFrameAux])
        self.srcPort = str(bits2dec(self.tcpFrame[0:16]))
        self.dstPort = str(bits2dec(self.tcpFrame[16:32]))
        self.seqNO = str(bits2dec(self.tcpFrame[32:64]))
        self.ackNO = str(bits2dec(self.tcpFrame[64:96]))
        self.dataOffset= self.tcpFrame[96:100]
        self.res= str(bits2dec(self.tcpFrame[100:103]))
        self.ecn= str(bits2dec(self.tcpFrame[103:106]))
        self.ctrl= str(bits2dec(self.tcpFrame[106:112]))
        self.window= str(bits2dec(self.tcpFrame[112:128]))
        self.checksum= str(bits2dec(self.tcpFrame[128:144]))
        self.urgentPtr= str(bits2dec(self.tcpFrame[144:160]))

    
    def displayTCP(self):
        print("\n")
        print("   TCP  \n")
        print("   Source Port: "  + self.srcPort)
        print("   Destination Port: "  + self.dstPort)
        print("   Sequence Number: "  + self.seqNO)
        print("   ACK: "  + self.ackNO)
        print("   Data Offset: "  + str(bits2dec(self.dataOffset)))
        print("   Res: "  + self.res)
        print("   Ecn: "  + self.ecn)
        print("   Ctrl: "  + self.ctrl)
        print("   Window: "  + self.window)
        print("   Checksum: "  + self.checksum)
        print("   Urgent Ptr: "  + self.urgentPtr)

    def getDataOffset(self):
        
        return self.dataOffset

    def getSrcPort(self):

        return self.srcPort

class intTCPOption():

    def __init__(self,hexStream,TCPLen):

        #INT TCP Option has 24 hexa carachteres
        self.tcpOptionsFrameAux = hexStream[(264):(288)]
        self.tcpOptionsFrame= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.tcpOptionsFrameAux])
        self.kind= str(bits2hex(self.tcpOptionsFrame[0:8]))
        self.length= str(bits2dec(self.tcpOptionsFrame[8:16]))
        self.path= str(bits2dec(self.tcpOptionsFrame[16:32]))
        self.pathLatency= str(bits2dec(self.tcpOptionsFrame[32:96]))

    
    def displayIntTCPOption(self):
        print("\n")
        print("   TCP INT Option  \n")
        print("   Kind: "+self.kind)
        print("   Length: "  + self.length)
        print("   Path: "  + self.path)
        print("   Path Latency: "  + self.pathLatency)

    def getPath(self):

        return self.path
    

    def getPathLatency(self):

        return self.pathLatency


class telemetryReportGroup():


    def __init__(self,hexStream):
        self.telemetryReportGroupAux = hexStream[(84):(100)]
        self.telemetryReportGroup= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.telemetryReportGroupAux])  
        self.version=self.telemetryReportGroup[0:4]
        self.hardwareID=self.telemetryReportGroup[4:10]
        self.sequenceNumber=self.telemetryReportGroup[10:32]
        self.nodeID=self.telemetryReportGroup[32:64]

    def displayTelemetryReportGroup(self):
        print("\n")
        print("   Telemetry Report Group  \n")
        print("   Version: " + str(bits2hex(self.version)))
        print("   Hardware ID: " + str(bits2hex(self.hardwareID)))
        print("   SequenceNumber: " + str(bits2dec(self.sequenceNumber)))
        print("   Node ID: " + str(bits2hex(self.nodeID)))

               
    def getSinkID(self):
        return str(bits2hex(self.nodeID))

class individualReport():


    def __init__(self,hexStream):
        self.individualReportAux = hexStream[(100):(124)]
        self.individualReport= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.individualReportAux])  
        self.repType=self.individualReport[0:4]
        self.innerType=self.individualReport[4:8]
        self.reportLength=self.individualReport[8:16]
        self.mDLength=self.individualReport[16:24]
        self.D=self.individualReport[24:25]
        self.Q=self.individualReport[25:26]
        self.F=self.individualReport[26:27]
        self.I=self.individualReport[27:28]
        self.rsvd=self.individualReport[28:32]
        self.repMdBits=self.individualReport[32:48]
        self.domainSpecificID=self.individualReport[48:64]
        self.dSMDBits=self.individualReport[64:80]
        self.dSMDStatus=self.individualReport[80:96]


       
    def displayIndividualReport(self):

        print("\n")
        print("   Individual Report  \n")
        print("   Report Type: " + str(bits2hex(self.repType)))
        print("   Inner Type: " + str(bits2hex(self.innerType)))
        print("   Report Length: " +str(bits2dec(self.reportLength)))
        print("   MD Length: " + str(bits2hex(self.mDLength)))
        print("   D: " + str(bits2hex(self.D)))
        print("   Q: " + str(bits2hex(self.Q)))
        print("   F: " + str(bits2hex(self.F)))
        print("   I " + str(bits2hex(self.I)))
        print("   Rsvd: " + str(bits2hex(self.rsvd)))
        print("   RepMDBits: " + str(bits2hex(self.repMdBits)))
        print("   Domain Specific ID: " + str(bits2hex(self.domainSpecificID)))
        print("   DS MD Bits: " + str(bits2hex(self.dSMDBits)))
        print("   DS MD Status: " + str(bits2hex(self.dSMDStatus)))




class SinkMetadata():

    def __init__(self,hexStream):

        self.latency = hexStream[(124):(140)]
        self.ingressTimestamp=hexStream[140:156]
        self.egressTimestamp=hexStream[156:172]
        self.queue_delay=hexStream[(172):(180)]
        self.queue_depth=hexStream[(180):(184)]


    def getLatency(self):
        return str(hex2dec(self.latency))

    def displayMetadata(self):
        print("\n")
        print("   Sink Node Metadata  \n")
        print("   Sink Node Latency: " + str(hex2dec(self.latency)))
        print("   Sink Node Ingress Timestamp: " + str(hex2dec(self.ingressTimestamp)))
        print("   Sink Node Egress Timestamp: " + str(hex2dec(self.egressTimestamp)))
        print("   Sink Node Queue Delay: " + str(hex2dec(self.queue_delay)))
        print("   Sink Node Queue Depth: " + str(hex2dec(self.queue_depth)))


    def getQueueDelay(self):
        return str(hex2dec(self.queue_delay))

    def getQueueDepth(self):
        return str(hex2dec(self.queue_depth))

    def getIngressTimestamp(self):
        return str(hex2dec(self.ingressTimestamp))

    def getEgressTimestamp(self):
        return str(hex2dec(self.egressTimestamp))

class shim():
    
    def __init__(self,hexStream,TCPLen):
        
        self.shimFrameAux = hexStream[(224+TCPLen):(224+8+TCPLen)]
        self.shimFrame= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.shimFrameAux])  
        self.shim_Type= self.shimFrame[0:4]
        self.shim_npt = self.shimFrame[4:6]
        self.shim_rsvd = self.shimFrame[6:7]
        self.shim_rsvd2 = self.shimFrame[7:8]
        self.len = self.shimFrame[8:16]
        self.dscp = self.shimFrame[16:22]
        self.shim_rsvd3 = self.shimFrame[22:32]
    
    def getNextProtocol(self):
        return self.nextProtocol
    
    def displaySHIM(self):
        print("\n")
        print("   Shim  ")
        print("\n")
        print("   Type: " +  str(bits2dec(self.shim_Type)))
        print("   Npt: " +  str(bits2dec(self.shim_npt )))
        print("   Reserved1: " + str(bits2dec(self.shim_rsvd )))
        print("   Reserved2: " +  str(bits2dec(self.shim_rsvd2 )))
        print("   Length: " +   str(bits2dec(self.len )))
        print("   Dscp: " +  str(bits2dec(self.dscp )))
        print("   Reserved3: " +  str(bits2dec(self.shim_rsvd3 )))

class iNTMDMetadata():
    
    def __init__(self,hexStream,TCPLen):
        
        self.intMetadataHeaderAux = hexStream[(232+TCPLen):(232+24+TCPLen)]
        self.intMetadataHeader= ''.join(['{0:04b}'.format(int(d, 16)) for d in self.intMetadataHeaderAux])    
        self.versionBits = str(bits2dec(self.intMetadataHeader[0:4]))
        self.d = self.intMetadataHeader[4:5]
        self.e= self.intMetadataHeader[5:6]
        self.m = self.intMetadataHeader[6:7]
        self.reservedBits = self.intMetadataHeader[7:19]
        self.hopMetadataLen = str(bits2dec(self.intMetadataHeader[19:24]))
        self.remainingHopCount = str(bits2dec(self.intMetadataHeader[24:32]))
        self.instructionMask = str(bits2dec(self.intMetadataHeader[32:48]))
        self.domainSpecificID = str(bits2dec(self.intMetadataHeader[48:64]))
        self.dsInstruction = str(bits2dec(self.intMetadataHeader[64:80]))
        self.dsFlags = str(bits2dec(self.intMetadataHeader[80:96]))

    
    def displayINTMDMetadata(self):
        
        
        print("\n")
        print("   INT MD Metadata  \n")

        print("   Version: " + self.versionBits )
        print("   D: " + self.d )
        print("   E: " +   self.e)
        print("   M: "  + self.m )
        print("   Reserved: "  + self.reservedBits)
        print("   Hop Metadata Length: " + self.hopMetadataLen )
        print("   Remainining Hop Count: " + self.remainingHopCount )
        print("   Instruction Mask: " +  self.instructionMask )
        print("   Domain Specific ID: "+ self.domainSpecificID )
        print("   Ds_Instruction: " + self.dsInstruction )
        print("   Ds_Flags: "  + self.dsFlags )

    def getRemainingHopCount(self):

        return self.remainingHopCount

class intMetadata():


    def __init__(self,hexStream,numNodes,TCPLen):
        
        self.start=232+24+TCPLen

        if numNodes==1:
        
            self.metadata = hexStream[(self.start):(self.start+default_metadata_stack_size*4*2)]
        
        else:
           
            self.start=self.start+((numNodes-1)*(default_metadata_stack_size*4*2))
            self.metadata = hexStream[(self.start):(self.start+default_metadata_stack_size*4*2)]

        self.switchID=self.metadata[0:4]
        self.latency = self.metadata[4:20]
        self.ingressTimestamp=self.metadata[20:36]
        self.egressTimestamp=self.metadata[36:52]
        self.queue_delay=self.metadata[52:60]
        self.queue_depth=self.metadata[60:64]

    def displayINTMetadata(self):

        print("   Switch ID: " + str(hex2dec(self.switchID)))
        print("   Hop Latency"+": " + str(hex2dec(self.latency)))
        print("   Ingress Timestamp: " + str(hex2dec(self.ingressTimestamp)))
        print("   Egress Timestamp " + str(hex2dec(self.egressTimestamp)))
        print("   Queue Delay"+": " + str(hex2dec(self.queue_delay)))
        print("   Queue Depth"+": " + str(hex2dec(self.queue_depth)))
        print("\n")

    def getSwitchID(self):
        return str(hex2dec(self.switchID))
    
    def getLatency(self):
        return str(hex2dec(self.latency))

    def getQueueDelay(self):
        return str(hex2dec(self.queue_delay))

    def getQueueDepth(self):
        return str(hex2dec(self.queue_depth))

    
    def getIngressTimestamp(self):
        return str(hex2dec(self.ingressTimestamp))

    def getEgressTimestamp(self):
        return str(hex2dec(self.egressTimestamp))


def connectToDB():

    load_dotenv()
    
    token=os.getenv('TOKEN')

    org = os.getenv('ORG')
    
    url = "http://localhost:8086"

    write_client = influxdb_client.InfluxDBClient(url=url, token=token, org=org)

    return write_client


def sendToDB(INTdict,path,pathLatency,client):

    print ("\n  Sending Telemetry Data to InfluxDB ... ")

    myKeys = list(INTdict.keys())
    myKeys.sort()
    sorted_dict = {int(i): INTdict[i] for i in myKeys}

    org = os.getenv('ORG')

    bucket = os.getenv('BUCKET')

    write_api = client.write_api(write_options=SYNCHRONOUS)
    
    point=influxdb_client.Point("INT_measurement").tag("Path",path).field("Path Latency",int(pathLatency))

    link_latencies=list()

    for i in range (1,5):

        if(path=="1"):

            if(i==1 or i==2):
               
                link_latencies.insert(i,int(sorted_dict[i+1][1])-int(sorted_dict[i][2]))

            if(i==3):

                link_latencies.insert(i,int(sorted_dict[i+2][1])-int(sorted_dict[i][2]))

        if(path=="2"):

            if(i==1 or i==4):

                link_latencies.insert(i,int(sorted_dict[i+1][1])-int(sorted_dict[i][2]))

            if(i==2):

                link_latencies.insert(i,int(sorted_dict[i+2][1])-int(sorted_dict[i][2]))

    for key in sorted_dict:

        point.tag("Hop Latency Switch ID:"+str(key),sorted_dict[key][0])
        point.tag("Queue Delay Switch ID:" + str(key),sorted_dict[key][3])
        point.tag("Queue Depth Switch ID:" + str(key),sorted_dict[key][4])
    
    point.tag("Link Latency S1-S2:",link_latencies[0])

    if(path=="1"):
       
       point.tag("Link Latency S2-S3:",link_latencies[1])
       point.tag("Link Latency S3-S5:",link_latencies[2])

    if(path=="2"):

       point.tag("Link Latency S2-S3:",link_latencies[1])
       point.tag("Link Latency S3-S5:",link_latencies[2])


    write_api.write(bucket=bucket, org=org, record=point)

    time.sleep(1) # separate points by 1 second

        
    print ("\n  Flush Completed \n")

    print( "\n--------------------- INT Collector ---------------------\n" )





def parser(pkt):

    print( "" )
    #estabilish connection to DB
    client=connectToDB()
    INTdict = dict()
    #convert packet bytes to hex
    msg=bytes_hex(pkt)
    hexStream = msg.decode("utf-8")
    Ethernet_Header = Ethernet(hexStream)
    typeField = Ethernet_Header.getTypeFieldIP()
    Ethernet_Header.displayEthernet()
    if typeField == '0800':
        IP_Header = ip(hexStream,0)
        ipProtocol = IP_Header.getIPProtocol()
        IP_Header.displayIP()
        if ipProtocol == '11':
            UDP_Header = udp(hexStream)
            UDP_Header.displayUDP()
            dscp = IP_Header.getDSCP()
            if dscp == "0":
                Telemetry_Report_Group_Header=telemetryReportGroup(hexStream)
                Telemetry_Report_Group_Header.displayTelemetryReportGroup()
                Individual_Report_Header=individualReport(hexStream)
                Individual_Report_Header.displayIndividualReport()
                Sink_Metadata=SinkMetadata(hexStream)
                Sink_Metadata.displayMetadata()
                Encapsulated_IP_Header = ip(hexStream,1)
                Encapsulated_IP_Header.displayIP()
                INT_dscp = Encapsulated_IP_Header.getDSCP()
                if INT_dscp == "23":
                    Encapsulated_TCP_Header = tcp(hexStream)
                    Encapsulated_TCP_Header.displayTCP()
                    #len of tcp options
                    TCPLen=int((bits2dec(Encapsulated_TCP_Header.getDataOffset()))*4*2)
                    INTdict.setdefault(Telemetry_Report_Group_Header.getSinkID(), [])
                    INTdict[Telemetry_Report_Group_Header.getSinkID()].append(Sink_Metadata.getLatency())
                    INTdict[Telemetry_Report_Group_Header.getSinkID()].append(Sink_Metadata.getIngressTimestamp())
                    INTdict[Telemetry_Report_Group_Header.getSinkID()].append(Sink_Metadata.getEgressTimestamp())
                    INTdict[Telemetry_Report_Group_Header.getSinkID()].append(Sink_Metadata.getQueueDelay())
                    INTdict[Telemetry_Report_Group_Header.getSinkID()].append(Sink_Metadata.getQueueDepth())
                    INT_TCP_Option = intTCPOption(hexStream,TCPLen)
                    path=INT_TCP_Option.getPath()
                    INT_TCP_Option.displayIntTCPOption()
                    pathLatency=INT_TCP_Option.getPathLatency()
                    Shim_Header = shim(hexStream,TCPLen)
                    Shim_Header.displaySHIM()
                    INT_MD_Metadata_Header=iNTMDMetadata(hexStream,TCPLen)
                    INT_MD_Metadata_Header.displayINTMDMetadata()
                    hops=default_remaining_hop_count-int(INT_MD_Metadata_Header.getRemainingHopCount())
                    print("\n")
                    print("   INT Metadata Stack  \n")

                    for i in range(1,hops+1):

                        INT_Metadata_Header=intMetadata(hexStream,i,TCPLen)
                        INT_Metadata_Header.displayINTMetadata()
                        INTdict.setdefault(INT_Metadata_Header.getSwitchID(), [])
                        INTdict[INT_Metadata_Header.getSwitchID()].append(INT_Metadata_Header.getLatency())
                        INTdict[INT_Metadata_Header.getSwitchID()].append(INT_Metadata_Header.getIngressTimestamp())
                        INTdict[INT_Metadata_Header.getSwitchID()].append(INT_Metadata_Header.getEgressTimestamp())
                        INTdict[INT_Metadata_Header.getSwitchID()].append(INT_Metadata_Header.getQueueDelay())
                        INTdict[INT_Metadata_Header.getSwitchID()].append(INT_Metadata_Header.getQueueDepth())

                    sendToDB(INTdict,path,pathLatency,client)                

                else:
                    print( "Invalid INT IP DSCP" )

            else:
                print( "Invalid IP DSCP" )
        else:
            print( "Invalid UDP Header" )
    else:
        print( "Invalid Ethernet Header" )



#S5 ip address
VALID_SOURCE_IPS = ("10.0.4.40")
Collector_IP="10.0.4.4"

def handle_pkt(pkt):

    if IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        id_tup = (src_ip, dst_ip)
        if src_ip in VALID_SOURCE_IPS:
            if dst_ip == Collector_IP:
                parser(pkt)


def main():

    print( "\n--------------------- INT Collector ---------------------\n" )

    sniff(iface = "root-eth0",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()








