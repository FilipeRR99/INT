/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> IPV4 = 0x800;
const bit<8>  DEFAULT_REMAINING_HOP_COUNT=3;
const bit<32> MIRROR_SESSION_ID = 100;
const bit<32> SINK_NODE_ID = 5;

//Header Size in 4 Byte Words
const bit<8>  INT_TCP_OPTION_SIZE= 3;
const bit<8>  INT_SHIM_HEADER_SIZE=1;
const bit<8>  INT_MD_METADATA_HEADER_SIZE=3;
const bit<8>  INT_METADATA_STACK_LENGTH=8;

typedef bit<9> PortId;
const PortId DROP_PORT = 0xF;

#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 64


#define MAX_HOPS 9

/*************************************************************************
********************* H E A D E R S  *********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qdepth_t;
typedef bit<32> switchID_t;





header ethernet_header {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv4_header {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;       
}


header tcp_header {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header Tcp_option_end_header {

    bit<8> kind;

}

header Tcp_option_nop_header {
    bit<8> kind;
}

header Tcp_option_ss_header {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}

header Tcp_option_s_header {
    bit<8>  kind;
    bit<24> scale;
}

header Tcp_option_timestamp_header{
    bit<8>  kind;
    bit<8> length;
    bit<32> ts_value;
    bit<32> ts_echo_reply;
}

header Tcp_option_sack_header {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}

header Tcp_option_INT_header{
    bit<8>  kind;
    bit<8> length;
    bit<16> path;
    bit<64> pathLatency;
}

header_union Tcp_option_header {
    Tcp_option_end_header  end;
    Tcp_option_nop_header  nop;
    Tcp_option_ss_header   ss;
    Tcp_option_s_header    s;
    Tcp_option_sack_header sack;
    Tcp_option_timestamp_header Tcp_option_Timestamp;
    Tcp_option_INT_header Tcp_option_INT;
}

typedef Tcp_option_header[10] Tcp_option_stack;

header Tcp_option_padding_header {
    varbit<256> padding;
}

struct Tcp_option_sack_top {
    bit<8> kind;
    bit<8> length;
}


header udp_header {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}



header shim_header {
    bit<4> type;
    bit<2> npt;
    bit<1> reserved1;
    bit<1> reserved2;
    bit<8> len;  
    bit<6> dscp;
    bit<10> reserved3;
}

header int_md_metadata_header {
    bit<4>  ver;
    bit<1>  d;
    bit<1>  e;
    bit<1>  m;
    bit<12> rsvd;
    bit<5>  hop_metadata_len;   
    bit<8>  remaining_hop_cnt;  
    bit<16> instruction_mask;
    bit<16> domain_specific_id;
    bit<16> ds_instruction;
    bit<16> ds_flags;
}


header int_metadata_stack_header {

    bit<16> switch_id;
    bit<64> hop_latency;
    bit<64> ingress_timestamp;   
    bit<64> egress_timestamp;  
    bit<32> queue_delay;
    bit<16> queue_depth;

}


header sink_metadata_stack_header{

    bit<64> sink_latency;
    bit<64> sink_ingress_timestamp;   
    bit<64> sink_egress_timestamp;  
    bit<32> sink_queue_delay;
    bit<16> sink_queue_depth;

}



header telemetry_report_group_header {
    bit<4> ver;
    bit<6> hw_id;
    bit<22> seq_num;
    bit<32> node_id;
}




header individual_report_header {

    bit<4> rep_type;
    bit<4> inner_type;
    bit<8> report_length;
    bit<8> metadata_length;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<1> i;
    bit<4> rsvd;
    bit<16> repMdBits;
    bit<16> domainSpecificID;
    bit<16> dSMDBits;
    bit<16> dSMDStatus;

}



header arp_header {

  bit<16>   hardware_type;
  bit<16>   protocol_type;
  bit<8>    hardware_address_len;
  bit<8>    protocol_address_len;
  bit<16>   operation_code;
  macAddr_t srcMac;
  ip4Addr_t srcAddr;
  macAddr_t dstMac;
  ip4Addr_t dstAddr;

  }


struct metadata {

    bit<16> metadata_stack_remaining;
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
    
    bit<64> last_stamp;
    bit<64> time_diff;
    

    bit<13> register_index;

    bit<13> s5_register_index;
    
    bit<9> egress_port;
    
    bit<9> s5_egress_port;

    bit<64> path1_latency;
    bit<64> path2_latency;

    bit<64> last_latency;

    @field_list(1) bit<64> sink_ingress_timestamp;

    bit<32> tag_timestamp;
    bit<32> last_tag_timestamp;

    bit<64> path1_weight;
    bit<64> path2_weight;

}


struct headers {

    arp_header        arp;

    ethernet_header report_ethernet;
    ipv4_header     report_ipv4;
    udp_header      report_udp;


    telemetry_report_group_header  telemetry_report_group;
    individual_report_header        individual_report;

    ethernet_header    ethernet;
    ipv4_header        ipv4; 
    tcp_header		tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_header tcp_options_padding;
    
    shim_header	shim;
    
    int_md_metadata_header int_md_metadata;
    
    int_metadata_stack_header[DEFAULT_REMAINING_HOP_COUNT] metadata_stack;
    
    //needed for the INT report
    sink_metadata_stack_header[1] sink_metadata_stack;
 
}


error { IPHeaderTooShort }



/*************************************************************************
********************* P A R S E R  *********************************
*************************************************************************/

parser Tcp_option_parser(packet_in b, out Tcp_option_stack vec ){


    state start {
        transition select(b.lookahead<bit<8>>()) {
            8w0x0 : parse_tcp_option_end;
            8w0x1 : parse_tcp_option_nop;
            8w0x2 : parse_tcp_option_ss;
            8w0x3 : parse_tcp_option_s;
            8w0x5 : parse_tcp_option_sack;
            8w0x8 : parse_tcp_option_timestamp;
            8w0x73: parse_tcp_option_int;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        transition start;
    }
    state parse_tcp_option_nop {
         b.extract(vec.next.nop);
         transition start;
    }
    state parse_tcp_option_ss {
         b.extract(vec.next.ss);
         transition start;
    }
    state parse_tcp_option_s {
         b.extract(vec.next.s);
         transition start;
    }
    state parse_tcp_option_sack {
         bit<32> n = (bit<32>)b.lookahead<Tcp_option_sack_top>().length;
         b.extract(vec.next.sack, n);
         transition start;
    }

    
    state parse_tcp_option_timestamp {
            b.extract(vec.next.Tcp_option_Timestamp);
            transition accept;
        }
    


    state parse_tcp_option_int {
            b.extract(vec.next.Tcp_option_INT);
            transition start;
    }
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
              

    state start {
    	
        transition parse_ethernet;
         
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0806: parse_arp;
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
      packet.extract(hdr.arp);
        transition select(hdr.arp.operation_code) {
            1  : accept;
      }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select (hdr.ipv4.protocol) {
            6: parse_tcp;
            default:accept;
	    }
    
    }
           
    state parse_tcp{
        packet.extract(hdr.tcp);
        Tcp_option_parser.apply(packet,hdr.tcp_options_vec);
        transition select(hdr.ipv4.dscp) {
             0x17: parse_int;
             default: accept;       
        }
        
    }

    state parse_int {
        packet.extract(hdr.shim);
        packet.extract(hdr.int_md_metadata);
        transition select(hdr.int_md_metadata.ver) {
             2: parse_metadata_stack;
             default: accept;       
        }
    }

    state parse_metadata_stack {
        meta.metadata_stack_remaining = (bit<16>) (DEFAULT_REMAINING_HOP_COUNT - hdr.int_md_metadata.remaining_hop_cnt);
        transition select(meta.metadata_stack_remaining ) {
            0 : accept;
            default: parse_switch_metadata;
        }
    }

    state parse_switch_metadata {
        packet.extract(hdr.metadata_stack.next);
        meta.metadata_stack_remaining  = meta.metadata_stack_remaining - 1;
        transition select(meta.metadata_stack_remaining ) {
            0 : accept;
            default: parse_switch_metadata;
        }
    }
    
}


/*************************************************************************
**********   C H E C K S U M    V E R I F I C A T I O N   ***********
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
************  I N G R E S S   P R O C E S S I N G   *****************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

 
    
    action drop() {
        mark_to_drop(standard_metadata);
    }


    
    action add_int_headers(switchID_t swid) {

        //Add new tcp option
        hdr.tcp.dataOffset=hdr.tcp.dataOffset+(bit<4>)(INT_TCP_OPTION_SIZE);
        hdr.tcp_options_vec.push_front(1);
        hdr.tcp_options_vec[0].Tcp_option_INT.setValid();
        hdr.tcp_options_vec[0].Tcp_option_INT.kind=0x73;
        hdr.tcp_options_vec[0].Tcp_option_INT.length=12;
        hdr.tcp_options_vec[0].Tcp_option_INT.path=0;
        hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency=0;
        
            
        //shim header
        hdr.shim.setValid();
        
        hdr.shim.type=1;
        hdr.shim.npt=0;
        hdr.shim.reserved1=0;
        hdr.shim.reserved2=0;
        hdr.shim.len=INT_MD_METADATA_HEADER_SIZE;
        hdr.shim.reserved3=0;
        hdr.shim.dscp=hdr.ipv4.dscp;

        //MD Metadata Header
        hdr.int_md_metadata.setValid();
        hdr.int_md_metadata.ver=2;
        hdr.int_md_metadata.d=0;
        hdr.int_md_metadata.e=0;
        hdr.int_md_metadata.m=0;
        hdr.int_md_metadata.rsvd=0;
        hdr.int_md_metadata.hop_metadata_len= (bit<5>)INT_METADATA_STACK_LENGTH;
        hdr.int_md_metadata.remaining_hop_cnt=DEFAULT_REMAINING_HOP_COUNT;  
        hdr.int_md_metadata.instruction_mask=0x2C60;
        hdr.int_md_metadata.domain_specific_id=0x0000;
        hdr.int_md_metadata.ds_instruction=0;
        hdr.int_md_metadata.ds_flags=0; 
        
        
        hdr.metadata_stack[0].setValid();  

        hdr.metadata_stack[0].ingress_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.metadata_stack[0].switch_id=(bit<16>)swid;

        hdr.ipv4.dscp=0x17;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)((INT_SHIM_HEADER_SIZE +(bit<8>)INT_MD_METADATA_HEADER_SIZE+INT_TCP_OPTION_SIZE)*4+(bit<8>)(4*INT_METADATA_STACK_LENGTH));
        
        
    
    }


     action add_transit_info(switchID_t swid) {

        hdr.metadata_stack.push_front(1);
        hdr.metadata_stack[0].setValid();
        hdr.metadata_stack[0].ingress_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;	
        hdr.metadata_stack[0].switch_id=(bit<16>)swid;

        //update ipv4 total len

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)(4*INT_METADATA_STACK_LENGTH);
   

    }

    action arp_reply(macAddr_t requestMac) {

      hdr.arp.dstMac = hdr.arp.srcMac;
      
      hdr.arp.srcMac = requestMac;

      hdr.arp.srcAddr= hdr.arp.dstAddr;

      hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
      
      hdr.ethernet.srcAddr = requestMac;

      standard_metadata.egress_spec = standard_metadata.ingress_port;

      hdr.arp.operation_code = 2;
      
    }

    register <bit<64>>(REGISTER_SIZE)  path1_values;
    register <bit<64>>(REGISTER_SIZE)  path2_values;
    register<bit<9>>(REGISTER_SIZE)  choosen_path_values;

     action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    {hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol},
	    num_nhops);

	    meta.ecmp_group_id = ecmp_group_id;
     }





    action set_nhop(macAddr_t dstAddr, egressSpec_t port,switchID_t swid) {

        hash(meta.register_index, HashAlgorithm.crc16,
        (bit<16>)0,
        {hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        hdr.tcp.srcPort,
        hdr.tcp.dstPort,hdr.ipv4.protocol},
        (bit<14>)8192);

        choosen_path_values.read(meta.egress_port,(bit<32>)meta.register_index);

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
       
        hdr.ethernet.dstAddr = dstAddr;

        if(swid==2 && hdr.ipv4.dstAddr==(0x0A000202) && meta.egress_port!=0){

            standard_metadata.egress_spec=meta.egress_port;

        }
        
        
        else if (swid ==2 && hdr.ipv4.dstAddr==(0x0A000101) && hdr.ipv4.dscp == 0 && hdr.tcp.ctrl==0x00000018 && hdr.tcp_options_vec[0].Tcp_option_INT.kind==0x73){

            standard_metadata.egress_spec=DROP_PORT;
        
        }

        else if(swid == 5 && hdr.ipv4.dstAddr==(0x0A000101) && hdr.ipv4.dscp == 0 && hdr.tcp.ctrl==0x00000018 && hdr.tcp_options_vec[0].Tcp_option_INT.kind==0x73 ){

            standard_metadata.egress_spec=(bit<9>)hdr.tcp_options_vec[0].Tcp_option_INT.path;

        }

        else{

            standard_metadata.egress_spec = port;

        }
        
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    action load_balance(){

        @atomic{

        hash(meta.register_index, HashAlgorithm.crc16,
            (bit<16>)0,
            {hdr.ipv4.dstAddr,
            hdr.ipv4.srcAddr,
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,hdr.ipv4.protocol},
            (bit<14>)8192);
                
        //Read previous latency values
        
        path1_values.read(meta.path1_latency, (bit<32>)meta.register_index);

        path2_values.read(meta.path2_latency, (bit<32>)meta.register_index);

        
        if(hdr.tcp_options_vec[0].Tcp_option_INT.path==1){

            if(hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency>meta.path2_latency){

                meta.egress_port = 2;

            }

            else{

                meta.egress_port = 1;

            }
        

            meta.path1_latency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency;
    
        }

        if(hdr.tcp_options_vec[0].Tcp_option_INT.path==2){

            if(hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency>meta.path1_latency){

                meta.egress_port = 1; 


            }

            else{
                
                meta.egress_port = 2;
                
            }
 
            meta.path2_latency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency;
          
        }
        
        choosen_path_values.write((bit<32>)meta.register_index,(bit<9>)meta.egress_port);
        path1_values.write((bit<32>)meta.register_index, meta.path1_latency); 
        path2_values.write((bit<32>)meta.register_index, meta.path2_latency);

        }   
   
    }
    
    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        size = 1024;
        default_action = drop;
    }


     
    table addINTHeaders {
    	 key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_int_headers;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table addTransitInfo{
        
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            add_transit_info;
        }

    }


    table loadBalance{

        actions = {

            load_balance;
            drop;

        }
        
        default_action = drop;

    }

    table arp{
      key = {
        hdr.arp.dstAddr: exact;
      }
      actions = {
        arp_reply;
        drop;
      }
      
      default_action = drop;
    }



     apply {
        
        if (hdr.ethernet.etherType == 0x0806)
        {
          arp.apply();
        }
        else if(hdr.ethernet.etherType == 0x0800)
        {
            
            if(hdr.ipv4.isValid() && hdr.ipv4.protocol==6 && hdr.ipv4.dstAddr==(0x0A000202) && hdr.tcp.ctrl==0x00000018 && hdr.tcp_options_vec[0].Tcp_option_INT.kind==0x73){
                    
                    meta.sink_ingress_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;
                    clone_preserving_field_list(CloneType.I2E,100,1);

            }
                        
            if (hdr.ipv4.isValid() && hdr.ipv4.protocol==6 && hdr.tcp.ctrl==0x00000018 && hdr.ipv4.dstAddr==(0x0A000202)) {
                
                addINTHeaders.apply();
                
                if(hdr.ipv4.dscp==0x17){

                    addTransitInfo.apply();
                }
                

            }        

                
            if(hdr.ipv4.isValid()){

                @Atomic{

                    if(hdr.tcp_options_vec[0].Tcp_option_INT.kind==0x73 && hdr.ipv4.dscp!=0x17 && hdr.tcp.ctrl==0x00000018){

                        loadBalance.apply();
                         
                    }
                }
            }

                switch (ipv4_lpm.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                    }
                

            
           }

        }
     }        
       
    }





/*************************************************************************
**************  E G R E S S   P R O C E S S I N G   *****************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                 

    
    action remove_int_headers() {
        
        //update ipv4 total len field

        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)(((INT_SHIM_HEADER_SIZE + (bit<8>)INT_MD_METADATA_HEADER_SIZE)*4)
        + (DEFAULT_REMAINING_HOP_COUNT-hdr.int_md_metadata.remaining_hop_cnt)*(bit<8>)(4*INT_METADATA_STACK_LENGTH));

        hdr.shim.setInvalid();
        hdr.int_md_metadata.setInvalid();
        hdr.metadata_stack.push_front(DEFAULT_REMAINING_HOP_COUNT);

            
    }

    action remove_int_tcp_option(){

        hdr.tcp.dataOffset=hdr.tcp.dataOffset-(bit<4>)(INT_TCP_OPTION_SIZE);
        hdr.tcp_options_vec[0].Tcp_option_INT.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)((INT_TCP_OPTION_SIZE)*4);
        hdr.ipv4.dscp=hdr.shim.dscp;

    }

    action add_egress_Metadata(){

        if (hdr.ipv4.dscp==0x17){

                bit<64> link_latency = 0;     

                if (hdr.metadata_stack[0].switch_id!=1){

                    link_latency=hdr.metadata_stack[0].ingress_timestamp-hdr.metadata_stack[1].egress_timestamp;

                }

                hdr.metadata_stack[0].egress_timestamp=(bit<64>)standard_metadata.egress_global_timestamp;

                //Switch_Metadata

                hdr.metadata_stack[0].hop_latency=hdr.metadata_stack[0].egress_timestamp-hdr.metadata_stack[0].ingress_timestamp;

                hdr.metadata_stack[0].queue_delay=standard_metadata.deq_timedelta;
                
                hdr.metadata_stack[0].queue_depth=(bit<16>)standard_metadata.deq_qdepth;

                hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency+hdr.metadata_stack[0].hop_latency+link_latency;

                hdr.int_md_metadata.remaining_hop_cnt=hdr.int_md_metadata.remaining_hop_cnt-1;
                
                if(hdr.metadata_stack[0].switch_id==2){

                    hdr.tcp_options_vec[0].Tcp_option_INT.path=(bit<16>)standard_metadata.egress_port;
                }	 	
        
            }
            
        }


    action return_packet() {

        macAddr_t mac_tmp;
        mac_tmp = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac_tmp;
        
        ip4Addr_t ip_tmp;
        ip_tmp=hdr.ipv4.srcAddr;   
        hdr.ipv4.srcAddr=hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr=ip_tmp;

        //ip+tcp+tcp_int_option
        hdr.ipv4.totalLen=20+20+(bit<16>)(INT_TCP_OPTION_SIZE*4);

        hdr.tcp.dataOffset=(bit<4>)((20+(INT_TCP_OPTION_SIZE*4))/4);

        truncate((bit<32>)(hdr.ipv4.totalLen+14));

        hdr.ipv4.dscp=hdr.shim.dscp;
     

    }

/*************************************************************************
************************** INT REPORT ***********************************
*************************************************************************/

// Code adapted from:
// - https://github.com/GEANT-DataPlaneProgramming/int-platforms/blob/master/p4src/int_v1.0/include/int_report.p4


action report(bit<48> source_mac, bit<32> source_ip, bit<48> collector_mac, bit<32> collector_ip, bit<16> collector_port,switchID_t swid) {

    
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr = collector_mac;
        hdr.report_ethernet.srcAddr = source_mac;
        hdr.report_ethernet.etherType = 0x0800;

        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4;
        hdr.report_ipv4.ihl = 5;
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 0;
        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 1;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl = 64;
        hdr.report_ipv4.protocol = 17; 
        hdr.report_ipv4.srcAddr = source_ip;
        hdr.report_ipv4.dstAddr = collector_ip;

        //INT Packet new ipv4 header + new udp header + telemetry report group header + individual report header + sink node metadata + previous ipv4 total len

        hdr.report_ipv4.totalLen= 20 + 8 + 8 + 12 + 26 + hdr.ipv4.totalLen;

        hdr.ethernet.setInvalid();
        
        hdr.report_udp.setValid();

        hdr.report_udp.srcPort=0;
        
        hdr.report_udp.dstPort = collector_port;

        hdr.report_udp.len=hdr.report_ipv4.totalLen-24;


        hdr.telemetry_report_group.setValid();

        hdr.telemetry_report_group.ver=2;
        hdr.telemetry_report_group.hw_id=(bit<6>)swid;
        hdr.telemetry_report_group.seq_num=1;
        hdr.telemetry_report_group.node_id=swid;

        hdr.individual_report.setValid();

        hdr.individual_report.rep_type=1;
        hdr.individual_report.inner_type=4;
        
        //Indivdual report fixed size + md_length + original IPheader + TCP header + INT shim + INT Fixed Headers + INT Metadata + Original TCP Payload, represented in 4 Bytes Words

        hdr.individual_report.report_length= 10+(bit<8>)(hdr.ipv4.totalLen >> 5);
        
        hdr.individual_report.metadata_length=8;
        hdr.individual_report.d=0;
        hdr.individual_report.q=0;
        hdr.individual_report.f=1;
        hdr.individual_report.i=0;
        hdr.individual_report.rsvd=0;
        hdr.individual_report.repMdBits=0xACC0;
        hdr.individual_report.domainSpecificID=0;
        hdr.individual_report.dSMDBits=0;
        hdr.individual_report.dSMDStatus=0;

        hdr.sink_metadata_stack[0].setValid();

        hdr.sink_metadata_stack[0].sink_ingress_timestamp=meta.sink_ingress_timestamp;
        hdr.sink_metadata_stack[0].sink_egress_timestamp=(bit<64>)standard_metadata.egress_global_timestamp;
        hdr.sink_metadata_stack[0].sink_latency=hdr.sink_metadata_stack[0].sink_egress_timestamp-hdr.sink_metadata_stack[0].sink_ingress_timestamp;
        hdr.sink_metadata_stack[0].sink_queue_delay=standard_metadata.deq_timedelta;
        hdr.sink_metadata_stack[0].sink_queue_depth=(bit<16>)standard_metadata.deq_qdepth;

        bit<64> link_latency=hdr.sink_metadata_stack[0].sink_egress_timestamp-hdr.sink_metadata_stack[0].sink_ingress_timestamp;
        
        hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency + hdr.sink_metadata_stack[0].sink_latency+link_latency;
    }


    table egressMetadata {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_egress_Metadata;
            NoAction;
        }
        default_action = NoAction();
    }
    
    table rmINTHeaders {
    	key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            remove_int_headers;
            NoAction;
        }
        default_action = NoAction();
    }

     table rmTCPOption {
    	key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            remove_int_tcp_option;
            NoAction;
        }
        default_action = NoAction();
    }

    table intReporting {
        actions = {
            report;
        }        
    }

    table returnLatencyValue{
        actions={
            return_packet;
        }
    }

    apply {

        if (hdr.ipv4.isValid()) {


            if (hdr.tcp.ctrl==0x00000018 && standard_metadata.instance_type == 0 && hdr.ipv4.dscp==0x17){

                egressMetadata.apply();
                rmINTHeaders.apply();
                rmTCPOption.apply();

            }


  
            if (standard_metadata.instance_type == 1) {
                 
                returnLatencyValue.apply();
                intReporting.apply();
                

            }




        }
            
    }
}         


/*************************************************************************
***********   C H E C K S U M    C O M P U T A T I O N   ************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16)
        ;
         
         update_checksum(
            hdr.report_ipv4.isValid(),
            {

              hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr

            },
            hdr.report_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
    
}


/*************************************************************************
*********************  D E P A R S E R  *****************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.telemetry_report_group);
        packet.emit(hdr.individual_report);
        packet.emit(hdr.sink_metadata_stack);
        
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    	packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_vec);
        
        packet.emit(hdr.shim);
        packet.emit(hdr.int_md_metadata);
        packet.emit(hdr.metadata_stack);

    }
}

/*************************************************************************
*********************  S W I T C H  *****************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

