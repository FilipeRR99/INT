
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> MIRROR_SESSION_ID = 100;
const bit<32> SINK_NODE_ID = 5;

const bit<16> TYPE_ARP  = 0x0806;

const bit<16> ARP_HTYPE = 0x0001; //Ethernet Hardware type is 1
const bit<16> ARP_PTYPE = TYPE_IPV4; //Protocol used for ARP is IPV4
const bit<8>  ARP_HLEN  = 6; //Ethernet address size is 6 bytes
const bit<8>  ARP_PLEN  = 4; //IP address size is 4 bytes
const bit<16> ARP_REQ = 1; //Operation 1 is request
const bit<16> ARP_REPLY = 2; //Operation 2 is reply

typedef bit<9> PortId;
const PortId DROP_PORT = 0xF;

#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 64


#define MAX_HOPS 9

const bit<8>  DEFAULT_REMAINING_HOP_COUNT=3;

/*************************************************************************
************************** H E A D E R S  ********************************
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

header Tcp_option_end_h {

    bit<8> kind;

}

header Tcp_option_nop_h {
    bit<8> kind;
}

header Tcp_option_ss_h {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}

header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}

header Tcp_option_timestamp_h{
    bit<8>  kind;
    bit<8> length;
    bit<32> ts_value;
    bit<32> ts_echo_reply;
}

header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}

header Tcp_option_INT_h{
    bit<8>  kind;
    bit<8> length;
    bit<16> path;
    bit<64> pathLatency;
}

header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sack_h sack;
    Tcp_option_timestamp_h Tcp_option_Timestamp;
    Tcp_option_INT_h Tcp_option_INT;
}

typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
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



header arp_t {
  bit<16>   h_type;
  bit<16>   p_type;
  bit<8>    h_len;
  bit<8>    p_len;
  bit<16>   op_code;
  macAddr_t src_mac;
  ip4Addr_t src_ip;
  macAddr_t dst_mac;
  ip4Addr_t dst_ip;
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

    arp_t        arp;

    ethernet_header report_ethernet;
    ipv4_header     report_ipv4;
    udp_header      report_udp;


    telemetry_report_group_header  telemetry_report_group;
    individual_report_header        individual_report;

    ethernet_header    ethernet;
    ipv4_header        ipv4; 
    tcp_header		tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
    
    shim_header	shim;
    
    int_md_metadata_header int_md_metadata;
    
    int_metadata_stack_header[DEFAULT_REMAINING_HOP_COUNT] metadata_stack;
    
    //needed for the INT report
    sink_metadata_stack_header[1] sink_metadata_stack;
 
}


error { IPHeaderTooShort }
