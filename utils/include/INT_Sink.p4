/*************************************************************************
************************** INT SINK ************************************
*************************************************************************/

 control INT_Sink (inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata){

    
    action remove_int_headers() {
        
        //update ipv4 total len field

        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)(((INT_SHIM_HEADER_SIZE + (bit<8>)INT_MD_METADATA_HEADER_SIZE)*4)
        + (DEFAULT_REMAINING_HOP_COUNT-hdr.int_md_metadata.remaining_hop_cnt)*(bit<8>)(4*INT_METADATA_STACK_LENGTH));

        //hdr.ipv4.dscp=hdr.shim.dscp;
        hdr.shim.setInvalid();
        hdr.int_md_metadata.setInvalid();
        hdr.metadata_stack.push_front(DEFAULT_REMAINING_HOP_COUNT);
        hdr.ipv4.dscp=0;
            
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

        hdr.individual_report.report_length= (bit<8>)(64+256+hdr.ipv4.totalLen) >> 5;
        
        hdr.individual_report.metadata_length=8;
        hdr.individual_report.d=0;
        hdr.individual_report.q=0;
        hdr.individual_report.f=1;
        hdr.individual_report.i=0;
        hdr.individual_report.rsvd=0;
        hdr.individual_report.repMdBits=0;
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

    table intReporting {
        actions = {
            report;
        }        
    }

    apply {

        if (hdr.tcp.ctrl==0x00000018 && standard_metadata.instance_type == 0 && hdr.ipv4.dscp==0x17){

            rmINTHeaders.apply();

        }

        if (standard_metadata.instance_type == 1) {
                 
                intReporting.apply();

        }
            
    }
}



