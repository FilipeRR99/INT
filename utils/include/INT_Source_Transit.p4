//Header Size in 4 Byte Words
const bit<8>  INT_TCP_OPTION_SIZE= 3;
const bit<8>  INT_SHIM_HEADER_SIZE=1;
const bit<8>  INT_MD_METADATA_HEADER_SIZE=3;
const bit<5>  INT_METADATA_STACK_LENGTH=8;

/*************************************************************************
************************** INT SOURCE && TRANSIT *************************
*************************************************************************/

 control INT_Source_Transit (inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata){
                    

    action add_int_headers(switchID_t swid) {

        hdr.ipv4.dscp=0x17;
    
        //Add new tcp option
        
        hdr.tcp.dataOffset=hdr.tcp.dataOffset+(bit<4>)(INT_TCP_OPTION_SIZE);
        hdr.tcp_options_vec.push_front(1);
        hdr.tcp_options_vec[0].Tcp_option_INT.setValid();
        hdr.tcp_options_vec[0].Tcp_option_INT.kind=0x73;
        hdr.tcp_options_vec[0].Tcp_option_INT.length=0;
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
        hdr.shim.dscp=0;

        //MD Metadata Header
        hdr.int_md_metadata.setValid();
        hdr.int_md_metadata.ver=2;
        hdr.int_md_metadata.d=0;
        hdr.int_md_metadata.e=0;
        hdr.int_md_metadata.m=0;
        hdr.int_md_metadata.rsvd=0;
        hdr.int_md_metadata.hop_metadata_len= INT_METADATA_STACK_LENGTH;
        hdr.int_md_metadata.remaining_hop_cnt=DEFAULT_REMAINING_HOP_COUNT;  
        hdr.int_md_metadata.instruction_mask=0;
        hdr.int_md_metadata.domain_specific_id=0x0000;
        hdr.int_md_metadata.ds_instruction=0;
        hdr.int_md_metadata.ds_flags=0; 
        
        
        hdr.metadata_stack[0].setValid();  

        hdr.metadata_stack[0].ingress_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.metadata_stack[0].switch_id=(bit<16>)swid;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)((INT_SHIM_HEADER_SIZE +(bit<8>)INT_MD_METADATA_HEADER_SIZE+INT_TCP_OPTION_SIZE)*4+(bit<8>)(4*INT_METADATA_STACK_LENGTH));
        
  
    }

    action add_metadata(switchID_t swid){

        hdr.metadata_stack.push_front(1);
        hdr.metadata_stack[0].setValid();
        hdr.metadata_stack[0].ingress_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;	
        hdr.metadata_stack[0].switch_id=(bit<16>)swid;

        //update ipv4 total len

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)(4*INT_METADATA_STACK_LENGTH);

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


    table addMetadata {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_metadata;
            NoAction;
        }
        default_action = NoAction();
    }
    

    apply {

        if (hdr.ipv4.isValid() && hdr.ipv4.protocol==6 && hdr.tcp.ctrl==0x00000018 && hdr.ipv4.dstAddr==(0x0A000202)) {

            addINTHeaders.apply();
        
            if(hdr.ipv4.dscp==0x17){
            
                addMetadata.apply();
            
            }
        }
                

    }           
}


