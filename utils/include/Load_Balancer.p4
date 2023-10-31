/*************************************************************************
************************** LOAD BALANCER ***********************************
*************************************************************************/


register <bit<64>>(REGISTER_SIZE)  path1_values;
register <bit<64>>(REGISTER_SIZE)  path2_values;
register<bit<9>>(REGISTER_SIZE)  choosen_path_values;



control Load_Balance (inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata){

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

                if(meta.path1_latency !=0){

                    if(hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency>meta.path2_latency){

                        meta.egress_port = 2;

                    }

                    else{

                        meta.egress_port = 1;

                    }
                }

                meta.path1_latency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency;
        
            }

            if(hdr.tcp_options_vec[0].Tcp_option_INT.path==2){

                if(meta.path2_latency!=0){

                    if(hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency>meta.path1_latency){

                        meta.egress_port = 1; 


                    }

                    else{
                        
                        meta.egress_port = 2;
                        
                    }
                }

                meta.path2_latency=hdr.tcp_options_vec[0].Tcp_option_INT.pathLatency;
            
            }
            
            choosen_path_values.write((bit<32>)meta.register_index,(bit<9>)meta.egress_port);
            path1_values.write((bit<32>)meta.register_index, meta.path1_latency); 
            path2_values.write((bit<32>)meta.register_index, meta.path2_latency);

            }   
    
        
    }


    table loadBalance{

        actions = {

            load_balance;

        }
        
    }

    apply {

        loadBalance.apply();
       
        }
            
}


