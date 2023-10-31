control Arp (inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata){

        action drop() {
            mark_to_drop(standard_metadata);
        }
        
        action arp_reply(macAddr_t request_mac) {

        hdr.arp.op_code = ARP_REPLY;
        
        hdr.arp.dst_mac = hdr.arp.src_mac;
        
        hdr.arp.src_mac = request_mac;

        hdr.arp.src_ip = hdr.arp.dst_ip;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        
        hdr.ethernet.srcAddr = request_mac;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
        
        }


        table arp_exact {
        key = {
            hdr.arp.dst_ip: exact;
        }
        actions = {
            arp_reply;
            drop;
        }
        size = 1024;
        default_action = drop;
        }

        apply {

            arp_exact.apply();

                
        }

}