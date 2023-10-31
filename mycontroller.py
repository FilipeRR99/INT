#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def writeArpRules(p4info_helper, ingress_sw, dst_ip_addr, reply_mac):

    table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp",
            match_fields={
           "hdr.arp.dstAddr": dst_ip_addr
            },
            action_name="MyIngress.arp_reply",
            action_params={
                "requestMac":reply_mac,
            })
    
    ingress_sw.WriteTableEntry(table_entry)
    
    print ("Installed ARP rule non switch %s" % ingress_sw.name)

def writeForwardRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr,port):


        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
           "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
            },
            action_name="MyIngress.set_nhop",
            action_params={
                "dstAddr": dst_eth_addr,
                "port":port,
                "swid": int(ingress_sw.name[1])
            })

        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ingress rule on %s" % ingress_sw.name)

def writeEcmpGroupRules(p4info_helper, ingress_sw, dst_ip_addr,ecmp_group, num_nhops):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
           "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ecmp_group",
        action_params={
            "ecmp_group_id": ecmp_group,
            "num_nhops":num_nhops
       }
       
       
       
       
       )


    ingress_sw.WriteTableEntry(table_entry)
    print("Installed ECMP Group rule on %s" % ingress_sw.name)
    


def writeEcmpRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr,port,group_id,hash_id):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ecmp_group_to_nhop",
            match_fields={
            "meta.ecmp_group_id": group_id,
            "meta.ecmp_hash":hash_id
            },
            action_name="MyIngress.set_nhop",
            action_params={
                "dstAddr": dst_eth_addr,
                "port":port,
                "swid": int(ingress_sw.name[1])
            })

        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ECMP rule on %s" % ingress_sw.name)


def writeEgressMetadataRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.egressMetadata",
        match_fields={
           "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
            },
        action_name="MyEgress.add_egress_Metadata",

        )
        
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed egress INT rule on %s" % ingress_sw.name)


def writeSourceRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.addINTHeaders",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.add_int_headers",
                action_params={
            "swid": int(ingress_sw.name[1])
        })
    
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed source rule on %s" % ingress_sw.name)



def writeSinkRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.rmINTHeaders",

        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyEgress.remove_int_headers",
    )
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed sink rule on %s" % ingress_sw.name)


def writeTransitRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.addTransitInfo",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.add_transit_info",
        action_params={
            "swid": int(ingress_sw.name[1])
        })
    
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed transit rule on %s" % ingress_sw.name)



def writeReportRules(p4info_helper, ingress_sw):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.intReporting",
        action_name="MyEgress.report",
        action_params={
            "source_mac": "00:00:00:00:00:00",
            "source_ip":"10.0.4.40",
            "collector_ip":"10.0.4.4",
            "collector_mac":"08:00:00:00:04:44",
            "collector_port":1024,
            "swid":int(ingress_sw.name[1])
        }
    )
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed report rule on %s" % ingress_sw.name)


def writeLoadBalanceRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.loadBalance",
        action_name="MyIngress.load_balance",
        
    )
    
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed load balance rule on %s" % ingress_sw.name)



def writeReturnLatencyValueRules(p4info_helper,ingress_sw):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.returnLatencyValue",
        action_name="return_packet",
        
    )
    
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed Return Latency Value rule on %s" % ingress_sw.name)



def writeRemoveTCPOptionRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.rmTCPOption",

        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyEgress.remove_int_tcp_option",
    )
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed remove INT TCP Option rule on %s" % ingress_sw.name)

def writeTagFrequencyRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.tagFrequency",
        match_fields={
           "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
            },
        action_name="MyIngress.tag_freq",
        )
        
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed tag frequency INT rule on %s" % ingress_sw.name)



def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()



def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s6;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50001',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        s2= p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50002',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50003',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50004',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        s5 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s5',
            address='127.0.0.1:50005',
            device_id=4,
            proto_dump_file='logs/s5-p4runtime-requests.txt')

        s6 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s6',
            address='127.0.0.1:50006',
            device_id=5,
            proto_dump_file='logs/s6-p4runtime-requests.txt')
        

        
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()
        s5.MasterArbitrationUpdate()
        s6.MasterArbitrationUpdate()


        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")

        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")

        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)

        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)

        print("Installed P4 Program using SetForwardingPipelineConfig on s4")

        s5.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)

        print("Installed P4 Program using SetForwardingPipelineConfig on s5")

        s6.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s6")
        

        switches=[s1,s2,s3,s4,s5,s6]

        default_gws={'10.0.1.10':'08:00:00:00:01:00','10.0.2.20':'08:00:00:00:02:00','10.0.3.30':'08:00:00:00:03:00','10.0.4.40':'08:00:00:00:04:00'}
        
        for i in switches:
            for y in default_gws.keys():
                writeArpRules(p4info_helper, ingress_sw=i,dst_ip_addr = y, reply_mac=default_gws[y])
                
   
        
        writeForwardRules(p4info_helper, ingress_sw=s1,dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=2)

        writeForwardRules(p4info_helper, ingress_sw=s2,dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=1)


        writeEcmpGroupRules(p4info_helper,ingress_sw=s5,dst_ip_addr="10.0.1.1",ecmp_group=1, num_nhops=2)
        
        writeEcmpRules(p4info_helper,ingress_sw=s5,dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=1,group_id=1,hash_id=0)

        writeEcmpRules(p4info_helper,ingress_sw=s5,dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=2,group_id=1,hash_id=1)
        

        writeForwardRules(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=2)
        
        writeForwardRules(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=2)


        writeForwardRules(p4info_helper, ingress_sw=s5,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=3)

        writeForwardRules(p4info_helper, ingress_sw=s6,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2",port=2)

        writeForwardRules(p4info_helper, ingress_sw=s6,
                       dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=1)

        writeForwardRules(p4info_helper, ingress_sw=s6,
            dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3",port=1)

        writeForwardRules(p4info_helper, ingress_sw=s4,
                       dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=1)
        
        
        writeForwardRules(p4info_helper, ingress_sw=s3,
                   dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=1)

        writeForwardRules(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=3)

        writeForwardRules(p4info_helper, ingress_sw=s1,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1",port=1)


        writeForwardRules(p4info_helper, ingress_sw=s6,
                         dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=1)

        writeForwardRules(p4info_helper, ingress_sw=s1,
                        dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=2)
       
        writeForwardRules(p4info_helper, ingress_sw=s2,
                        dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=2)

        writeForwardRules(p4info_helper, ingress_sw=s3,
                        dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=2)

        writeForwardRules(p4info_helper, ingress_sw=s4,
                        dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=2)

        writeForwardRules(p4info_helper, ingress_sw=s4,
            dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3",port=3)

        writeForwardRules(p4info_helper, ingress_sw=s5,
                        dst_eth_addr="08:00:00:00:04:44", dst_ip_addr="10.0.4.4",port=4)

        writeForwardRules(p4info_helper, ingress_sw=s5,
                        dst_eth_addr="08:00:00:00:03:33", dst_ip_addr="10.0.3.3",port=2)

     
        writeSourceRules(p4info_helper, ingress_sw=s1,
                     dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeEgressMetadataRules(p4info_helper, ingress_sw=s1,
                          dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeEgressMetadataRules(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeEgressMetadataRules(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        
        writeEgressMetadataRules(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")
        
        writeTransitRules(p4info_helper, ingress_sw=s2,
                   dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeTransitRules(p4info_helper, ingress_sw=s3,
                      dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        
        writeTransitRules(p4info_helper, ingress_sw=s4,
                      dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeTransitRules(p4info_helper, ingress_sw=s5,
                   dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeEgressMetadataRules(p4info_helper, ingress_sw=s5,
            dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeSinkRules(p4info_helper, ingress_sw=s5,
                     dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

                
        writeReportRules(p4info_helper, ingress_sw=s5)

        writeLoadBalanceRules(p4info_helper, ingress_sw=s2, dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

        writeReturnLatencyValueRules(p4info_helper,ingress_sw=s6)

        writeRemoveTCPOptionRules(p4info_helper, ingress_sw=s6,dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='P4Runtime Controller')

    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/INT.p4.p4info.txt')

    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                    type=str, action="store", required=False,
                    default='./build/INT.json')
    
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)