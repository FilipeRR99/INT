-- protocol naming
p4_report_udp = Proto('p4_report_udp','P4_REPORT_UDPProtocol')

-- protocol fields
local p4_report_udp_srcPort = ProtoField.string('p4_report_udp.srcPort','Source Port')
local p4_report_udp_dstPort = ProtoField.string('p4_report_udp.dstPort','Destination Port')
local p4_report_udp_len = ProtoField.string('p4_report_udp.len','Len')
local p4_report_udp_checksum = ProtoField.string('p4_report_udp.checksum','Checksum')
p4_report_udp.fields = {p4_report_udp_srcPort, p4_report_udp_dstPort, p4_report_udp_len, p4_report_udp_checksum}


-- protocol dissector function
function p4_report_udp.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_REPORT_UDP'
    local subtree = tree:add(p4_report_udp,buffer(),'P4_REPORT_UDP Protocol Data')
        subtree:add(p4_report_udp_srcPort,tostring(buffer(0,2):bitfield(0,16)))
        subtree:add(p4_report_udp_dstPort,tostring(buffer(2,2):bitfield(0,16)))
        subtree:add(p4_report_udp_len,tostring(buffer(4,2):bitfield(0,16)))
        subtree:add(p4_report_udp_checksum,tostring(buffer(6,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_report_udp_dstPort')
    mydissectortable:try(buffer(2,2):bitfield(0,16), buffer:range(8):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

local newdissectortable = DissectorTable.new('p4_report_udp_dstPort','P4_REPORT_UDP_DSTPORT',ftypes.STRING)



-- protocol registration
my_table = DissectorTable.get('p4_ipv4.protocol')
my_table:add(0x11,p4_report_udp)

