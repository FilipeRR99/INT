-- protocol naming
p4_tcp = Proto('p4_tcp','P4_TCPProtocol')

-- protocol fields
local p4_tcp_srcPort = ProtoField.string('p4_tcp.srcPort','Source Port')
local p4_tcp_dstPort = ProtoField.string('p4_tcp.dstPort','Destination Port')
local p4_tcp_seqNo = ProtoField.string('p4_tcp.seqNo','Sequence Number')
local p4_tcp_ackNo = ProtoField.string('p4_tcp.ackNo','ACK Number')
local p4_tcp_dataOffset = ProtoField.string('p4_tcp.dataOffset','Data Offset')
local p4_tcp_res = ProtoField.string('p4_tcp.res','Res')
local p4_tcp_ecn = ProtoField.string('p4_tcp.ecn','Ecn')
local p4_tcp_ctrl = ProtoField.string('p4_tcp.ctrl','Ctrl')
local p4_tcp_window = ProtoField.string('p4_tcp.window','Window')
local p4_tcp_checksum = ProtoField.string('p4_tcp.checksum','Checksum')
local p4_tcp_urgentPtr = ProtoField.string('p4_tcp.urgentPtr','Urgent Pointer')
p4_tcp.fields = {p4_tcp_srcPort, p4_tcp_dstPort, p4_tcp_seqNo, p4_tcp_ackNo, p4_tcp_dataOffset, p4_tcp_res, p4_tcp_ecn, p4_tcp_ctrl, p4_tcp_window, p4_tcp_checksum, p4_tcp_urgentPtr}


-- protocol dissector function
function p4_tcp.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_TCP'
    local subtree = tree:add(p4_tcp,buffer(),'P4_TCP Protocol Data')
        subtree:add(p4_tcp_srcPort,tostring(buffer(0,2):bitfield(0,16)))
        subtree:add(p4_tcp_dstPort,tostring(buffer(2,2):bitfield(0,16)))
        subtree:add(p4_tcp_seqNo,tostring(buffer(4,4):bitfield(0,32)))
        subtree:add(p4_tcp_ackNo,tostring(buffer(8,4):bitfield(0,32)))
        subtree:add(p4_tcp_dataOffset,tostring(buffer(12,1):bitfield(0,4)))
        subtree:add(p4_tcp_res,tostring(buffer(12,1):bitfield(4,3)))
        subtree:add(p4_tcp_ecn,tostring(buffer(12,2):bitfield(7,3)))
        subtree:add(p4_tcp_ctrl,tostring(buffer(13,1):bitfield(2,6)))
        subtree:add(p4_tcp_window,tostring(buffer(14,2):bitfield(0,16)))
        subtree:add(p4_tcp_checksum,tostring(buffer(16,2):bitfield(0,16)))
        subtree:add(p4_tcp_urgentPtr,tostring(buffer(18,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_tcp_dataOffset')
    mydissectortable:try(buffer(12,1):bitfield(0,4), buffer:range(20):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)

local newdissectortable = DissectorTable.new('p4_tcp_dataOffset','p4_TCP_dataOffset',ftypes.STRING)
-- protocol registration
my_table = DissectorTable.get('p4_ipv4.protocol')
my_table:add(6,p4_tcp)
