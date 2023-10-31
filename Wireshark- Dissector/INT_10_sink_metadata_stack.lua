-- protocol naming
p4_sink_metadata_stack = Proto('p4_sink_metadata_stack','P4_SINK_METADATA_STACK_Protocol')


-- protocol fields

local p4_metadata_stack_hop_latency = ProtoField.string('p4_metadata_stack_hop_latency','Hop Latency (microseconds)')
local p4_metadata_stack_ingress_timestamp = ProtoField.string('p4_metadata_stack_ingress_timestamp','Ingress Timestamp (microseconds)')
local p4_metadata_stack_egress_timestamp = ProtoField.string('p4_metadata_stack_egress_timestamp','Egress Timestamp (microseconds)')
local p4_metadata_stack_queue_delay = ProtoField.string('p4_metadata_stack_queue_delay','Queue Delay (microseconds)')
local p4_metadata_stack_queue_depth = ProtoField.string('p4_metadata_stack_queue_depth','Queue Depth')
p4_metadata_stack.fields = {p4_metadata_stack_hop_latency,p4_metadata_stack_ingress_timestamp,p4_metadata_stack_egress_timestamp, p4_metadata_stack_queue_delay, p4_metadata_stack_queue_depth}


-- protocol dissector function
function p4_sink_metadata_stack.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_SINK_METADATA'
    local subtree = tree:add(p4_int_md_metadata,buffer(),'P4_SINK_METADATA')
        subtree:add(p4_metadata_stack_hop_latency ,tostring(buffer(0,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_ingress_timestamp,tostring(buffer(8,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_egress_timestamp,tostring(buffer(16,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_queue_delay,tostring(buffer(24,4):bitfield(0,32)))
        subtree:add(p4_metadata_stack_queue_depth,tostring(buffer(28,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_sink_metadata_stack')
    mydissectortable:try(0, buffer:range(30):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_sink_metadata_stack','P4_SINK_METADATA_STACK',ftypes.STRING)

-- protocol registration
my_table = DissectorTable.get('p4_individual_report')
my_table:add(0x01,p4_sink_metadata_stack)




----------------------------------------------------------IPV4 Report---------------------------------------------------------------------------


-- protocol naming
p4_original_ipv4 = Proto('p4_original_ipv4','P4_Original_IPV4Protocol')

-- protocol fields
local p4_ipv4_version = ProtoField.string('p4_ipv4.version','version')
local p4_ipv4_ihl = ProtoField.string('p4_ipv4.ihl','ihl')
local p4_ipv4_dscp = ProtoField.string('p4_ipv4.dscp','dscp')
local p4_ipv4_ecn = ProtoField.string('p4_ipv4.ecn','ecn')
local p4_ipv4_totalLen = ProtoField.string('p4_ipv4.totalLen','totalLen')
local p4_ipv4_identification = ProtoField.string('p4_ipv4.identification','identification')
local p4_ipv4_flags = ProtoField.string('p4_ipv4.flags','flags')
local p4_ipv4_fragOffset = ProtoField.string('p4_ipv4.fragOffset','fragOffset')
local p4_ipv4_ttl = ProtoField.string('p4_ipv4.ttl','ttl')
local p4_ipv4_protocol = ProtoField.string('p4_ipv4.protocol','protocol')
local p4_ipv4_hdrChecksum = ProtoField.string('p4_ipv4.hdrChecksum','hdrChecksum')
local p4_ipv4_srcAddr = ProtoField.string('p4_ipv4.srcAddr','srcAddr')
local p4_ipv4_dstAddr = ProtoField.string('p4_ipv4.dstAddr','dstAddr')
p4_original_ipv4.fields = {p4_ipv4_version, p4_ipv4_ihl, p4_ipv4_dscp, p4_ipv4_ecn, p4_ipv4_totalLen, p4_ipv4_identification, p4_ipv4_flags, p4_ipv4_fragOffset, p4_ipv4_ttl, p4_ipv4_protocol, p4_ipv4_hdrChecksum, p4_ipv4_srcAddr, p4_ipv4_dstAddr}


-- protocol dissector function
function p4_original_ipv4.dissector(buffer,pinfo,tree)

    if buffer(1,1):bitfield(0,6) == 23 then

        pinfo.cols.protocol = 'P4_IPV4'
        local subtree = tree:add(p4_ipv4,buffer(),'P4_IPV4')
            subtree:add(p4_ipv4_version,tostring(buffer(0,1):bitfield(0,4)))
            subtree:add(p4_ipv4_ihl,tostring(buffer(0,1):bitfield(4,4)))
            subtree:add(p4_ipv4_dscp,tostring(buffer(1,1):bitfield(0,6)))
            subtree:add(p4_ipv4_ecn,tostring(buffer(1,1):bitfield(6,2)))
            subtree:add(p4_ipv4_totalLen,tostring(buffer(2,2):bitfield(0,16)))
            subtree:add(p4_ipv4_identification,tostring(buffer(4,2):bitfield(0,16)))
            subtree:add(p4_ipv4_flags,tostring(buffer(6,1):bitfield(0,3)))
            subtree:add(p4_ipv4_fragOffset,tostring(buffer(6,2):bitfield(3,13)))
            subtree:add(p4_ipv4_ttl,tostring(buffer(8,1):bitfield(0,8)))
            subtree:add(p4_ipv4_protocol,tostring(buffer(9,1):bitfield(0,8)))
            subtree:add(p4_ipv4_hdrChecksum,tostring(buffer(10,2):bitfield(0,16)))
            subtree:add(p4_ipv4_srcAddr,tostring(buffer(12,4):bitfield(0,32)))
            subtree:add(p4_ipv4_dstAddr,tostring(buffer(16,4):bitfield(0,32)))
        local mydissectortable = DissectorTable.get('p4_ipv4.protocol')
        mydissectortable:try(buffer(9,1):bitfield(0,8), buffer:range(20):tvb(),pinfo,tree)

    end

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4__original_ipv4.protocol','P4_ORIGINAL_IPV4.PROTOCOL',ftypes.STRING)

-- protocol registration
my_table = DissectorTable.get('p4_sink_metadata_stack')
my_table:add(0,p4_original_ipv4)
