MAX_SWITCH_ID=4
MIN_SWITCH_ID=1


-- protocol naming
p4_metadata_stack = Proto('p4_metadata_stack','P4_METADATA_STACK_Protocol')

-- protocol fields
local p4_metadata_stack_switch_id = ProtoField.string('p4_metadata_stack_switch_id','Switch ID')
local p4_metadata_stack_hop_latency = ProtoField.string('p4_metadata_stack_hop_latency','Hop Latency (microseconds)')
local p4_metadata_stack_ingress_timestamp = ProtoField.string('p4_metadata_stack_ingress_timestamp','Ingress Timestamp (microseconds)')
local p4_metadata_stack_egress_timestamp = ProtoField.string('p4_metadata_stack_egress_timestamp','Egress Timestamp (microseconds)')
local p4_metadata_stack_queue_delay = ProtoField.string('p4_metadata_stack_queue_delay','Queue Delay (microseconds)')
local p4_metadata_stack_queue_depth = ProtoField.string('p4_metadata_stack_queue_depth','Queue Depth')
p4_metadata_stack.fields = {p4_metadata_stack_switch_id,p4_metadata_stack_hop_latency,p4_metadata_stack_ingress_timestamp,p4_metadata_stack_egress_timestamp, p4_metadata_stack_queue_delay, p4_metadata_stack_queue_depth}


-- protocol dissector function
function p4_metadata_stack.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_METADATA_STACK'
    local subtree = tree:add(p4_int_md_metadata,buffer(),'P4_METADATA_STACK')
        subtree:add(p4_metadata_stack_switch_id,tostring(buffer(0,2):bitfield(0,16)))
        subtree:add(p4_metadata_stack_hop_latency ,tostring(buffer(2,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_ingress_timestamp,tostring(buffer(10,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_egress_timestamp,tostring(buffer(18,8):bitfield(0,64)))
        subtree:add(p4_metadata_stack_queue_delay,tostring(buffer(26,4):bitfield(0,32)))
        subtree:add(p4_metadata_stack_queue_depth,tostring(buffer(30,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_metadata_stack'..MAX_SWITCH_ID)
    mydissectortable:try(buffer(0,2):bitfield(0,16), buffer:range(32):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_metadata_stack'..MAX_SWITCH_ID,'P4_INT_METADATA_STACK'..MAX_SWITCH_ID,ftypes.STRING)

-- protocol registration
my_table = DissectorTable.get('p4_int_md_metadata.ver')
my_table:add(0x10,p4_metadata_stack)

for i=MAX_SWITCH_ID-1,MIN_SWITCH_ID,-1
do


-- protocol naming
p4_metadata_stack = Proto('p4_metadata_stack'..i,'P4_METADATA_STACK_Protocol'..i)


-- protocol dissector function
function p4_metadata_stack.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = 'P4_METADATA_STACK'
    local subtree = tree:add(p4_int_md_metadata,buffer(),'P4_METADATA_STACK')
    subtree:add(p4_metadata_stack_switch_id,tostring(buffer(0,2):bitfield(0,16)))
    subtree:add(p4_metadata_stack_hop_latency ,tostring(buffer(2,8):bitfield(0,64)))
    subtree:add(p4_metadata_stack_ingress_timestamp,tostring(buffer(10,8):bitfield(0,64)))
    subtree:add(p4_metadata_stack_egress_timestamp,tostring(buffer(18,8):bitfield(0,64)))
    subtree:add(p4_metadata_stack_queue_delay,tostring(buffer(26,4):bitfield(0,32)))
    subtree:add(p4_metadata_stack_queue_depth,tostring(buffer(30,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_metadata_stack'..i)
    mydissectortable:try(buffer(0,2):bitfield(0,16), buffer:range(32):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_metadata_stack'..i,'P4_INT_METADATA_STACK'..i,ftypes.STRING)

for n=MAX_SWITCH_ID-2,MIN_SWITCH_ID+1,-1
do
my_table = DissectorTable.get('p4_metadata_stack'..i+1)
my_table:add((n),p4_metadata_stack)
end

for y=MAX_SWITCH_ID-1,MIN_SWITCH_ID+1,-1
do
my_table = DissectorTable.get('p4_metadata_stack'..i+1)
my_table:add((y+1),p4_metadata_stack)
end 

end
