-- protocol naming
p4_telemetry_report_group = Proto('p4_telemetry_report_group','P4_TELEMETRY_REPORT_GROUP')

-- protocol fields
local p4_ver = ProtoField.string('p4_telemetry_report_group.ver','Ver')
local p4_hw_id = ProtoField.string('p4_telemetry_report_group.hw_id','HW ID')
local p4_seq_num = ProtoField.string('p4_telemetry_report_group.seq_num','Sequence Number')
local p4_node_id = ProtoField.string('p4_telemetry_report_group.node_id','Node ID')
p4_telemetry_report_group.fields = {p4_ver, p4_hw_id, p4_seq_num, p4_node_id}


-- protocol dissector function
function p4_telemetry_report_group.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_TELEMETRY_REPORT_GROUP'
    local subtree = tree:add(p4_report_udp,buffer(),'P4_TELEMETRY_REPORT_GROUP Protocol Data')
        subtree:add(p4_ver,tostring(buffer(0,1):bitfield(0,4)))
        subtree:add(p4_hw_id,tostring(buffer(0,2):bitfield(4,6)))
        subtree:add(p4_seq_num,tostring(buffer(1,4):bitfield(10,22)))
        subtree:add(p4_node_id,tostring(buffer(4,4):bitfield(0,32)))
    local mydissectortable = DissectorTable.get('p4_telemetry_report_group_ver')
    mydissectortable:try(buffer(0,1):bitfield(0,4), buffer:range(8):tvb(),pinfo,tree)

end

print( (require 'debug').getinfo(1).source )

local newdissectortable = DissectorTable.new('p4_telemetry_report_group_ver','P4_TELEMETRY_REPORT_GROUP',ftypes.STRING)



-- protocol registration
my_table = DissectorTable.get('p4_report_udp_dstPort')
my_table:add(1024,p4_telemetry_report_group)

