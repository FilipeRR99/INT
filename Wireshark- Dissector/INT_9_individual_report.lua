-- protocol naming
p4_individual_report = Proto('p4_individual_report','P4_INDIVIDUAL_REPORT')

-- protocol fields
local p4_rep_type = ProtoField.string('p4_individual_report.rep_type','Report Type')
local p4_inner_type= ProtoField.string('p4_individual_report.inner_type','Inner Type')
local p4_report_length = ProtoField.string('p4_individual_report.report_length','Report Length')
local p4_metadata_length = ProtoField.string('p4_individual_report.metadata_length','Metadata Length')
local p4_d = ProtoField.string('p4_individual_report.d','D')
local p4_q = ProtoField.string('p4_individual_report.q','Q')
local p4_f = ProtoField.string('p4_individual_report.f','F')
local p4_i = ProtoField.string('p4_individual_report.i','I')
local p4_rsvd = ProtoField.string('p4_individual_report.rsvd','Node ID')
local p4_repMdBits = ProtoField.string('p4_individual_report.repMdBits','RepMdBits')
local p4_domainSpecificID = ProtoField.string('p4_individual_report.domainSpecificID','Domain Specific ID')
local p4_dSMDBits = ProtoField.string('p4_individual_report.dSMDBits','dSMDBits')
local p4_dSMDStatus = ProtoField.string('p4_individual_report.dSMDStatus','dSMDStatus')
local p4_sink_hop_latency = ProtoField.string('p4_individual_report.sink_hop_latency','Sink Hop Latency')

p4_individual_report.fields = {p4_rep_type , p4_inner_type,  p4_report_length,p4_metadata_length,p4_d,p4_q,p4_f,p4_i,p4_rsvd,p4_repMdBits,p4_domainSpecificID,p4_dSMDBits,p4_dSMDStatus,p4_sink_hop_latency}


-- protocol dissector function
function p4_individual_report.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_INDIVIDUAL_REPORT'
    local subtree = tree:add(p4_report_udp,buffer(),'P4_INDIVIDUAL_REPORT Protocol Data')
        subtree:add(p4_rep_type,tostring(buffer(0,1):bitfield(0,4)))
        subtree:add(p4_inner_type,tostring(buffer(0,1):bitfield(4,4)))
        subtree:add(p4_report_length,tostring(buffer(1,1):bitfield(0,8)))
        subtree:add(p4_metadata_length,tostring(buffer(2,1):bitfield(0,8)))
        subtree:add(p4_d,tostring(buffer(3,1):bitfield(0,1)))
        subtree:add(p4_q,tostring(buffer(3,1):bitfield(1,1)))
        subtree:add(p4_f,tostring(buffer(3,1):bitfield(2,1)))
        subtree:add(p4_i,tostring(buffer(3,1):bitfield(3,1)))
        subtree:add(p4_rsvd,tostring(buffer(3,1):bitfield(4,4)))
        subtree:add(p4_repMdBits,string.format("%x",(buffer(4,2):bitfield(0,16))))
        subtree:add(p4_domainSpecificID,tostring(buffer(6,2):bitfield(0,16)))
        subtree:add(p4_dSMDBits,tostring(buffer(8,2):bitfield(0,16)))
        subtree:add(p4_dSMDStatus,tostring(buffer(10,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_individual_report')
    mydissectortable:try(buffer(0,1):bitfield(0,4), buffer:range(12):tvb(),pinfo,tree)

end



print( (require 'debug').getinfo(1).source )

local newdissectortable = DissectorTable.new('p4_individual_report','P4_INDIVIDUAL_REPORT',ftypes.STRING)


-- protocol registration
my_table = DissectorTable.get('p4_telemetry_report_group_ver')
my_table:add(0x02,p4_individual_report)


