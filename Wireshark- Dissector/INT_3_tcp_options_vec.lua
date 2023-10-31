-- protocol naming
p4_tcp_options_vec = Proto('p4_tcp_options_vec','P4_TCP_OPTIONS_VECProtocol')

-- protocol fields
local p4_tcp_options_vec_kind = ProtoField.uint8('p4_tcp_options_vec.kind','Kind',base.HEX)
local p4_tcp_options_vec_length = ProtoField.string('p4_tcp_options_vec.length','Length')
local p4_tcp_options_vec_path = ProtoField.string('p4_tcp_options_vec.path','Path')
local p4_tcp_options_vec_pathLatency = ProtoField.string('p4_tcp_options_vec.pathLatency','Total Path Latency')
local p4_tcp_options_vec_tagFrequency = ProtoField.string('p4_tcp_options_vec.tagFrequency','Tag Frequency')
local p4_tcp_options_vec_evaluated = ProtoField.string('p4_tcp_options_vec.evaluated','Evaluated')
p4_tcp_options_vec.fields = {p4_tcp_options_vec_kind, p4_tcp_options_vec_length, p4_tcp_options_vec_path, p4_tcp_options_vec_pathLatency,p4_tcp_options_vec_tagFrequency,p4_tcp_options_vec_evaluated}


-- protocol dissector function
function p4_tcp_options_vec.dissector(buffer,pinfo,tree)

    if buffer(0,1):bitfield(0,8) == 115 then
        pinfo.cols.protocol = p4_tcp_options_vec.name
        local subtree = tree:add(p4_tcp_options_vec,buffer(),'P4_INT_TCP_OPTION Protocol Data')
            subtree:add(p4_tcp_options_vec_kind,tostring(buffer(0,1):bitfield(0,8)))
            subtree:add(p4_tcp_options_vec_length,tostring(buffer(1,1):bitfield(0,8)))
            subtree:add(p4_tcp_options_vec_path,tostring(buffer(2,2):bitfield(0,16)))
            subtree:add(p4_tcp_options_vec_pathLatency,tostring(buffer(4,8):bitfield(0,64)))
            subtree:add("Other TCP options",tostring(buffer(12,6):bitfield(0,48)))
            subtree:add("Other TCP options",tostring(buffer(18,6):bitfield(0,48)))
        local mydissectortable = DissectorTable.get('p4_tcp_options_vec.kind')
        mydissectortable:try(buffer(0,1):bitfield(0,8),buffer:range(24):tvb(),pinfo,tree)
    end

end

print( (require 'debug').getinfo(1).source )

-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_tcp_options_vec.kind','P4_TCP_OPTIONS_VEC.KIND',ftypes.STRING)

-- protocol registration

my_table = DissectorTable.get('p4_tcp_dataOffset')
my_table:add(11,p4_tcp_options_vec)



-- protocol naming
p4_tcp_options_vec_response = Proto('p4_tcp_options_vec_response','P4_TCP_OPTIONS_VECProtocol_RESPONSE')

-- protocol fields
local p4_tcp_options_vec_kind_response = ProtoField.uint8('p4_tcp_options_vec.kind','Kind',base.HEX)
local p4_tcp_options_vec_length_response = ProtoField.string('p4_tcp_options_vec.length','Length')
local p4_tcp_options_vec_path_response= ProtoField.string('p4_tcp_options_vec.path','Path')
local p4_tcp_options_vec_pathLatency_response = ProtoField.string('p4_tcp_options_vec.pathLatency','Total Path Latency')
local p4_tcp_options_vec_tagFrequency_response = ProtoField.string('p4_tcp_options_vec.tagFrequency','Tag Frequency')
local p4_tcp_options_vec_evaluated_response = ProtoField.string('p4_tcp_options_vec.evaluated','Evaluated')
p4_tcp_options_vec_response.fields = {p4_tcp_options_vec_kind_response, p4_tcp_options_vec_length_response, p4_tcp_options_vec_path_response, p4_tcp_options_vec_pathLatency_response,p4_tcp_options_vec_tagFrequency_response,p4_tcp_options_vec_evaluated_response}


-- protocol dissector function
function p4_tcp_options_vec_response.dissector(buffer,pinfo,tree)

    if buffer(0,1):bitfield(0,8) == 115 then

            pinfo.cols.protocol = p4_tcp_options_vec_response.name
            local subtree = tree:add(p4_tcp_options_vec_response,buffer(),'P4_INT_TCP_OPTION Protocol Data')
            subtree:add(p4_tcp_options_vec_kind_response,tostring(buffer(0,1):bitfield(0,8)))
            subtree:add(p4_tcp_options_vec_length_response,tostring(buffer(1,1):bitfield(0,8)))
            subtree:add(p4_tcp_options_vec_path_response,tostring(buffer(2,2):bitfield(0,16)))
            subtree:add(p4_tcp_options_vec_pathLatency_response,tostring(buffer(4,8):bitfield(0,64)))

    end
end 

print( (require 'debug').getinfo(1).source )

-- protocol registration

my_table = DissectorTable.get('p4_tcp_dataOffset')
my_table:add(8,p4_tcp_options_vec_response)
