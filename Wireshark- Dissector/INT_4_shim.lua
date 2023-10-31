-- protocol naming
p4_shim = Proto('p4_shim','P4_SHIMProtocol')

-- protocol fields
local p4_shim_type = ProtoField.string('p4_shim.type','Type')
local p4_shim_npt = ProtoField.string('p4_shim.npt','Npt')
local p4_shim_reserved1 = ProtoField.string('p4_shim.reserved1','Reserved1')
local p4_shim_reserved2 = ProtoField.string('p4_shim.reserved2','Reserved2')
local p4_shim_len = ProtoField.string('p4_shim.len','Len')
local p4_shim_dscp = ProtoField.string('p4_shim.dscp','Dscp')
local p4_shim_reserved3 = ProtoField.string('p4_shim.reserved3','Reserved3')
p4_shim.fields = {p4_shim_type, p4_shim_npt, p4_shim_reserved1, p4_shim_reserved2, p4_shim_len, p4_shim_dscp, p4_shim_reserved3}


-- protocol dissector function
function p4_shim.dissector(buffer,pinfo,tree)

    if buffer(0,1):bitfield(0,4) == 1 then

        pinfo.cols.protocol = 'P4_SHIM'
        local subtree = tree:add(p4_shim,buffer(),'P4_SHIM')
            subtree:add(p4_shim_type,tostring(buffer(0,1):bitfield(0,4)))
            subtree:add(p4_shim_npt,tostring(buffer(0,1):bitfield(4,2)))
            subtree:add(p4_shim_reserved1,tostring(buffer(0,1):bitfield(6,1)))
            subtree:add(p4_shim_reserved2,tostring(buffer(0,1):bitfield(7,1)))
            subtree:add(p4_shim_len,tostring(buffer(1,1):bitfield(0,8)))
            subtree:add(p4_shim_dscp,tostring(buffer(2,1):bitfield(0,6)))
            subtree:add(p4_shim_reserved3,tostring(buffer(2,2):bitfield(6,10)))
        local mydissectortable = DissectorTable.get('p4_shim.type')
        mydissectortable:try(buffer(0,1):bitfield(0,4), buffer:range(4):tvb(),pinfo,tree)

    print( (require 'debug').getinfo(1).source )
        

    
    end
end

-- protocol registration
my_table = DissectorTable.get('p4_tcp_options_vec.kind')
my_table:add(0x73,p4_shim)


-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_shim.type','P4_SHIMProtocol',ftypes.STRING)
        

