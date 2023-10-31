-- protocol naming
p4_int_md_metadata = Proto('p4_int_md_metadata','P4_INT_MD_METADATAProtocol')

-- protocol fields
local p4_int_md_metadata_ver = ProtoField.string('p4_int_md_metadata.ver','Version')
local p4_int_md_metadata_d = ProtoField.string('p4_int_md_metadata.d','D')
local p4_int_md_metadata_e = ProtoField.string('p4_int_md_metadata.e','E')
local p4_int_md_metadata_m = ProtoField.string('p4_int_md_metadata.m','M')
local p4_int_md_metadata_rsvd = ProtoField.string('p4_int_md_metadata.rsvd','Reserved')
local p4_int_md_metadata_hop_metadata_len = ProtoField.string('p4_int_md_metadata.hop_metadata_len','Hop Metadata Len')
local p4_int_md_metadata_remaining_hop_cnt = ProtoField.string('p4_int_md_metadata.remaining_hop_cnt','Remaining Hop Count')
local p4_int_md_metadata_instruction_mask = ProtoField.string('p4_int_md_metadata.instruction_mask','Instruction Mask')
local p4_int_md_metadata_domain_specific_id = ProtoField.string('p4_int_md_metadata.domain_specific_id','Domain Specific Id')
local p4_int_md_metadata_ds_instruction = ProtoField.string('p4_int_md_metadata.ds_instruction','Ds Instruction')
local p4_int_md_metadata_ds_flags = ProtoField.string('p4_int_md_metadata.ds_flags','ds_flags')

p4_int_md_metadata.fields = {p4_int_md_metadata_ver, p4_int_md_metadata_d, p4_int_md_metadata_e, p4_int_md_metadata_m, p4_int_md_metadata_rsvd, p4_int_md_metadata_hop_metadata_len, p4_int_md_metadata_remaining_hop_cnt, p4_int_md_metadata_instruction_mask, p4_int_md_metadata_domain_specific_id, p4_int_md_metadata_ds_instruction, p4_int_md_metadata_ds_flags}

-- protocol dissector function
function p4_int_md_metadata.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = 'P4_INT_MD_METADATA'
    local subtree = tree:add(p4_int_md_metadata,buffer(),'P4_INT_MD_METADATA')
        subtree:add(p4_int_md_metadata_ver,tostring(buffer(0,1):bitfield(0,4)))
        subtree:add(p4_int_md_metadata_d,tostring(buffer(0,1):bitfield(4,1)))
        subtree:add(p4_int_md_metadata_e,tostring(buffer(0,1):bitfield(5,1)))
        subtree:add(p4_int_md_metadata_m,tostring(buffer(0,1):bitfield(6,1)))
        subtree:add(p4_int_md_metadata_rsvd,tostring(buffer(0,3):bitfield(7,12)))
        subtree:add(p4_int_md_metadata_hop_metadata_len,tostring(buffer(2,1):bitfield(3,5)))
        subtree:add(p4_int_md_metadata_remaining_hop_cnt,tostring(buffer(3,1):bitfield(0,8)))
        subtree:add(p4_int_md_metadata_instruction_mask,string.format("%x",(buffer(4,2):bitfield(0,16))))
        subtree:add(p4_int_md_metadata_domain_specific_id,tostring(buffer(6,2):bitfield(0,16)))
        subtree:add(p4_int_md_metadata_ds_instruction,tostring(buffer(8,2):bitfield(0,16)))
        subtree:add(p4_int_md_metadata_ds_flags,tostring(buffer(10,2):bitfield(0,16)))
    local mydissectortable = DissectorTable.get('p4_int_md_metadata.ver')
    mydissectortable:try(0x10, buffer:range(12):tvb(),pinfo,tree)

end


print( (require 'debug').getinfo(1).source )



-- creation of table for next layer(if required)
local newdissectortable = DissectorTable.new('p4_int_md_metadata.ver','P4_INT_MD_METADATA.VER',ftypes.STRING)



-- protocol registration
my_table = DissectorTable.get('p4_shim.type')
my_table:add(0x01,p4_int_md_metadata)






