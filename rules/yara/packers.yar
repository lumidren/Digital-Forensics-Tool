/*
  Veritas curated rules: executable packers and protectors.
  Original rules written for Veritas DFIR (Apache-2.0). Informational: packing is common in
  legitimate software, so these are low/medium severity context for other findings.
*/
import "pe"
import "math"

rule Packer_UPX
{
    meta:
        author = "Veritas DFIR"
        description = "UPX packed PE (UPX0/UPX1 sections or UPX! stub marker)"
        severity = "low"
        attack = "T1027.002"
    strings:
        $magic = "UPX!" ascii
    condition:
        pe.is_pe and (
            (for any s in pe.sections : (s.name == "UPX0" or s.name == "UPX1" or s.name == "UPX2")) or
            $magic in (0..4096)
        )
}

rule Packer_Known_Section_Names
{
    meta:
        author = "Veritas DFIR"
        description = "Section names left by common packers/protectors (MPRESS, ASPack, PECompact, Themida, VMProtect, Enigma, Petite, nsPack)"
        severity = "low"
        attack = "T1027.002"
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.name == ".MPRESS1" or s.name == ".MPRESS2" or s.name == ".aspack" or s.name == ".adata" or
            s.name == "PEC2" or s.name == "PEC2TO" or s.name == ".themida" or s.name == ".vmp0" or
            s.name == ".vmp1" or s.name == ".enigma1" or s.name == ".petite" or s.name == ".nsp0" or s.name == ".nsp1"
        )
}

rule Packer_High_Entropy_Executable_Section
{
    meta:
        author = "Veritas DFIR"
        description = "Executable section whose entropy exceeds 7.2 bits/byte (compressed or encrypted code)"
        severity = "medium"
        attack = "T1027.002"
    condition:
        pe.is_pe and for any s in pe.sections : (
            (s.characteristics & pe.SECTION_MEM_EXECUTE) != 0 and s.raw_data_size > 1024 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.2
        )
}

rule PE_Writable_Executable_Section
{
    meta:
        author = "Veritas DFIR"
        description = "Section that is both writable and executable (self-modifying code, unpacking stubs)"
        severity = "low"
        attack = "T1027"
    condition:
        pe.is_pe and for any s in pe.sections : (
            (s.characteristics & pe.SECTION_MEM_EXECUTE) != 0 and (s.characteristics & pe.SECTION_MEM_WRITE) != 0
        )
}
