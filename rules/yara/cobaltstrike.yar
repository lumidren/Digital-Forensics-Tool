/*
  Veritas curated rules: Cobalt Strike beacon markers.
  Original rules written for Veritas DFIR (Apache-2.0). Intended for files and process memory.
  The beacon configuration block is a TLV list whose first entries (setting 1 BeaconType,
  setting 2 Port, both of type "short") are XOR-encoded with one byte: 0x69 in 3.x builds and
  0x2e in 4.x builds. The encoded patterns are 00 01 00 01 00 02 | 00 02 00 01 00 02 XOR key.
*/

rule CobaltStrike_Beacon_Config_Block
{
    meta:
        author = "Veritas DFIR"
        description = "Cobalt Strike beacon configuration header, XOR-encoded (key 0x69 or 0x2e) or plaintext"
        severity = "high"
        attack = "T1071.001"
    strings:
        $k69 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B }
        $k2e = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C }
        $plain = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
    condition:
        any of them
}

rule CobaltStrike_Beacon_Strings
{
    meta:
        author = "Veritas DFIR"
        description = "Strings characteristic of the Cobalt Strike beacon DLL and its default named pipes"
        severity = "high"
        attack = "T1055"
    strings:
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "beacon.x64.dll" ascii
        $s4 = "ReflectiveLoader" ascii
        $c1 = "could not spawn %s: %d" ascii
        $c2 = "Could not connect to pipe (%s): %d" ascii
        $p1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $p2 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii
        $p3 = "\\\\.\\pipe\\msagent_" ascii wide
        $p4 = "\\\\.\\pipe\\postex_" ascii wide
    condition:
        2 of ($s*, $c*) or any of ($p*)
}

rule CobaltStrike_Stager_Shellcode
{
    meta:
        author = "Veritas DFIR"
        description = "Reverse-HTTP stager prologue shared by Cobalt Strike and Metasploit stagers"
        severity = "medium"
        attack = "T1105"
    strings:
        // cld; call +0x89; pushad; mov ebp,esp; xor edx,edx; mov edx,fs:[edx+0x30]
        $x86 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        // cld; and rsp,-16; call +0xc8; push r9; push r8; push rdx; push rcx
        $x64 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 }
        // push <ror13 hash of wininet.dll!InternetOpenA>
        $h1 = { 68 3A 56 79 A7 }
    condition:
        (($x86 or $x64) and $h1) or (($x86 or $x64) and filesize < 4KB)
}
