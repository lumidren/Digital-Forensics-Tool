/*
  Veritas curated rules: process injection tooling.
  Original rules written for Veritas DFIR (Apache-2.0).
*/
import "pe"

rule Injection_Classic_Remote_Thread_Imports
{
    meta:
        author = "Veritas DFIR"
        description = "PE imports the full open/allocate/write/remote-thread injection chain"
        severity = "medium"
        attack = "T1055.001"
    condition:
        pe.is_pe and
        pe.imports(/kernel32\.dll/i, /^OpenProcess$/) and
        pe.imports(/kernel32\.dll/i, /^VirtualAllocEx$/) and
        pe.imports(/kernel32\.dll/i, /^WriteProcessMemory$/) and
        (pe.imports(/kernel32\.dll/i, /^CreateRemoteThread(Ex)?$/) or pe.imports(/ntdll\.dll/i, /^(Nt|Rtl)CreateUserThread$/) or
         pe.imports(/ntdll\.dll/i, /^NtCreateThreadEx$/) or pe.imports(/kernel32\.dll/i, /^QueueUserAPC$/))
}

rule Injection_Hollowing_Imports
{
    meta:
        author = "Veritas DFIR"
        description = "PE imports the create-suspended / unmap / set-context sequence used for process hollowing"
        severity = "medium"
        attack = "T1055.012"
    condition:
        pe.is_pe and
        pe.imports(/ntdll\.dll/i, /^(Nt|Zw)UnmapViewOfSection$/) and
        (pe.imports(/kernel32\.dll/i, /^SetThreadContext$/) or pe.imports(/kernel32\.dll/i, /^Wow64SetThreadContext$/)) and
        pe.imports(/kernel32\.dll/i, /^ResumeThread$/)
}

rule Meterpreter_Reflective_Payload
{
    meta:
        author = "Veritas DFIR"
        description = "Strings of the Metasploit meterpreter server DLL (metsrv) in a file or memory region"
        severity = "high"
        attack = "T1055.001"
    strings:
        $m1 = "metsrv.dll" ascii wide nocase
        $m2 = "metsrv.x64.dll" ascii wide nocase
        $m3 = "ext_server_stdapi" ascii wide nocase
        $m4 = "core_channel_open" ascii
        $m5 = "core_loadlib" ascii
        $r = "ReflectiveLoader" ascii
    condition:
        2 of ($m*) or ($r and any of ($m*))
}
