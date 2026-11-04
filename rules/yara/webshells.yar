/*
  Veritas curated rules: web shells.
  Original rules written for Veritas DFIR (Apache-2.0). Tuned for triage of web roots:
  they look for request parameters flowing straight into code-evaluation or command sinks.
*/

rule Webshell_PHP_Eval_Request
{
    meta:
        author = "Veritas DFIR"
        description = "PHP passes HTTP request input into eval/assert/create_function, optionally via a decoder"
        severity = "high"
        attack = "T1505.003"
    strings:
        $php = "<?php" nocase
        $php_short = "<?="
        $sink1 = /(eval|assert|create_function)\s*\(\s*(@?\s*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes|urldecode)\s*\(\s*){0,4}@?\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $sink2 = /preg_replace\s*\(\s*["'][^"']{1,40}\/e["']\s*,\s*@?\s*\$_(POST|GET|REQUEST)/ nocase
    condition:
        filesize < 2MB and ($php or $php_short) and any of ($sink*)
}

rule Webshell_PHP_Command_Exec_Request
{
    meta:
        author = "Veritas DFIR"
        description = "PHP runs an OS command taken from HTTP request input"
        severity = "high"
        attack = "T1505.003"
    strings:
        $php = "<?php" nocase
        $exec = /(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $bt = /`\s*\$_(GET|POST|REQUEST)\s*\[/ nocase
    condition:
        filesize < 2MB and $php and ($exec or $bt)
}

rule Webshell_ASPX_Eval_Request
{
    meta:
        author = "Veritas DFIR"
        description = "ASP/ASPX page evaluates request input (China Chopper style one-liners and variants)"
        severity = "high"
        attack = "T1505.003"
    strings:
        $asp = "<%"
        $e1 = /eval\s*\(\s*Request(\.Item)?\s*[\[\(]/ nocase
        $e2 = /Execute\s*\(?\s*Request(\.Item|\.Form|\.QueryString)?\s*\(/ nocase
        $e3 = "System.Reflection.Assembly.Load(Convert.FromBase64String(Request" nocase
        $e4 = /ProcessStartInfo\s*\(\s*"cmd(\.exe)?"/ nocase
        $req = "Request" nocase
    condition:
        filesize < 2MB and $asp and (any of ($e1, $e2, $e3) or ($e4 and $req))
}

rule Webshell_JSP_Runtime_Exec_Request
{
    meta:
        author = "Veritas DFIR"
        description = "JSP passes a request parameter to Runtime.exec, ProcessBuilder or a class loader"
        severity = "high"
        attack = "T1505.003"
    strings:
        $jsp = "<%"
        $x1 = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter\s*\(/ nocase
        $x2 = /new\s+ProcessBuilder\s*\([^)]{0,80}request\.getParameter/ nocase
        $x3 = /defineClass\s*\([^;]{0,160}(decodeBuffer|getDecoder\(\)\.decode)\s*\(\s*request/ nocase
    condition:
        filesize < 2MB and $jsp and any of ($x*)
}
