/**
 * Static MITRE ATT&CK (Enterprise) reference for the techniques Veritas rules emit: technique
 * names, the tactics each belongs to, and helpers that build the tactic heatmap shown on the case
 * dashboard. Sub-techniques inherit the tactics of their parent technique.
 */
import type { Finding, Severity } from "./types";
import { SEVERITIES } from "./types";

export interface Tactic {
  id: string;
  key: string;
  name: string;
  short: string;
}

/** Enterprise tactics in kill-chain order. */
export const TACTICS: Tactic[] = [
  { id: "TA0043", key: "reconnaissance", name: "Reconnaissance", short: "Recon" },
  { id: "TA0042", key: "resource-development", name: "Resource Development", short: "Resource dev" },
  { id: "TA0001", key: "initial-access", name: "Initial Access", short: "Initial access" },
  { id: "TA0002", key: "execution", name: "Execution", short: "Execution" },
  { id: "TA0003", key: "persistence", name: "Persistence", short: "Persistence" },
  { id: "TA0004", key: "privilege-escalation", name: "Privilege Escalation", short: "Priv. esc." },
  { id: "TA0005", key: "defense-evasion", name: "Defense Evasion", short: "Def. evasion" },
  { id: "TA0006", key: "credential-access", name: "Credential Access", short: "Cred. access" },
  { id: "TA0007", key: "discovery", name: "Discovery", short: "Discovery" },
  { id: "TA0008", key: "lateral-movement", name: "Lateral Movement", short: "Lateral mvmt" },
  { id: "TA0009", key: "collection", name: "Collection", short: "Collection" },
  { id: "TA0011", key: "command-and-control", name: "Command and Control", short: "C2" },
  { id: "TA0010", key: "exfiltration", name: "Exfiltration", short: "Exfiltration" },
  { id: "TA0040", key: "impact", name: "Impact", short: "Impact" },
];

type TacticKey =
  | "reconnaissance"
  | "resource-development"
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "collection"
  | "command-and-control"
  | "exfiltration"
  | "impact";

/** Parent techniques: name and tactics. */
const TECHNIQUES: Record<string, { name: string; tactics: TacticKey[] }> = {
  T1003: { name: "OS Credential Dumping", tactics: ["credential-access"] },
  T1014: { name: "Rootkit", tactics: ["defense-evasion"] },
  T1018: { name: "Remote System Discovery", tactics: ["discovery"] },
  T1021: { name: "Remote Services", tactics: ["lateral-movement"] },
  T1036: { name: "Masquerading", tactics: ["defense-evasion"] },
  T1040: { name: "Network Sniffing", tactics: ["credential-access", "discovery"] },
  T1046: { name: "Network Service Discovery", tactics: ["discovery"] },
  T1047: { name: "Windows Management Instrumentation", tactics: ["execution"] },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactics: ["exfiltration"] },
  T1053: {
    name: "Scheduled Task/Job",
    tactics: ["execution", "persistence", "privilege-escalation"],
  },
  T1055: { name: "Process Injection", tactics: ["defense-evasion", "privilege-escalation"] },
  T1059: { name: "Command and Scripting Interpreter", tactics: ["execution"] },
  T1070: { name: "Indicator Removal", tactics: ["defense-evasion"] },
  T1071: { name: "Application Layer Protocol", tactics: ["command-and-control"] },
  T1078: {
    name: "Valid Accounts",
    tactics: ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
  },
  T1087: { name: "Account Discovery", tactics: ["discovery"] },
  T1090: { name: "Proxy", tactics: ["command-and-control"] },
  T1095: { name: "Non-Application Layer Protocol", tactics: ["command-and-control"] },
  T1098: { name: "Account Manipulation", tactics: ["persistence", "privilege-escalation"] },
  T1105: { name: "Ingress Tool Transfer", tactics: ["command-and-control"] },
  T1110: { name: "Brute Force", tactics: ["credential-access"] },
  T1136: { name: "Create Account", tactics: ["persistence"] },
  T1204: { name: "User Execution", tactics: ["execution"] },
  T1218: { name: "System Binary Proxy Execution", tactics: ["defense-evasion"] },
  T1219: { name: "Remote Access Software", tactics: ["command-and-control"] },
  T1482: { name: "Domain Trust Discovery", tactics: ["discovery"] },
  T1484: {
    name: "Domain or Tenant Policy Modification",
    tactics: ["defense-evasion", "privilege-escalation"],
  },
  T1485: { name: "Data Destruction", tactics: ["impact"] },
  T1486: { name: "Data Encrypted for Impact", tactics: ["impact"] },
  T1490: { name: "Inhibit System Recovery", tactics: ["impact"] },
  T1543: { name: "Create or Modify System Process", tactics: ["persistence", "privilege-escalation"] },
  T1546: { name: "Event Triggered Execution", tactics: ["persistence", "privilege-escalation"] },
  T1547: {
    name: "Boot or Logon Autostart Execution",
    tactics: ["persistence", "privilege-escalation"],
  },
  T1550: { name: "Use Alternate Authentication Material", tactics: ["defense-evasion", "lateral-movement"] },
  T1555: { name: "Credentials from Password Stores", tactics: ["credential-access"] },
  T1558: { name: "Steal or Forge Kerberos Tickets", tactics: ["credential-access"] },
  T1560: { name: "Archive Collected Data", tactics: ["collection"] },
  T1562: { name: "Impair Defenses", tactics: ["defense-evasion"] },
  T1566: { name: "Phishing", tactics: ["initial-access"] },
  T1569: { name: "System Services", tactics: ["execution"] },
  T1570: { name: "Lateral Tool Transfer", tactics: ["lateral-movement"] },
  T1572: { name: "Protocol Tunneling", tactics: ["command-and-control"] },
};

/** Sub-technique names (the parent supplies the tactics). */
const SUB_TECHNIQUES: Record<string, string> = {
  "T1003.001": "LSASS Memory",
  "T1021.001": "Remote Desktop Protocol",
  "T1021.002": "SMB/Windows Admin Shares",
  "T1021.006": "Windows Remote Management",
  "T1036.005": "Match Legitimate Name or Location",
  "T1053.003": "Cron",
  "T1053.005": "Scheduled Task",
  "T1055.012": "Process Hollowing",
  "T1059.001": "PowerShell",
  "T1059.003": "Windows Command Shell",
  "T1070.001": "Clear Windows Event Logs",
  "T1070.003": "Clear Command History",
  "T1070.004": "File Deletion",
  "T1070.006": "Timestomp",
  "T1090.003": "Multi-hop Proxy",
  "T1098.004": "SSH Authorized Keys",
  "T1136.001": "Local Account",
  "T1204.002": "Malicious File",
  "T1218.005": "Mshta",
  "T1218.010": "Regsvr32",
  "T1218.011": "Rundll32",
  "T1484.001": "Group Policy Modification",
  "T1543.001": "Launch Agent",
  "T1543.002": "Systemd Service",
  "T1543.003": "Windows Service",
  "T1543.004": "Launch Daemon",
  "T1546.003": "WMI Event Subscription",
  "T1546.012": "Image File Execution Options Injection",
  "T1547.001": "Registry Run Keys / Startup Folder",
  "T1547.015": "Login Items",
  "T1550.002": "Pass the Hash",
  "T1558.003": "Kerberoasting",
  "T1560.001": "Archive via Utility",
  "T1562.001": "Disable or Modify Tools",
  "T1562.002": "Disable Windows Event Logging",
  "T1566.001": "Spearphishing Attachment",
  "T1569.002": "Service Execution",
};

export interface TechniqueInfo {
  id: string;
  /** Full display name, "Parent: Sub-technique" for sub-techniques. */
  name: string;
  /** Short name: the sub-technique name, or the technique name. */
  short: string;
  tactics: string[];
  known: boolean;
}

export function normalizeTechnique(id: string): string {
  return id.trim().toUpperCase();
}

export function techniqueInfo(rawId: string): TechniqueInfo {
  const id = normalizeTechnique(rawId);
  const parentId = id.split(".")[0] ?? id;
  const parent = TECHNIQUES[parentId];
  const sub = id.includes(".") ? SUB_TECHNIQUES[id] : undefined;
  if (!parent) return { id, name: id, short: id, tactics: [], known: false };
  return {
    id,
    name: sub ? `${parent.name}: ${sub}` : parent.name,
    short: sub ?? parent.name,
    tactics: [...parent.tactics],
    known: true,
  };
}

/** The tactic a technique is drawn under when one colour/family is needed (first listed). */
export function primaryTactic(id: string): Tactic | null {
  const key = techniqueInfo(id).tactics[0];
  return TACTICS.find((t) => t.key === key) ?? null;
}

export function attackUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${normalizeTechnique(id).replace(".", "/")}/`;
}

export interface MatrixTechnique {
  id: string;
  name: string;
  findings: number;
  severity: Severity;
}

export interface MatrixColumn {
  tactic: Tactic;
  techniques: MatrixTechnique[];
  /** Total findings touching this tactic. */
  findings: number;
}

const SEV_RANK = new Map<Severity, number>(SEVERITIES.map((s, i) => [s, i]));

/** Severity with the lower index in SEVERITIES (critical first) wins. */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return (SEV_RANK.get(a) ?? 99) <= (SEV_RANK.get(b) ?? 99) ? a : b;
}

/**
 * Tactic columns for the dashboard heatmap from live findings (rejected findings are excluded).
 * Each technique is counted once per finding, under every tactic it belongs to. Unknown
 * technique ids are returned separately so they are never silently dropped.
 */
export function tacticMatrix(findings: Finding[]): { columns: MatrixColumn[]; unmapped: MatrixTechnique[] } {
  const byTactic = new Map<string, Map<string, MatrixTechnique>>();
  const tacticFindings = new Map<string, Set<string>>();
  const unmapped = new Map<string, MatrixTechnique>();
  const bump = (bucket: Map<string, MatrixTechnique>, info: TechniqueInfo, sev: Severity) => {
    const cur = bucket.get(info.id);
    if (cur) {
      cur.findings += 1;
      cur.severity = maxSeverity(cur.severity, sev);
    } else bucket.set(info.id, { id: info.id, name: info.short, findings: 1, severity: sev });
  };
  for (const f of findings) {
    if (f.state === "rejected") continue;
    for (const t of new Set(f.attack_techniques.map(normalizeTechnique))) {
      const info = techniqueInfo(t);
      if (!info.known) {
        bump(unmapped, info, f.severity);
        continue;
      }
      for (const tac of info.tactics) {
        const bucket = byTactic.get(tac) ?? new Map<string, MatrixTechnique>();
        byTactic.set(tac, bucket);
        bump(bucket, info, f.severity);
        const fs = tacticFindings.get(tac) ?? new Set<string>();
        fs.add(f.id);
        tacticFindings.set(tac, fs);
      }
    }
  }
  const columns = TACTICS.map((tactic) => ({
    tactic,
    techniques: [...(byTactic.get(tactic.key)?.values() ?? [])].sort(
      (a, b) => b.findings - a.findings || a.id.localeCompare(b.id),
    ),
    findings: tacticFindings.get(tactic.key)?.size ?? 0,
  }));
  return { columns, unmapped: [...unmapped.values()].sort((a, b) => a.id.localeCompare(b.id)) };
}

/** Colour family per tactic (categorical slots; unlisted tactics share the neutral colour). */
const TACTIC_COLORS: Record<string, string> = {
  "lateral-movement": "var(--cat-1)",
  persistence: "var(--cat-2)",
  execution: "var(--cat-3)",
  "initial-access": "var(--cat-4)",
  "privilege-escalation": "var(--cat-5)",
  "command-and-control": "var(--cat-6)",
  "defense-evasion": "var(--cat-7)",
  "credential-access": "var(--cat-8)",
};

export function tacticColor(key: string): string {
  return TACTIC_COLORS[key] ?? "var(--cat-other)";
}

export function tacticName(key: string): string {
  return TACTICS.find((t) => t.key === key)?.name ?? "Other";
}
