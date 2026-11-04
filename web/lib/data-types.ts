/**
 * Data-type categories: every timeline `data_type` maps to one of eight fixed artifact families,
 * each with a fixed colour slot (identity follows the category, never its rank), plus "other".
 */
export interface DataCategory {
  key: string;
  label: string;
  /** CSS custom property holding the category colour (`var(--cat-n)`). */
  color: string;
}

export const DATA_CATEGORIES: DataCategory[] = [
  { key: "eventlog", label: "Event logs", color: "var(--cat-1)" },
  { key: "filesystem", label: "File system", color: "var(--cat-2)" },
  { key: "execution", label: "Execution", color: "var(--cat-3)" },
  { key: "browser", label: "Browser", color: "var(--cat-4)" },
  { key: "registry", label: "Registry", color: "var(--cat-5)" },
  { key: "network", label: "Network", color: "var(--cat-6)" },
  { key: "memory", label: "Memory", color: "var(--cat-7)" },
  { key: "messaging", label: "Mail and mobile", color: "var(--cat-8)" },
];

export const OTHER_CATEGORY: DataCategory = { key: "other", label: "Other", color: "var(--cat-other)" };

const RULES: [RegExp, string][] = [
  [/(^|:)(evtx|evt|eventlog|syslog|journal|auditd|utmp|wtmp|setupapi)/, "eventlog"],
  [
    /(prefetch|amcache|shimcache|appcompat|srum|bam|userassist|lnk|jumplist|bash_history|powershell)/,
    "execution",
  ],
  [/^(fs|ntfs|mft|usn)(:|$)|(^|:)(fs|mft|usn|zone_identifier|recycle)/, "filesystem"],
  [/^(chrome|firefox|edge|safari|webhist|browser|msie|opera)(:|$)/, "browser"],
  [/(registry|winreg|hive)/, "registry"],
  [
    /^(net|network|pcap|dns|zeek|firewall|proxy|http|netflow)(:|$)|(^|:)(dns|pcap|netstat|connection)/,
    "network",
  ],
  [/^(memory|volatility|mem)(:|$)/, "memory"],
  [/^(email|mail|msg|pst|ios|android|imessage|whatsapp|sms)(:|$)/, "messaging"],
];

export function dataTypeCategory(dataType: string | null | undefined): DataCategory {
  const dt = (dataType ?? "").toLowerCase();
  if (!dt) return OTHER_CATEGORY;
  for (const [re, key] of RULES) {
    if (re.test(dt)) return DATA_CATEGORIES.find((c) => c.key === key) ?? OTHER_CATEGORY;
  }
  return OTHER_CATEGORY;
}

export function categoryByKey(key: string): DataCategory {
  return DATA_CATEGORIES.find((c) => c.key === key) ?? OTHER_CATEGORY;
}

/**
 * Group data-type facet values into categories (largest first, in-category data types listed).
 * At most `maxCategories` named categories are returned; the rest fold into "other".
 */
export function groupDataTypes(
  facets: { value: string; count: number }[],
  maxCategories = 4,
): { category: DataCategory; dataTypes: string[]; count: number }[] {
  const groups = new Map<string, { category: DataCategory; dataTypes: string[]; count: number }>();
  for (const f of facets) {
    if (!f.value) continue;
    const cat = dataTypeCategory(f.value);
    const g = groups.get(cat.key) ?? { category: cat, dataTypes: [], count: 0 };
    g.dataTypes.push(f.value);
    g.count += f.count;
    groups.set(cat.key, g);
  }
  const named = [...groups.values()]
    .filter((g) => g.category.key !== OTHER_CATEGORY.key)
    .sort((a, b) => b.count - a.count || a.category.key.localeCompare(b.category.key));
  return named.slice(0, Math.max(0, maxCategories));
}

const ATTR_GROUPS: { key: string; label: string; tokens: string[] }[] = [
  {
    key: "identity",
    label: "Identity and logon",
    tokens: [
      "user",
      "username",
      "sid",
      "account",
      "domain",
      "logon",
      "owner",
      "subject",
      "group",
      "uid",
      "gid",
      "member",
    ],
  },
  {
    key: "process",
    label: "Process and execution",
    tokens: [
      "process",
      "pid",
      "ppid",
      "image",
      "command",
      "cmdline",
      "commandline",
      "parent",
      "exe",
      "executable",
      "service",
      "task",
      "module",
      "thread",
      "args",
      "run",
    ],
  },
  {
    key: "network",
    label: "Network",
    tokens: [
      "ip",
      "ipaddress",
      "addr",
      "address",
      "port",
      "url",
      "dns",
      "protocol",
      "remote",
      "workstation",
      "hostname",
      "src",
      "dst",
      "source",
      "destination",
      "referrer",
    ],
  },
  {
    key: "file",
    label: "File system",
    tokens: [
      "path",
      "file",
      "filename",
      "hash",
      "sha1",
      "sha256",
      "md5",
      "size",
      "extension",
      "directory",
      "dir",
      "volume",
      "mft",
      "inode",
      "drive",
      "usn",
      "reason",
    ],
  },
  {
    key: "time",
    label: "Time",
    tokens: ["time", "date", "timestamp", "created", "modified", "accessed", "changed", "ts", "duration"],
  },
  {
    key: "event",
    label: "Event record",
    tokens: [
      "event",
      "eventid",
      "channel",
      "provider",
      "record",
      "level",
      "keywords",
      "opcode",
      "computer",
      "identifier",
      "category",
      "xml",
    ],
  },
];

/** Split attribute keys into readable groups (first matching token wins; "Other" last). */
export function groupAttributes<T>(
  attrs: Record<string, T>,
): { key: string; label: string; entries: [string, T][] }[] {
  const out = new Map<string, [string, T][]>();
  for (const [k, v] of Object.entries(attrs)) {
    const tokens = k
      .replace(/([a-z])([A-Z])/g, "$1_$2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
    const g = ATTR_GROUPS.find((grp) => tokens.some((t) => grp.tokens.includes(t)));
    const key = g?.key ?? "other";
    out.set(key, [...(out.get(key) ?? []), [k, v]]);
  }
  return [...ATTR_GROUPS, { key: "other", label: "Other", tokens: [] }]
    .filter((g) => out.has(g.key))
    .map((g) => ({ key: g.key, label: g.label, entries: out.get(g.key) ?? [] }));
}
