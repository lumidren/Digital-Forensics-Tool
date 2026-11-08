# Parsers

Every parser emits the unified event schema (`docs/ARCHITECTURE.md` section 6) with Plaso
`data_type` and `timestamp_desc` names where Plaso has them, and records the evidence hash, the path
inside the evidence, the record offset and its own version. Validation against reference tools is
in [PARITY.md](PARITY.md); this page lists what each parser covers and what it does not.

All Rust parsers are `#![forbid(unsafe_code)]`, bounds-check every length field, cap recursion and
decompression output, and have property-based "never panics" tests plus cargo-fuzz targets
(`crates/*/fuzz`, run by `scripts/fuzz_smoke.py`). Python parsers turn any record-level failure into
a counted warning and only ever raise `ParserError`, verified with Hypothesis.

## Acquisition and containers

| Component | Coverage | Reference | Not supported |
|---|---|---|---|
| `veritas-ewf` writer | EnCase 6 E01: header/header2, volume, sectors/table/table2, zlib chunks, segment chains to EAA.., MD5 hash and MD5+SHA-1 digest sections, error2 bad-sector map | libewf (pyewf): byte-identical media, same hashes | Ex01/EWF2, L01 |
| `veritas-ewf` reader | E01 segment chains, table2 fallback, verify; raw `.000/.001`, `.aa` splits | libewf | encrypted Ex01 |
| `veritas-aff4` writer / reader | AFF4 Standard v1.0 disk images in a ZIP64 volume: `container.description`, `version.txt`, `information.turtle` (aff4:ZipVolume, aff4:Image/DiskImage, aff4:Map, aff4:ImageStream, aff4:CaseDetails), bevies with `.index` (u64 offset + u32 length per chunk), 32 KiB chunks by default; chunk compression deflate (zlib framing, RFC 1950), raw deflate (RFC 1951), snappy and stored written and read, LZ4 read; MD5, SHA-1 and SHA-256 as `aff4:hash` literals (SHA-512 also verified); reader resolves aff4:Image -> aff4:dataStream -> aff4:Map -> image streams, stored ZIP segments and symbolic streams (Zero, UnknownData, UnreadableData, SymbolicStreamXX), map gaps, appended-ZIP offsets; bounded Turtle subset parser; ZIP CRC-32 checked on verify; `aff4-tool write/info/verify/dump`; read by `fs-tool` / `open_evidence` and `veritas hash --media` | pyaff4 0.34 in both directions: byte-identical media, same stored MD5/SHA-1 | AFF4 Logical (aff4:FileImage), encrypted AFF4 (aff4:EncryptedStream), pre-standard / legacy-namespace streams, multi-part volumes, hash-based (deduplicated) images, nested maps, writing LZ4; bad sectors are stored zero-filled and listed as `veritas:badSectors` rather than mapped to aff4:UnreadableData; not yet compared against Evimetry-written reference images |
| `veritas-agent` | live triage bundle with manifest, raw NTFS copy of `$MFT`/`$LogFile`/`$J`, imaging to E01, AFF4 or raw with retry and zero-fill, write-block check, WinPmem/LiME/osxpmem drivers, resumable mTLS upload, signed acquisition entry | hashes vs `veritas hash`; raw NTFS copies vs pytsk3 | Linux/macOS collectors not yet run on real hosts; E01 and AFF4 output is not resumable (raw is) |

## File systems (`veritas-fs`)

| File system | Coverage | Reference | Not supported |
|---|---|---|---|
| MBR / GPT | extended partitions, GPT header and entry CRC32 | pytsk3 | LVM, dynamic disks (detected only) |
| NTFS | MFT with fixups, all `$FILE_NAME`s, ADS, resident/non-resident/sparse/LZNT1 data, `$ATTRIBUTE_LIST`, `$I30` including slack, deleted records, USN V2-V4, `$LogFile` records, timestomp indicators | pyfsntfs, pytsk3, dissect.ntfs | `$LogFile` replay, EFS, WOF/dedup |
| FAT12/16/32, exFAT | chains, LFN with checksum, deleted entries, exFAT UTC offsets | pytsk3, pyfsfat | exFAT checksums (exFAT tested on a synthetic image only) |
| ext2/3/4 | inodes with ns times and crtime, extents and block maps, deleted inodes and directory slack, jbd2 enumeration | pyfsext, pytsk3 | htree hash lookup (linear walk instead), inline data > 60 B, fscrypt, journal replay |
| APFS | checkpoints, object maps, volume superblocks, FS B-trees, snapshot listing | pyfsapfs | encryption in Rust (Python adapter only), transparent compression, snapshot trees |
| VSS | catalog, stores, read-through view of each shadow copy | pyvshadow (byte-identical over 82 MB) | validated on one two-store image |
| Carving | JPEG, PNG (CRC), PDF, ZIP/OOXML, GIF, PE, SQLite, EVTX, with validation and size caps | constructed fixtures | fragmented files |
| Decryption (Python) | BitLocker (password, recovery password, startup key), LUKS1/LUKS2, encrypted APFS | pybde, pyluksde, own LUKS2 key-slot unlock, pyfsapfs | LUKS2 with non-AES ciphers |
| `harvest` | extracts known artifact paths for Windows, Linux and macOS into a manifest with hashes | | |

## Windows artifacts (`veritas-artifacts`, Rust)

| Artifact | Data types | Reference |
|---|---|---|
| Registry hives, with LOG1/LOG2 replay and deleted-cell recovery | `windows:registry:key_value` | libregf, dissect.regf |
| UserAssist, ShellBags, RecentDocs/RunMRU/OpenSave/LastVisited/WordWheel/TypedURLs/TypedPaths | `windows:registry:userassist`, `windows:shellbags`, `windows:registry:mrulist(ex)`, `windows:registry:typedurls` | independent decoders |
| USB (USBSTOR, USB, MountedDevices, WPD, MountPoints2), network profiles | `windows:registry:usbstor`, `windows:registry:usb`, `windows:registry:network` | |
| ShimCache (XP to Win11), Amcache (old and Inventory layouts), BAM/DAM | `windows:registry:appcompatcache`, `windows:registry:amcache`, `windows:registry:bam` | independent decoder |
| Services, autoruns (Run keys, Winlogon, IFEO, AppInit, LSA, Active Setup, ...), system info | `windows:registry:service`, `windows:registry:run`, `windows:registry:sysinfo` | |
| EVTX (full binary XML, templates, substitutions, CRC flags), legacy EVT, ~165 known event IDs | `windows:evtx:record`, `windows:evt:record` | libevtx (XML identical), pyevt |
| Prefetch v17/23/26/30/31 with LZXPRESS Huffman | `windows:prefetch:execution` | libscca |
| LNK, shell items (~67 known folders), OLE compound files, jump lists | `windows:lnk:link`, `windows:shell_item:file_entry`, `windows:jump_list:*` | liblnk, libfwsi, libolecf |
| Scheduled tasks (`.job` and Task Scheduler 2.0 XML) | `windows:tasks:job`, `windows:tasks:xml` | |

## Linux and macOS (Rust and Python)

| Artifact | Data types | Reference |
|---|---|---|
| systemd journal (regular and compact, LZ4) | `systemd:journal` | independent reader (XZ/ZSTD payloads reported, not decoded) |
| plist (binary and XML, NSKeyedArchiver), install history, login items, Time Machine, AirPort, Bluetooth | `macos:*`, `plist:key` | plistlib |
| syslog (traditional, RFC 5424, sudo, ssh, cron), auditd, utmp/wtmp, shell histories (bash, zsh, fish), cron, systemd units, SSH files, dpkg/apt/dnf/yum logs, Apache | `syslog:*`, `linux:*`, `bash:history:entry`, ... | Plaso |
| Unified logs (via `log show` JSON exports), FSEvents, KnowledgeC, quarantine, TCC, application usage, notification center, iMessage, launchd plists and logs, BTM, ASL, BSM, Santa, wifi and firewall logs | `macos:*`, `bsm:entry`, `santa:*` | Plaso |

tracev3 is not decoded natively; examiners export with `log show --style ndjson` or run on macOS.

## Windows and cross-platform (Python)

Chromium (History, Cookies, Web Data, Login Data), Firefox (places, downloads, cookies), MSIE
index.dat and WebCache, SRUM (five tables), PST/OST and mbox, OOXML and OLE Office metadata,
Recycle Bin (`$I` v1/v2, INFO2), PowerShell transcripts and history, Windows Timeline, setupapi,
Windows Firewall log, Defender detection history and MPLog, WMI persistence carving.

## Memory, network and malware (Python)

| Area | Coverage | Reference |
|---|---|---|
| Memory | Volatility 3 in-process and CLI; Windows, Linux and macOS plugin sets; process-tree anomalies, hidden processes, unlinked DLLs, RWX private memory, hollowing, lsass access; YARA over process memory | Volatility 3 (parity test gated on `VERITAS_MEM_IMAGE`: no public image small enough for the corpus) |
| PCAP | own pcap/pcapng reader with ns timestamps; flows, DNS, HTTP with reassembly, TLS SNI/JA3/JA3S and certificates, file extraction; Zeek adapter with native fallback | scapy |
| Static analysis | PE (imports, sections and entropy, imphash, Rich header, resources, TLS, overlay, Authenticode via LIEF), ELF and Mach-O basics | LIEF, pefile |
| YARA | curated rules (`rules/yara`), rule-set fingerprint recorded per match | |
| Reputation and sandbox | VirusTotal v3, MalwareBazaar (keys from environment only, never logged); CAPE and Cuckoo REST adapters | mock servers |

## Cloud and mobile (Python)

AWS CloudTrail, S3 access logs, ELB/ALB/NLB; Azure Activity, Entra audit and sign-in, Application
Gateway; Google Workspace Reports; Microsoft 365 Unified Audit Log (CSV and JSON). iOS backups
(unencrypted, iOS 10+) with SMS, calls, contacts, photos metadata, Wi-Fi, accounts, data usage;
Android ADB backups and `adb pull` trees with SMS/MMS, calls, contacts, downloads, WebView, browser,
packages. Scope limits and their reasons are in [MOBILE_SCOPE.md](MOBILE_SCOPE.md).
