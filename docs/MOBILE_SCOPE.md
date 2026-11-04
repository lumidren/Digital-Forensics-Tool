# Mobile scope

Veritas parses mobile evidence at the **logical / backup level only**. This document states what is
supported, what is deliberately out of scope and why, and how an examiner obtains input that the
parsers accept. Code: `python/veritas/mobile/` (`ios_backup.py`, `ios_db.py`, `android_backup.py`,
`android_db.py`); tests: `python/tests/unit/test_mobile_*.py`.

## 1. Scope limits and justification

| Out of scope | Why |
|---|---|
| Physical and full file-system extraction (chip-off, JTAG, ISP, agent-based FFS) | These require hardware, device-specific exploits or vendor agents. They cannot be reproduced from a published input format, which conflicts with the determinism and independent-verification goals (ARCHITECTURE.md sections 1 and 7). Backups are a documented, repeatable format the opposing expert can regenerate. |
| Encrypted backups (iOS `IsEncrypted`, Android `AES-256` `.ab`) | Decryption needs the user's backup password and keybag/PBKDF2 handling. Supporting it would put credential material inside the platform and create a password-cracking path. The parsers detect encryption and raise `ParserError` with a clear message instead of producing partial or misleading output. |
| checkm8 / bootrom exploits, jailbreaks, rooting | They change the device state, depend on specific hardware and OS versions, and are legally sensitive. Images produced this way can still be processed by the generic file-system pipeline, but no exploit tooling ships with Veritas. |
| Proprietary app decryption (WhatsApp `crypt14/15`, Signal, Telegram secret chats, keychain items) | The keys live in the Secure Enclave, Keystore or keychain, so recovering them needs privileged extraction (see above). The format details are also undocumented and change often. Files are still listed as `ios:backup:file` / `android:backup:file` so examiners can see they exist. |
| Legacy iOS 9 and earlier `Manifest.mbdb` backups | Obsolete since 2016. They are detected and rejected with `ParserError`. |
| Android 12+ binary ABX `packages.xml` | Detected and rejected. Convert it with `abx2xml` first, then parse the text XML. |
| Apple Notes body text (gzip'd protobuf), message attachments' content | Only metadata is extracted. Attachments are referenced by path. |

Every limit fails closed. Unsupported input raises `ParserError`, and damaged records become counted
warnings in `ParseResult.warnings`. No parser silently returns an empty result for a format it
does not support.

## 2. What each artifact supports

All timestamps are converted to integer ns UTC. Cocoa (2001 epoch) seconds and nanoseconds, Unix
ms/s and plist dates are handled. Coordinates are stored as 6-decimal strings. PII fields are
kept in full in `attrs` and flagged with `pii`. Messages redact IMEI, serial and phone numbers to
the last 4 digits.

### iOS (iTunes / Finder / `idevicebackup2`, iOS 10+)

| Artifact | Location in backup | `data_type` | Fields / events |
|---|---|---|---|
| Backup metadata | `Info.plist` | `ios:backup:info` | device name, product type/version, build, serial, IMEI, MEID, phone, ICCID, UDID; Last Backup Time |
| Backup status | `Status.plist` | `ios:backup:status` | date, full/incremental, snapshot state |
| Installed apps | `Manifest.plist` `Applications` | `ios:app:installed` | bundle id, version, container path (no time) |
| File inventory | `Manifest.db` `Files` | `ios:backup:file` | domain, relativePath, fileID, size, mode, uid/gid, protection class; LastModified / Birth / LastStatusChange |
| SMS / iMessage | `HomeDomain/Library/SMS/sms.db` | `ios:sms:message` | text, handle, service, chat, is_from_me; sent/received, read, delivered |
| Calls | `HomeDomain/Library/CallHistoryDB/CallHistory.storedata` | `ios:callhistory:call` | address, duration, originated/answered, call type; start and end |
| Contacts | `HomeDomain/Library/AddressBook/AddressBook.sqlitedb` | `ios:addressbook:contact` | names, organisation, phones, emails; creation/modification |
| Photos metadata | `CameraRollDomain/Media/PhotoData/Photos.sqlite` (`ZASSET` / `ZGENERICASSET`) | `ios:photos:asset` | filename, directory, kind, dimensions, lat/lon; created, added, modified |
| Wi-Fi | `com.apple.wifi.plist`, `com.apple.wifi.known-networks.plist` | `ios:wifi:known_network` | SSID, BSSID(s), security, channel; added/joined/updated |
| Accounts | `Accounts3.sqlite` | `ios:accounts:account` | username, type, owning bundle; creation |
| Data usage | `DataUsage.sqlite`, `netusage.sqlite` | `ios:{datausage,netusage}:{process,live_usage}` | process/bundle first and last seen; Wi-Fi/WWAN byte counters |
| Notes | `NoteStore.sqlite` | `ios:notes:note` | title, snippet, locked flag; created/modified |
| iCloud backup state (on-device plist) | `com.apple.MobileBackup.plist` | `ios:mobilebackup:event` | enable date, backup results |

The backup can be given as a directory or as a zip/tar of one. Archives are extracted to a
temporary directory with path-traversal, link and size checks. Every database parser also works
on a standalone file, for example `testdata/corpus/plaso/ios/*`.

### Android (`adb backup` `.ab` and `adb pull` trees)

| Artifact | File | `data_type` | Fields / events |
|---|---|---|---|
| Backup header | `.ab` | `android:backup:header` | version, compression, encryption (only `none` accepted) |
| Archive inventory | tar members | `android:backup:file` | path, size, mode, package; mtime |
| App inventory | `apps/<pkg>/_manifest`, `packages.xml` | `android:app:package` | package, version, code path, installer, permissions; install / update |
| SMS / MMS | `mmssms.db` | `android:messaging:sms`, `android:messaging:mms` | address, body, type, read/seen; MMS parts and addresses; sent/received |
| Call log | `contacts2.db` `calls` (≤ Android 6), `calllog.db` | `android:event:call` | number, name, type, duration, geocoded location; start and end |
| Contacts | `contacts2.db` `raw_contacts` + `data` + `mimetypes` | `android:contacts:contact` | display/given/family name, phones, emails, account |
| Downloads | `downloads.db` | `android:download` | URI, local path, MIME, status, sizes, requesting package; lastmod |
| WebView | `webview.db` | `android:webview:{cookie,formdata,credential}` | cookies (expiry), form data, stored credentials (username only; passwords are never copied) |
| Stock browser | `browser2.db` / `browser.db` | `android:browser:{history,bookmark}` | URL, title, visits; last visit / created |

The `.ab` payload is inflated as a stream and read as a streaming tar, so it is never fully
loaded into memory. If one member database fails to parse, that is recorded as a warning and the
rest of the archive is still processed. Directory mode walks an `adb pull` tree and sends each
known database file to the same parser.

## 3. How examiners obtain supported input

**iOS (unencrypted logical backup)**

```sh
idevicepair pair                                         # trust the workstation on the device
idevicebackup2 -i encryption off                          # only if the user agrees; needs the current password
idevicebackup2 backup --full ./case-1234/ios-backup
```

Alternatives: Finder (macOS 10.15+) or iTunes (Windows) with "Encrypt local backup" unticked. The
backup directory is `~/Library/Application Support/MobileSync/Backup/<UDID>` or
`%APPDATA%\Apple Computer\MobileSync\Backup\<UDID>`. Hash the directory (or a zip/tar of it)
before ingest. Turning encryption off causes iOS to exclude keychain, Health and some Wi-Fi data;
record this limitation in the case notes.

**Android `adb backup`** (deprecated in Android 12; app opt-out via `allowBackup=false`)

```sh
adb backup -all -shared -apk -f case-1234.ab
```

Leave the on-device password field empty, otherwise the archive is AES-256 encrypted and will be
rejected. On Android 12 and later, `adb backup` only covers apps that target older SDKs.

**Android `adb pull`** (rooted or debug builds, or exports from a lawful extraction tool)

```sh
adb root
adb pull /data/data/com.android.providers.telephony/databases/mmssms.db ./case-1234/pull/data/data/com.android.providers.telephony/databases/
adb pull /data/data/com.android.providers.contacts/databases/ ./case-1234/pull/data/data/com.android.providers.contacts/
adb pull /data/system/packages.xml ./case-1234/pull/data/system/
```

Keep the device paths under the pull root, because they become `evidence_path` values. Rooting a
device to make `adb root` work is outside Veritas scope (see section 1).
