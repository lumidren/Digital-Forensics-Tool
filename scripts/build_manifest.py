#!/usr/bin/env python3
"""Build testdata/MANIFEST.json from local plaso/dfvfs sparse checkouts (maintainer tool)."""
import hashlib, json, pathlib, sys
src = pathlib.Path(sys.argv[1])
WANT = {
 "plaso": ["MFT","UsnJrnl.raw","NTUSER.DAT","NTUSER-WIN7.DAT","SYSTEM","SOFTWARE","SRUDB.dat","NeroInfoTool.lnk","example.lnk",
           "unpaired_surrogate.lnk","SysEvent.Evt","test.pcap","test_pe.exe","test_driver.sys","bash_history","zsh_extended_history.txt",
           "powershell_transcript.txt","wintask.job","apache_access.log","audit.log","dpkg.log","apt_history.log","security.log","typed_history.xml",
           "aws_elb_access.log","azure_application_gateway_access.json","Cookies.binarycookies","Document.docx","Document.doc",
           "ios_app_privacy_report.ndjson","ios_lockdownd.log","ios_sysdiag.log","backgrounditems.btm","fish_history",
           "winprefetch/CMD.EXE-087B4001.pf","winprefetch/PING.EXE-B29F6629.pf","winprefetch/TASKHOST.EXE-3AE259FC.pf",
           "winprefetch/NOTEPAD.EXE-D8414F97.pf","winprefetch/WUAUCLT.EXE-830BCC14.pf","winprefetch/ONEDRIVE.EXE-7E152375.pf",
           "winprefetch/BYTECODEGENERATOR.EXE-C1E9BCE6.pf","winprefetch/AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf",
           "automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms","automaticDestinations-ms/9d1f905ce5044aee.automaticDestinations-ms",
           "customDestinations-ms/368d807282ccde9d.customDestinations-ms","customDestinations-ms/5afe4de1b92fc382.customDestinations-ms",
           "plist/com.apple.loginitems.plist","plist/InstallHistory.plist","plist/com.apple.TimeMachine.plist","plist/launchd.minimal.plist",
           "plist/com.apple.airport.preferences.plist","plist/com.apple.bluetooth.plist","plist/NSKeyedArchiver.plist","plist/com.apple.SoftwareUpdate.plist",
           "utmp/utmp","utmp/wtmp.1","utmp/utmp_corrupted","utmpx_mac",
           "syslog/syslog","syslog/syslog_rsyslog","syslog/syslog_ssh.log","syslog/syslog_sudo.log","syslog/syslog_cron.log","syslog/syslog_osx",
           "systemd/journal/system.journal","systemd/journal/user-1000.journal",
           "sqlite/quarantine.db","sqlite/imessage_chat.db","sqlite/dropbox_sync_history.db","sqlite/skype_main.db","mac_notificationcenter.db",
           "evtx/System.evtx","evtx/System2.evtx","chrome/History","chrome/History-59.0.3071.86","chrome/Cookies-68.0.3440.106","chrome/Web Data",
           "firefox/places.sqlite","firefox/places118.sqlite","firefox/downloads.sqlite","fsevents/fsevents-00000000001a0b79","fsevents/fsevents-0000000002d89b58",
           "ios/Accounts3.sqlite","ios/DataUsage.sqlite","ios/NoteStore.sqlite","ios/com.apple.wifi.known-networks.plist","ios/com.apple.MobileBackup.plist","ios/netusage.sqlite",
           "macos/knowledgec-10.14.db","macos/knowledgec-10.13.db","macos/TCC-test.db","macos/application_usage.sqlite","recycler/$I103S5F.jpg","recycler/$II3DF3L.zip","recycler/INFO2",
           "android/mmssms.db","android/contacts2.db","android/downloads.db","android/webview.db","msiecf/nfury_index.dat","2019.09.26.asl","apple.bsm","openbsm.bsm","wifi.log","santa.log","appfirewall.log","macos_launchd.log",
           "ext4.raw","vsstest.qcow2","image.E01","image-split.E01","image-split.E02","tsk_volume_system.raw","ímynd.dd","syslog_image.dd"],
 "dfvfs": ["ntfs.raw","ext4.raw","ext2.raw","fat12.raw","apfs.raw","apfs_encrypted.dmg","mbr.raw","gpt.raw","gpt_in_mbr.raw","ext2.E01","ext2.split.E01","ext2.split.E02",
           "ext2.splitraw.000","ext2.splitraw.001","vss.raw","bdetogo.raw","luks1.raw","luks2.raw","hfsplus.raw","iso9660.raw","lvm.raw","xfs.raw"],
}
out = {"files": {}}
for proj, files in WANT.items():
    out["files"][proj] = {}
    for rel in files:
        p = src / proj / "test_data" / rel
        if not p.exists():
            print("skip missing", proj, rel); continue
        out["files"][proj][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
pathlib.Path("testdata/MANIFEST.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(sum(len(v) for v in out["files"].values()), "files in manifest")
