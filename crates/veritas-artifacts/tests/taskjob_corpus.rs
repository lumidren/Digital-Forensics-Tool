//! Task Scheduler tests. wintask.job expectations follow Plaso's winjob parser test
//! (application, parameters, author, last run 2013-08-24 12:42:00.112, scheduled start
//! 2013-07-12 15:42:00); the XML task is a synthetic Task Scheduler 2.0 definition.
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::taskjob;
use veritas_timeline::format_ns;

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso").join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var("VERITAS_REQUIRE_CORPUS").is_err() => {
            eprintln!("skipping: corpus file {} missing (run testdata/fetch.py)", p.display());
            None
        }
        Err(e) => panic!("corpus file {} missing: {e}", p.display()),
    }
}

#[test]
fn wintask_job() {
    let Some(d) = corpus("wintask.job") else { return };
    let j = taskjob::parse_job(&d).unwrap();
    assert_eq!(j.application_name, r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe");
    assert_eq!(j.parameters, "/ua /installsource scheduler");
    assert_eq!(j.author, "Brian");
    assert_eq!(j.working_directory, "");
    assert!(j.comment.starts_with("Keeps your Google software up to date."));
    assert_eq!(j.uuid, "0df2cfeb-5293-41e9-a45e-733720c2e1fa");
    assert_eq!(format_ns(j.last_run_time.to_ns().unwrap()), "2013-08-24T12:42:00.112000Z");
    assert_eq!(j.triggers.len(), 1);
    assert_eq!(j.triggers[0].trigger_type_name, "DAILY");
    assert_eq!(format_ns(j.triggers[0].start_ns().unwrap()), "2013-07-12T15:42:00.000000Z");
    let ev = taskjob::job_events(&j, "s", "wintask.job");
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0].data_type, "windows:tasks:job");
    assert_eq!(ev[0].timestamp_desc, "Last Time Executed");
    assert_eq!(ev[1].timestamp_desc, "Scheduled to start");
    assert_eq!(serde_json::to_string(&ev).unwrap(), serde_json::to_string(&taskjob::job_events(&taskjob::parse_job(&d).unwrap(), "s", "wintask.job")).unwrap());
}

const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2021-03-04T05:06:07.1234567</Date>
    <Author>CONTOSO\admin</Author>
    <URI>\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2021-03-05T00:00:00Z</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c evil.bat</Arguments></Exec>
  </Actions>
</Task>"#;

#[test]
fn task_xml_utf16() {
    let mut d = vec![0xff, 0xfe];
    for u in TASK_XML.encode_utf16() {
        d.extend_from_slice(&u.to_le_bytes());
    }
    let t = taskjob::parse_task_xml(&d).unwrap();
    assert_eq!(t.author.as_deref(), Some(r"CONTOSO\admin"));
    assert_eq!(t.uri.as_deref(), Some(r"\Updater"));
    assert_eq!(t.user_id.as_deref(), Some("S-1-5-18"));
    assert_eq!(t.run_level.as_deref(), Some("HighestAvailable"));
    assert_eq!(t.hidden.as_deref(), Some("true"));
    assert_eq!(t.triggers.len(), 2);
    assert_eq!(t.actions[0].command.as_deref(), Some(r"C:\Windows\System32\cmd.exe"));
    assert_eq!(t.actions[0].arguments.as_deref(), Some("/c evil.bat"));
    let ev = taskjob::xml_events(&t, "s", "Updater");
    assert_eq!(ev.len(), 2);
    assert_eq!(ev[0].data_type, "windows:tasks:xml");
    assert_eq!(format_ns(ev[0].timestamp.unwrap()), "2021-03-04T05:06:07.123456Z");
    assert_eq!(format_ns(ev[1].timestamp.unwrap()), "2021-03-05T00:00:00.000000Z");
    assert_eq!(ev[0].attrs["command"], r"C:\Windows\System32\cmd.exe");
    // UTF-8 input works too
    assert!(taskjob::parse_task_xml(TASK_XML.replace("UTF-16", "UTF-8").as_bytes()).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]
    #[test]
    fn job_mutations_never_panic(muts in proptest::collection::vec((0usize..896, any::<u8>()), 1..32), cut in 0usize..896) {
        if let Some(mut d) = corpus("wintask.job") {
            let n = d.len();
            for (o, b) in &muts { d[o % n] = *b; }
            if let Ok(j) = taskjob::parse_job(&d) { let _ = taskjob::job_events(&j, "", ""); }
            let _ = taskjob::parse_job(&d[..cut % n]);
        }
    }

    #[test]
    fn xml_random_never_panics(s in ".{0,400}") {
        let _ = taskjob::parse_task_xml(s.as_bytes());
        let _ = taskjob::parse_xml_datetime(&s);
    }
}
