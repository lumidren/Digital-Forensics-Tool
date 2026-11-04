//! Linux and macOS collectors. Compiled on every platform (paths are data); run only on the
//! matching OS. Unreadable files (other users' histories, `/var/log/auth.log` without the `adm`
//! group, `log collect` without root) are recorded as errors.

use super::{profile_label, user_profiles, CollectorFn, Ctx, Profile};
use crate::{cmd, Result};
use std::path::{Path, PathBuf};

pub fn linux_collectors() -> Vec<(&'static str, CollectorFn)> {
    vec![("auth_logs", linux_logs), ("journal", linux_journal), ("shell_history", shell_history), ("cron", cron), ("systemd", systemd)]
}

pub fn macos_collectors() -> Vec<(&'static str, CollectorFn)> {
    vec![("launchd", launchd), ("unified_log", unified_log), ("shell_history", shell_history), ("cron", cron), ("macos_logs", macos_logs)]
}

fn prefixed(dir: &Path, prefixes: &[&str]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.file_name().map(|n| prefixes.iter().any(|x| n.to_string_lossy().starts_with(x))).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn linux_logs(ctx: &mut Ctx) -> Result<()> {
    let mut wanted = vec!["auth.log", "secure", "wtmp", "btmp", "lastlog", "faillog", "audit"];
    if ctx.opts.profile == Profile::Full {
        wanted.extend(["syslog", "messages", "kern.log", "dpkg.log", "yum.log", "cron"]);
    }
    for p in prefixed(Path::new("/var/log"), &wanted) {
        let name = format!("logs{}", p.display());
        ctx.bundle.add_file("auth_logs", &name, &p)?;
    }
    let audit = Path::new("/var/log/audit");
    if audit.is_dir() {
        ctx.bundle.add_tree("auth_logs", "logs/var/log/audit", audit, false, 200, &|_| true)?;
    }
    Ok(())
}

fn linux_journal(ctx: &mut Ctx) -> Result<()> {
    let args: Vec<&str> = match ctx.opts.profile {
        Profile::Quick => vec!["--no-pager", "-o", "export", "--since", "-2d"],
        Profile::Full => vec!["--no-pager", "-o", "export"],
    };
    ctx.command("journal", "logs/journal.export", "journalctl", &args)?;
    Ok(())
}

fn shell_history(ctx: &mut Ctx) -> Result<()> {
    let files = [".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history", ".local/share/fish/fish_history", ".mysql_history", ".psql_history", ".lesshst", ".viminfo"];
    for p in user_profiles() {
        let user = profile_label(&p);
        for f in files {
            ctx.copy_if_exists("shell_history", &format!("shell_history/{}/{}", user, f), &p.join(f))?;
        }
        let sessions = p.join(".zsh_sessions");
        if sessions.is_dir() {
            ctx.bundle.add_tree("shell_history", &format!("shell_history/{}/.zsh_sessions", user), &sessions, false, 500, &|_| true)?;
        }
    }
    Ok(())
}

fn cron(ctx: &mut Ctx) -> Result<()> {
    ctx.copy_if_exists("cron", "cron/etc/crontab", Path::new("/etc/crontab"))?;
    ctx.copy_if_exists("cron", "cron/etc/anacrontab", Path::new("/etc/anacrontab"))?;
    for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/usr/lib/cron/tabs", "/var/at/tabs", "/etc/periodic"] {
        let p = Path::new(d);
        if p.is_dir() {
            ctx.bundle.add_tree("cron", &format!("cron{}", d), p, true, 2000, &|_| true)?;
        }
    }
    Ok(())
}

fn systemd(ctx: &mut Ctx) -> Result<()> {
    let mut dirs = vec!["/etc/systemd/system", "/run/systemd/system", "/etc/init.d", "/etc/rc.local"];
    if ctx.opts.profile == Profile::Full {
        dirs.extend(["/usr/lib/systemd/system", "/lib/systemd/system"]);
    }
    for d in dirs {
        let p = Path::new(d);
        if p.is_dir() {
            ctx.bundle.add_tree("systemd", &format!("systemd{}", d), p, true, 5000, &|_| true)?;
        } else {
            ctx.copy_if_exists("systemd", &format!("systemd{}", d), p)?;
        }
    }
    for p in user_profiles() {
        let u = p.join(".config/systemd/user");
        if u.is_dir() {
            ctx.bundle.add_tree("systemd", &format!("systemd/users/{}", profile_label(&p)), &u, true, 500, &|_| true)?;
        }
    }
    ctx.command("systemd", "systemd/list-unit-files.txt", "systemctl", &["list-unit-files", "--no-pager"])?;
    Ok(())
}

fn launchd(ctx: &mut Ctx) -> Result<()> {
    let mut dirs: Vec<PathBuf> = ["/Library/LaunchAgents", "/Library/LaunchDaemons", "/Library/StartupItems"].iter().map(PathBuf::from).collect();
    if ctx.opts.profile == Profile::Full {
        dirs.extend(["/System/Library/LaunchAgents", "/System/Library/LaunchDaemons"].iter().map(PathBuf::from));
    }
    for d in dirs {
        if d.is_dir() {
            ctx.bundle.add_tree("launchd", &format!("launchd{}", d.display()), &d, true, 5000, &|_| true)?;
        }
    }
    for p in user_profiles() {
        let d = p.join("Library/LaunchAgents");
        if d.is_dir() {
            ctx.bundle.add_tree("launchd", &format!("launchd/users/{}/LaunchAgents", profile_label(&p)), &d, true, 1000, &|_| true)?;
        }
    }
    ctx.command("launchd", "launchd/launchctl_list.txt", "launchctl", &["list"])?;
    Ok(())
}

/// `log collect` produces a `.logarchive` directory (root required); quick profile collects the
/// last hour, full the last day.
fn unified_log(ctx: &mut Ctx) -> Result<()> {
    let out = ctx.tmp.join("system.logarchive");
    let out_s = out.display().to_string();
    let last = if ctx.opts.profile == Profile::Full { "1d" } else { "1h" };
    match cmd::run("log", &["collect", "--last", last, "--output", out_s.as_str()], ctx.opts.command_timeout * 4) {
        Ok(o) if o.success() && out.is_dir() => {
            ctx.bundle.add_tree("unified_log", "unified_log/system.logarchive", &out, true, 100_000, &|_| true)?;
        }
        Ok(o) => ctx.bundle.error("unified_log", "log collect", o.failure_text()),
        Err(e) => ctx.bundle.error("unified_log", "log collect", e),
    }
    Ok(())
}

fn macos_logs(ctx: &mut Ctx) -> Result<()> {
    for p in prefixed(Path::new("/var/log"), &["system.log", "install.log", "wifi.log", "fsck_"]) {
        ctx.bundle.add_file("macos_logs", &format!("logs{}", p.display()), &p)?;
    }
    for p in user_profiles() {
        ctx.copy_if_exists(
            "macos_logs",
            &format!("quarantine/{}/QuarantineEventsV2", profile_label(&p)),
            &p.join("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"),
        )?;
    }
    Ok(())
}
