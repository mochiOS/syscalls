//! Small std-based test runner usable without libtest on mochiOS.
//! Each case runs in a fresh ordinary process. The parent reports every
//! result, including timeout or failed child creation, over a supplied writer.
use std::{
    io::{self, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const PROTOCOL: u32 = 1;
pub type TestResult = Result<(), String>;

pub struct Case {
    pub id: &'static str,
    pub timeout_seconds: u64,
    pub run: fn() -> TestResult,
}

pub fn require(condition: bool, message: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Emits bounded, newline-delimited JSON. A missing final summary is never
/// evidence of success; the receiving runner must verify the entire plan.
pub struct Reporter<W: Write> {
    writer: W,
    run_id: String,
}
impl<W: Write> Reporter<W> {
    pub fn new(writer: W, run_id: &str) -> io::Result<Self> {
        if run_id.len() != 32 || !run_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid test run ID",
            ));
        }
        Ok(Self {
            writer,
            run_id: run_id.into(),
        })
    }
    fn event(&mut self, event: &str, fields: &str) -> io::Result<()> {
        writeln!(
            self.writer,
            "{{\"protocol\":{PROTOCOL},\"run_id\":{},\"event\":{}{fields}}}",
            quoted(&self.run_id),
            quoted(event)
        )?;
        self.writer.flush()
    }
    pub fn begin(&mut self, cases: &[Case]) -> io::Result<()> {
        if cases.is_empty()
            || cases.iter().enumerate().any(|(i, c)| {
                c.id.is_empty()
                    || c.id.len() > 64
                    || !c.id.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                    })
                    || c.timeout_seconds == 0
                    || c.timeout_seconds > 1800
                    || cases[..i].iter().any(|p| p.id == c.id)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty or duplicate test plan",
            ));
        }
        let ids = cases
            .iter()
            .map(|c| quoted(c.id))
            .collect::<Vec<_>>()
            .join(",");
        self.event("begin", &format!(",\"cases\":[{ids}]"))
    }
    pub fn start(&mut self, id: &str) -> io::Result<()> {
        self.event("start", &format!(",\"id\":{}", quoted(id)))
    }
    pub fn result(
        &mut self,
        id: &str,
        passed: bool,
        detail: &str,
        elapsed: Duration,
    ) -> io::Result<()> {
        self.event(
            "result",
            &format!(
                ",\"id\":{},\"status\":{},\"detail\":{},\"elapsed_ms\":{}",
                quoted(id),
                quoted(if passed { "pass" } else { "fail" }),
                quoted(detail),
                elapsed.as_millis()
            ),
        )
    }
    pub fn end(&mut self, passed: usize, failed: usize) -> io::Result<()> {
        self.event("end", &format!(",\"passed\":{passed},\"failed\":{failed}"))
    }
}

pub fn run_case(cases: &[Case], id: &str) -> i32 {
    match cases.iter().find(|case| case.id == id) {
        Some(case) => match (case.run)() {
            Ok(()) => 0,
            Err(reason) => {
                eprintln!("{}: {reason}", case.id);
                1
            }
        },
        None => {
            eprintln!("unknown test case: {id}");
            2
        }
    }
}

fn isolated(executable: &std::path::Path, case: &Case) -> TestResult {
    use std::io::{Read, Seek, SeekFrom};
    struct Log(std::path::PathBuf);
    impl Drop for Log {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "mochios-test-{}-{}.log",
        std::process::id(),
        case.id
    ));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&path)
        .map_err(|e| format!("cannot create case log: {e}"))?;
    let _owned_log = Log(path);
    let mut child = Command::new(executable)
        .args(["--case", case.id])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(output.try_clone().map_err(|e| e.to_string())?))
        .spawn()
        .map_err(|e| format!("cannot start case: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(case.timeout_seconds);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if output.metadata().map_err(|e| e.to_string())?.len() > 65536 {
                    return Err("case log exceeded its limit".into());
                }
                return if status.success() {
                    Ok(())
                } else {
                    let mut captured = Vec::new();
                    output.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                    output
                        .take(4096)
                        .read_to_end(&mut captured)
                        .map_err(|e| e.to_string())?;
                    Err(format!(
                        "child exited {status}: {}",
                        String::from_utf8_lossy(&captured)
                    ))
                };
            }
            Ok(None)
                if Instant::now() < deadline
                    && output.metadata().is_ok_and(|m| m.len() <= 65536) =>
            {
                thread::sleep(Duration::from_millis(10))
            }
            state => {
                // Stop and reap this case process before proceeding.
                let _ = child.kill();
                let _ = child.wait();
                return Err(match state {
                    Err(e) => format!("cannot observe child: {e}"),
                    _ if Instant::now() >= deadline => "case timed out".into(),
                    _ => "case log exceeded its limit or could not be observed".into(),
                });
            }
        }
    }
}

pub fn run_suite<W: Write>(cases: &[Case], reporter: &mut Reporter<W>) -> io::Result<bool> {
    reporter.begin(cases)?;
    let executable = std::env::current_exe()?;
    let mut passed = 0;
    for case in cases {
        reporter.start(case.id)?;
        let start = Instant::now();
        let result = isolated(&executable, case);
        if result.is_ok() {
            passed += 1;
        }
        reporter.result(
            case.id,
            result.is_ok(),
            result.as_ref().err().map(String::as_str).unwrap_or(""),
            start.elapsed(),
        )?;
        println!(
            "{} {}",
            if result.is_ok() { "PASS" } else { "FAIL" },
            case.id
        );
    }
    reporter.end(passed, cases.len() - passed)?;
    Ok(passed == cases.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_escapes_controls_and_keeps_unicode() {
        assert_eq!(quoted("あ\0\n\"\\"), "\"あ\\u0000\\n\\\"\\\\\"");
    }
    #[test]
    fn rejects_bad_run_ids_and_empty_or_duplicate_plans() {
        assert!(Reporter::new(Vec::new(), "bad").is_err());
        let mut report = Reporter::new(Vec::new(), &"ab".repeat(16)).unwrap();
        assert!(report.begin(&[]).is_err());
        let case = || Case {
            id: "same",
            timeout_seconds: 1,
            run: || Ok(()),
        };
        assert!(report.begin(&[case(), case()]).is_err());
        assert!(report.writer.is_empty());
    }
    #[test]
    fn propagates_writer_failure_instead_of_success() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("broken"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut report = Reporter::new(Broken, &"ab".repeat(16)).unwrap();
        assert!(report.end(1, 0).is_err());
    }
    #[test]
    fn unknown_and_failed_cases_have_nonzero_status() {
        let cases = [Case {
            id: "failure",
            timeout_seconds: 1,
            run: || Err("expected".into()),
        }];
        assert_eq!(run_case(&cases, "missing"), 2);
        assert_eq!(run_case(&cases, "failure"), 1);
    }

    #[cfg(all(unix, not(target_os = "mochios")))]
    #[test]
    fn isolated_children_capture_failure_and_terminate_at_the_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("mochios-test-fixture-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let program = path.join("child");
        std::fs::write(&program,b"#!/bin/sh\ncase \"$2\" in fail) echo failure-detail >&2; exit 3;; overflow) head -c 70000 /dev/zero; exit 0;; hang) exec sleep 10;; *) exit 0;; esac\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let case = |id| Case {
            id,
            timeout_seconds: 1,
            run: || Ok(()),
        };
        assert!(isolated(&program, &case("pass")).is_ok());
        assert!(
            isolated(&program, &case("overflow"))
                .unwrap_err()
                .contains("log exceeded")
        );
        assert!(
            isolated(&program, &case("fail"))
                .unwrap_err()
                .contains("failure-detail")
        );
        let start = Instant::now();
        assert_eq!(
            isolated(&program, &case("hang")).unwrap_err(),
            "case timed out"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        std::fs::remove_dir_all(path).unwrap();
    }
}
