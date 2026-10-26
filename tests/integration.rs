//! End-to-end tests: run the real binary against an in-process mock SMTP server.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use time::OffsetDateTime;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Plain,
    StartTls,
    Smtps,
}

#[derive(Clone)]
struct Opts {
    mode: Mode,
    proxy: bool,
    reject_rcpt: bool,
    silent: bool,
    bad_banner: bool,
    cert_valid_days: i64,
}

impl Opts {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            proxy: false,
            reject_rcpt: false,
            silent: false,
            bad_banner: false,
            cert_valid_days: 365,
        }
    }
}

struct Mock {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl Mock {
    /// Commands (and the PROXY line) the server received, after the client is done.
    fn finish(self) -> Vec<String> {
        self.handle.join().unwrap();
        self.log.lock().unwrap().clone()
    }
}

fn server_config(valid_days: i64) -> Arc<ServerConfig> {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "mock.test");
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(valid_days);
    let cert = params.self_signed(&key_pair).unwrap();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    )
}

/// Unbuffered line read so nothing is swallowed ahead of a TLS upgrade.
fn read_line(s: &mut impl Read) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b) {
            Ok(1) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    return Some(String::from_utf8_lossy(&line).trim_end().to_owned());
                }
            }
            _ => return None,
        }
    }
}

/// Runs one SMTP dialogue. Returns true if the client asked for (and we agreed
/// to) a STARTTLS upgrade.
fn converse<S: Read + Write>(
    s: &mut S,
    opts: &Opts,
    log: &Mutex<Vec<String>>,
    banner: bool,
    offer_starttls: bool,
) -> bool {
    if banner {
        let b = if opts.bad_banner { "554 no service\r\n" } else { "220 mock ESMTP\r\n" };
        s.write_all(b.as_bytes()).unwrap();
        s.flush().unwrap();
    }
    while let Some(line) = read_line(s) {
        log.lock().unwrap().push(line.clone());
        let upper = line.to_ascii_uppercase();
        let reply: &str = if upper.starts_with("EHLO") {
            if offer_starttls {
                "250-mock\r\n250-STARTTLS\r\n250 8BITMIME\r\n"
            } else {
                "250-mock\r\n250 8BITMIME\r\n"
            }
        } else if upper.starts_with("STARTTLS") {
            if offer_starttls {
                s.write_all(b"220 ready\r\n").unwrap();
                s.flush().unwrap();
                return true;
            }
            "502 not implemented\r\n"
        } else if upper.starts_with("MAIL FROM") {
            "250 ok\r\n"
        } else if upper.starts_with("RCPT TO") {
            if opts.reject_rcpt { "550 5.1.1 no such user\r\n" } else { "250 ok\r\n" }
        } else if upper.starts_with("QUIT") {
            s.write_all(b"221 bye\r\n").unwrap();
            let _ = s.flush();
            return false;
        } else {
            "500 what\r\n"
        };
        s.write_all(reply.as_bytes()).unwrap();
        s.flush().unwrap();
    }
    false
}

fn spawn(opts: Opts) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();

    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        if opts.silent {
            thread::sleep(Duration::from_secs(3));
            return;
        }
        if opts.proxy {
            let line = read_line(&mut tcp).unwrap_or_default();
            log2.lock().unwrap().push(line);
        }

        let cfg = server_config(opts.cert_valid_days);
        let tls = |tcp: TcpStream| StreamOwned::new(ServerConnection::new(cfg.clone()).unwrap(), tcp);

        match opts.mode {
            Mode::Smtps => {
                let mut s = tls(tcp);
                converse(&mut s, &opts, &log2, true, false);
            }
            Mode::Plain | Mode::StartTls => {
                let upgrade = converse(&mut tcp, &opts, &log2, true, opts.mode == Mode::StartTls);
                if upgrade {
                    let mut s = tls(tcp);
                    converse(&mut s, &opts, &log2, false, false);
                }
            }
        }
    });

    Mock { port, log, handle }
}

struct Out {
    code: i32,
    stdout: String,
}

fn run(args: &[&str]) -> Out {
    let o = Command::new(env!("CARGO_BIN_EXE_check-smtp"))
        .args(args)
        .output()
        .unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
    }
}

fn run_against(mock: &Mock, extra: &[&str]) -> Out {
    let port = mock.port.to_string();
    let mut args = vec!["-H", "127.0.0.1", "-p", &port, "-t", "5s"];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn plain_ok_with_mail_and_rcpt() {
    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["-f", "a@example.com", "-r", "b@example.org", "-F", "me.test"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.starts_with("SMTP OK: "), "{}", out.stdout);
    assert!(out.stdout.contains("response time"));
    assert_eq!(
        m.finish(),
        ["EHLO me.test", "MAIL FROM:<a@example.com>", "RCPT TO:<b@example.org>", "QUIT"]
    );
}

#[test]
fn starttls_ok_reports_tls_and_cert() {
    let m = spawn(Opts::new(Mode::StartTls));
    let out = run_against(
        &m,
        &["-S", "--minimum-tls-version", "1.2", "--cert-warn", "30", "--cert-crit", "7", "-r", "b@x.org"],
    );
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("TLS 1."), "{}", out.stdout);
    assert!(out.stdout.contains(">= 1.2"), "{}", out.stdout);
    assert!(out.stdout.contains("certificate 'mock.test' expires in 36"), "{}", out.stdout);
    // EHLO is repeated on the encrypted channel.
    assert_eq!(
        m.finish(),
        ["EHLO localhost", "STARTTLS", "EHLO localhost", "RCPT TO:<b@x.org>", "QUIT"]
    );
}

#[test]
fn smtps_ok_implicit_tls() {
    let m = spawn(Opts::new(Mode::Smtps));
    let out = run_against(&m, &["--smtps", "--minimum-tls-version", "1.3", "-f", "a@x.org"]);
    // rustls servers negotiate 1.3 by default.
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("TLS 1.3 >= 1.3"), "{}", out.stdout);
    assert_eq!(m.finish(), ["EHLO localhost", "MAIL FROM:<a@x.org>", "QUIT"]);
}

#[test]
fn ssl_alias_works() {
    let m = spawn(Opts::new(Mode::Smtps));
    let out = run_against(&m, &["--ssl"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    m.finish();
}

#[test]
fn proxy_protocol_header_is_sent_first() {
    let m = spawn(Opts { proxy: true, ..Opts::new(Mode::Plain) });
    let out = run_against(&m, &["-P"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    let log = m.finish();
    assert!(log[0].starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "), "{log:?}");
    assert!(log[0].ends_with(&format!(" {}", log_port(&log[0]))));
    assert_eq!(log[1], "EHLO localhost");
}

fn log_port(proxy_line: &str) -> &str {
    proxy_line.rsplit(' ').next().unwrap()
}

#[test]
fn proxy_protocol_before_implicit_tls() {
    let m = spawn(Opts { proxy: true, ..Opts::new(Mode::Smtps) });
    let out = run_against(&m, &["-P", "--smtps"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    let log = m.finish();
    assert!(log[0].starts_with("PROXY TCP4 "), "{log:?}");
}

#[test]
fn rejected_rcpt_is_critical() {
    let m = spawn(Opts { reject_rcpt: true, ..Opts::new(Mode::Plain) });
    let out = run_against(&m, &["-r", "nobody@example.org"]);
    assert_eq!(out.code, 2);
    assert_eq!(
        out.stdout.trim(),
        "SMTP CRITICAL: RCPT command was not accepted: 550 5.1.1 no such user"
    );
    m.finish();
}

#[test]
fn bad_banner_is_critical() {
    let m = spawn(Opts { bad_banner: true, ..Opts::new(Mode::Plain) });
    let out = run_against(&m, &[]);
    assert_eq!(out.code, 2);
    assert!(out.stdout.contains("failed to connect to SMTP server: 554"), "{}", out.stdout);
    m.finish();
}

#[test]
fn starttls_unsupported_is_critical() {
    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["-S"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stdout.contains("failed to establish TLS connection: 502"),
        "{}",
        out.stdout
    );
    m.finish();
}

#[test]
fn smtps_against_plain_server_is_critical() {
    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["--smtps"]);
    assert_eq!(out.code, 2);
    assert!(out.stdout.contains("failed to establish TLS connection"), "{}", out.stdout);
    let _ = m.handle.join();
}

#[test]
fn cert_expiring_soon_warns_then_crits() {
    let m = spawn(Opts { cert_valid_days: 20, ..Opts::new(Mode::StartTls) });
    let out = run_against(&m, &["-S", "--cert-warn", "30", "--cert-crit", "7"]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.starts_with("SMTP WARNING: certificate 'mock.test'"), "{}", out.stdout);
    m.finish();

    let m = spawn(Opts { cert_valid_days: 5, ..Opts::new(Mode::Smtps) });
    let out = run_against(&m, &["--smtps", "--cert-warn", "30", "--cert-crit", "7"]);
    assert_eq!(out.code, 2, "{}", out.stdout);
    assert!(out.stdout.starts_with("SMTP CRITICAL: certificate 'mock.test'"), "{}", out.stdout);
    m.finish();
}

#[test]
fn verify_rejects_self_signed() {
    let m = spawn(Opts::new(Mode::StartTls));
    let out = run_against(&m, &["-S", "--verify", "--tls-server-name", "localhost"]);
    assert_eq!(out.code, 2, "{}", out.stdout);
    assert!(out.stdout.contains("TLS") || out.stdout.contains("certificate"), "{}", out.stdout);
    let _ = m.handle.join();
}

#[test]
fn response_time_thresholds() {
    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["-w", "1us"]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stdout.starts_with("SMTP WARNING: "), "{}", out.stdout);
    m.finish();

    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["-w", "1us", "-c", "1us"]);
    assert_eq!(out.code, 2, "{}", out.stdout);
    m.finish();

    // Plain seconds are accepted, Nagios-style; a generous limit stays OK.
    let m = spawn(Opts::new(Mode::Plain));
    let out = run_against(&m, &["-w", "2.0", "-c", "4"]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    m.finish();
}

#[test]
fn silent_server_times_out() {
    let m = spawn(Opts { silent: true, ..Opts::new(Mode::Plain) });
    let port = m.port.to_string();
    let started = std::time::Instant::now();
    let out = run(&["-H", "127.0.0.1", "-p", &port, "-t", "500ms"]);
    assert_eq!(out.code, 2, "{}", out.stdout);
    assert!(out.stdout.contains("timed out"), "{}", out.stdout);
    assert!(started.elapsed() < Duration::from_secs(3));
    let _ = m.handle.join();
}

#[test]
fn connection_refused_is_critical() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let out = run(&["-H", "127.0.0.1", "-p", &port.to_string(), "-t", "2s"]);
    assert_eq!(out.code, 2);
    assert!(out.stdout.starts_with("SMTP CRITICAL: failed to connect to SMTP server"), "{}", out.stdout);
}

#[test]
fn usage_errors_are_unknown() {
    for args in [
        &["-H", "x", "-S", "--smtps"][..],
        &["-H", "x", "--verify"][..],
        &["-H", "x", "--cert-warn", "5"][..],
        &["-H", "x", "--minimum-tls-version", "1.2"][..],
        &["-H", "x", "--minimum-tls-version", "9.9", "-S"][..],
        &["-p", "25"][..], // missing --hostname
    ] {
        let out = run(args);
        assert_eq!(out.code, 3, "args: {args:?}");
    }
}

#[test]
fn help_exits_zero() {
    assert_eq!(run(&["--help"]).code, 0);
}
