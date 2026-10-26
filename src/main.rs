//! check-smtp: a Nagios-compatible SMTP check (drop-in for `go-check-smtp`
//! and `check_smtp`) with STARTTLS and implicit-TLS (SMTPS) support.

mod nagios;
mod net;
mod proxy;
mod smtp;
mod tls;

use std::io::Write;
use std::process::exit;
use std::time::{Duration, Instant};

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use nagios::{Check, Status};
use net::Stream;
use tls::{Connector, TlsInfo, TlsVersion};

#[derive(Parser, Debug)]
#[command(
    name = "check-smtp",
    version,
    about = "Nagios-compatible SMTP check with STARTTLS, SMTPS and PROXY protocol support"
)]
struct Cli {
    /// FQDN for EHLO/HELO
    #[arg(short = 'F', long, default_value = "localhost")]
    fqdn: String,

    /// Host name or address to check
    #[arg(short = 'H', long = "hostname")]
    hostname: String,

    /// Port number [default: 25, or 465 with --smtps]
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Envelope sender; issues MAIL FROM when set
    #[arg(short = 'f', long = "from")]
    from: Option<String>,

    /// Envelope recipient; issues RCPT TO when set
    #[arg(short = 'r', long = "recipient")]
    recipient: Option<String>,

    /// Response time that results in WARNING (e.g. 2, 1.5, 500ms, 2s)
    #[arg(short = 'w', long, value_parser = parse_duration)]
    warning: Option<Duration>,

    /// Response time that results in CRITICAL (e.g. 2, 1.5, 500ms, 2s)
    #[arg(short = 'c', long, value_parser = parse_duration)]
    critical: Option<Duration>,

    /// WARNING when a certificate expires within this many days
    #[arg(long, default_value_t = 0)]
    cert_warn: u32,

    /// CRITICAL when a certificate expires within this many days
    #[arg(long, default_value_t = 0)]
    cert_crit: u32,

    /// Send a PROXY protocol v1 header before anything else
    #[arg(short = 'P', long = "proxyproto")]
    proxyproto: bool,

    /// Upgrade the connection with STARTTLS
    #[arg(short = 'S', long, conflicts_with = "smtps")]
    starttls: bool,

    /// Speak SMTP over TLS from the first byte (implicit TLS, usually port 465)
    #[arg(long, visible_alias = "ssl")]
    smtps: bool,

    /// WARNING when the negotiated TLS version is lower than this
    #[arg(long, value_enum)]
    minimum_tls_version: Option<TlsVersion>,

    /// Validate the server certificate chain and name against the system
    /// trust store (by default any certificate is accepted)
    #[arg(long)]
    verify: bool,

    /// Name used for TLS SNI and --verify [default: the --hostname value]
    #[arg(long)]
    tls_server_name: Option<String>,

    /// Overall timeout for connect + session (e.g. 10, 2.5, 500ms, 10s)
    #[arg(short = 't', long, default_value = "10s", value_parser = parse_duration)]
    timeout: Duration,

    /// Verbose diagnostics (SMTP transcript and TLS details) on stderr
    #[arg(short = 'v', long)]
    verbose: bool,
}

impl Cli {
    fn tls_enabled(&self) -> bool {
        self.starttls || self.smtps
    }

    /// Options that only make sense with a TLS mode are rejected up front
    /// instead of being silently ignored.
    fn validate(&self) -> Result<(), String> {
        if self.tls_enabled() {
            return Ok(());
        }
        let stray = [
            ("--minimum-tls-version", self.minimum_tls_version.is_some()),
            ("--cert-warn", self.cert_warn > 0),
            ("--cert-crit", self.cert_crit > 0),
            ("--verify", self.verify),
            ("--tls-server-name", self.tls_server_name.is_some()),
        ];
        match stray.iter().find(|(_, set)| *set) {
            Some((flag, _)) => Err(format!("{flag} requires --starttls or --smtps")),
            None => Ok(()),
        }
    }
}

/// Accepts plain seconds (`2`, `1.5`, as Nagios plugins do) or humantime
/// syntax (`500ms`, `2s`, `1m`).
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<f64>() {
        return Duration::try_from_secs_f64(secs).map_err(|e| e.to_string());
    }
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        let _ = e.print();
        // Nagios: usage errors are UNKNOWN (3); --help/--version are 0.
        exit(if e.use_stderr() { 3 } else { 0 });
    });
    if let Err(msg) = cli.validate() {
        let _ = Cli::command().error(ErrorKind::ArgumentConflict, msg).print();
        exit(3);
    }

    let mut check = Check::new("SMTP");
    if let Err(msg) = run(&cli, &mut check) {
        check.add(Status::Critical, msg);
    }
    check.finish();
}

/// Runs the whole check. `Err` carries the CRITICAL message of a fatal failure.
fn run(cli: &Cli, check: &mut Check) -> Result<(), String> {
    let start = Instant::now();
    let deadline = start + cli.timeout;
    let port = cli.port.unwrap_or(if cli.smtps { 465 } else { 25 });

    let connector = if cli.tls_enabled() {
        let name = cli.tls_server_name.as_deref().unwrap_or(&cli.hostname);
        Some(Connector::new(cli.verify, name)?)
    } else {
        None
    };

    let mut sock = net::connect(&cli.hostname, port, deadline)
        .map_err(|e| format!("failed to connect to SMTP server: {e}"))?;

    if cli.verbose {
        eprintln!("{:?} {:?}", sock.local_addr(), sock.peer_addr());
    }

    if cli.proxyproto {
        let io_err = |e| format!("failed to send PROXY header: {e}");
        let local = sock.local_addr().map_err(io_err)?;
        let remote = sock.peer_addr().map_err(io_err)?;
        let header = proxy::v1_header(local, remote)?;
        if cli.verbose {
            eprint!("ProxyConn: {header}");
        }
        sock.write_all(header.as_bytes()).map_err(io_err)?;
    }

    fn tls_err(e: impl std::fmt::Display) -> String {
        format!("failed to establish TLS connection: {e}")
    }
    let mut tls_info: Option<TlsInfo> = None;

    let stream: Box<dyn Stream> = match (&connector, cli.smtps) {
        (Some(c), true) => {
            let (s, info) = c.handshake(sock).map_err(tls_err)?;
            tls_info = Some(info);
            Box::new(s)
        }
        _ => Box::new(sock),
    };

    let mut client = smtp::Client::new(stream, cli.verbose)
        .map_err(|e| format!("failed to connect to SMTP server: {e}"))?;

    client
        .hello(&cli.fqdn)
        .map_err(|e| format!("failed to say hello: {e}"))?;

    if let (Some(c), true) = (&connector, cli.starttls) {
        client = client
            .starttls(|raw| {
                let (s, info) = c.handshake(raw)?;
                tls_info = Some(info);
                Ok(Box::new(s))
            })
            .map_err(tls_err)?;
    }

    // Response time includes connect, TLS negotiation and the greeting.
    let elapsed = start.elapsed();
    let elapsed = Duration::from_micros(elapsed.as_micros().try_into().unwrap_or(u64::MAX));
    let slower_than = |limit: Option<Duration>| limit.is_some_and(|l| !l.is_zero() && elapsed > l);
    if slower_than(cli.warning) {
        check.add(Status::Warning, format!("{elapsed:?} response time"));
    }
    if slower_than(cli.critical) {
        check.add(Status::Critical, format!("{elapsed:?} response time"));
    }
    check.add(Status::Ok, format!("{elapsed:?} response time"));

    if let Some(from) = cli.from.as_deref().filter(|s| !s.is_empty()) {
        client
            .mail(from)
            .map_err(|e| format!("MAIL command was not accepted: {e}"))?;
    }
    if let Some(to) = cli.recipient.as_deref().filter(|s| !s.is_empty()) {
        client
            .rcpt(to)
            .map_err(|e| format!("RCPT command was not accepted: {e}"))?;
    }

    client.quit();

    if let Some(info) = &tls_info {
        check_tls(cli, check, info);
    }
    Ok(())
}

fn check_tls(cli: &Cli, check: &mut Check, info: &TlsInfo) {
    if let Some(min) = cli.minimum_tls_version {
        let ok = info.version.is_some_and(|v| v >= min);
        let msg = format!(
            "{} {} {} ({})",
            info.version_name(),
            if ok { ">=" } else { "<" },
            min.short(),
            info.cipher
        );
        if cli.verbose {
            eprintln!("{msg}");
        }
        check.add(if ok { Status::Ok } else { Status::Warning }, msg);
    }

    if cli.cert_warn > 0 || cli.cert_crit > 0 {
        check_certs(cli, check, info);
    }
}

fn check_certs(cli: &Cli, check: &mut Check, info: &TlsInfo) {
    if info.certs.is_empty() {
        check.add(Status::Warning, "server presented no certificate");
        return;
    }

    let now = OffsetDateTime::now_utc();
    for der in &info.certs {
        let cert = match x509_parser::parse_x509_certificate(der.as_ref()) {
            Ok((_, cert)) => cert,
            Err(e) => {
                check.add(Status::Warning, format!("failed to parse certificate: {e}"));
                continue;
            }
        };

        let subject = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map_or_else(|| cert.subject().to_string(), str::to_owned);
        let not_after = cert.validity().not_after.to_datetime();
        let days = (not_after - now).whole_days();
        let date = not_after.format(&Rfc3339).unwrap_or_else(|_| not_after.to_string());

        check.add(
            tls::cert_status(not_after, now, cli.cert_warn, cli.cert_crit),
            format!("certificate '{subject}' expires in {days} day(s) ({date})"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert!(parse_duration("-1").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}
