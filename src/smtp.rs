//! Tiny blocking SMTP client: just enough of RFC 5321 for a health check.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

use crate::net::Stream;

const MAX_LINE: u64 = 8 * 1024;
const MAX_REPLY_LINES: usize = 256;

#[derive(Debug, Clone)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {}", self.code, self.lines.join(" "))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The peer sent something that is not valid SMTP.
    Protocol(String),
    /// A well-formed reply with an unexpected code (e.g. 550 to RCPT).
    Reply(Reply),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Protocol(m) => f.write_str(m),
            Error::Reply(r) => write!(f, "{r}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    io: BufReader<Box<dyn Stream>>,
    verbose: bool,
    fqdn: String,
}

impl Client {
    /// Wraps an established stream and consumes the `220` greeting.
    pub fn new(stream: Box<dyn Stream>, verbose: bool) -> Result<Self> {
        let mut c = Self {
            io: BufReader::new(stream),
            verbose,
            fqdn: String::new(),
        };
        let greeting = c.read_reply()?;
        c.expect(greeting, |code| code == 220)?;
        Ok(c)
    }

    /// `EHLO`, falling back to `HELO` if the server rejects it.
    pub fn hello(&mut self, fqdn: &str) -> Result<()> {
        check_param(fqdn)?;
        self.fqdn = fqdn.to_owned();
        let reply = self.cmd(&format!("EHLO {fqdn}"))?;
        if reply.code == 250 {
            return Ok(());
        }
        let reply = self.cmd(&format!("HELO {fqdn}"))?;
        self.expect(reply, |code| code == 250)
    }

    /// Issues `STARTTLS`, lets `upgrade` perform the TLS handshake over the raw
    /// stream, then repeats the greeting on the encrypted channel (RFC 3207).
    pub fn starttls<F>(mut self, upgrade: F) -> Result<Self>
    where
        F: FnOnce(Box<dyn Stream>) -> io::Result<Box<dyn Stream>>,
    {
        let reply = self.cmd("STARTTLS")?;
        self.expect(reply, |code| code == 220)?;

        // Anything already buffered was sent in plaintext before the handshake;
        // accepting it would enable STARTTLS response injection (CVE-2011-0411).
        if !self.io.buffer().is_empty() {
            return Err(Error::Protocol(
                "server sent data before the TLS handshake".into(),
            ));
        }

        let Self { io, verbose, fqdn } = self;
        let stream = upgrade(io.into_inner())?;
        let mut c = Self {
            io: BufReader::new(stream),
            verbose,
            fqdn,
        };
        let fqdn = c.fqdn.clone();
        c.hello(&fqdn)?;
        Ok(c)
    }

    pub fn mail(&mut self, from: &str) -> Result<()> {
        check_param(from)?;
        let reply = self.cmd(&format!("MAIL FROM:<{from}>"))?;
        self.expect(reply, |code| code == 250)
    }

    pub fn rcpt(&mut self, to: &str) -> Result<()> {
        check_param(to)?;
        let reply = self.cmd(&format!("RCPT TO:<{to}>"))?;
        self.expect(reply, |code| (250..=251).contains(&code))
    }

    /// Best-effort `QUIT`; the check outcome never depends on it.
    pub fn quit(mut self) {
        let _ = self.cmd("QUIT");
        self.io.get_mut().close();
    }

    fn expect(&self, reply: Reply, ok: impl Fn(u16) -> bool) -> Result<()> {
        if ok(reply.code) {
            Ok(())
        } else {
            Err(Error::Reply(reply))
        }
    }

    fn cmd(&mut self, line: &str) -> Result<Reply> {
        if self.verbose {
            eprintln!("C: {line}");
        }
        let w = self.io.get_mut();
        w.write_all(line.as_bytes())?;
        w.write_all(b"\r\n")?;
        w.flush()?;
        self.read_reply()
    }

    fn read_line(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        let n = (&mut self.io).take(MAX_LINE).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed by server").into());
        }
        if buf.last() != Some(&b'\n') {
            return Err(Error::Protocol("reply line too long or truncated".into()));
        }
        let line = String::from_utf8_lossy(&buf);
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn read_reply(&mut self) -> Result<Reply> {
        let mut code = 0u16;
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            if self.verbose {
                eprintln!("S: {line}");
            }
            let b = line.as_bytes();
            let malformed = || Error::Protocol(format!("malformed reply: {line:?}"));

            if b.len() < 3 || !b[..3].iter().all(u8::is_ascii_digit) {
                return Err(malformed());
            }
            let sep = b.get(3).copied();
            if !matches!(sep, None | Some(b' ') | Some(b'-')) {
                return Err(malformed());
            }
            let this: u16 = line[..3].parse().map_err(|_| malformed())?;
            if lines.is_empty() {
                code = this;
            } else if this != code {
                return Err(Error::Protocol(format!(
                    "inconsistent multi-line reply: {line:?}"
                )));
            }
            lines.push(line.get(4..).unwrap_or("").to_owned());

            if sep != Some(b'-') {
                return Ok(Reply { code, lines });
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err(Error::Protocol("reply has too many lines".into()));
            }
        }
    }
}

/// Rejects CR/LF so arguments can never smuggle extra SMTP commands.
fn check_param(s: &str) -> Result<()> {
    if s.contains(['\r', '\n']) {
        Err(Error::Protocol(
            "argument must not contain line breaks".into(),
        ))
    } else {
        Ok(())
    }
}
