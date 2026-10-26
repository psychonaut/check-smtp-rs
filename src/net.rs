//! TCP transport with a single absolute deadline for the whole session.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Anything the SMTP client can talk over (plain TCP or TLS-wrapped).
pub trait Stream: Read + Write {
    /// Best-effort graceful shutdown (e.g. TLS `close_notify`).
    fn close(&mut self) {}
}

impl<S: Stream + ?Sized> Stream for Box<S> {
    fn close(&mut self) {
        (**self).close()
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "operation timed out")
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(timed_out)
}

/// `TcpStream` whose every read/write is bounded by one absolute deadline,
/// mirroring Go's `conn.SetDeadline`.
pub struct DeadlineStream {
    sock: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.sock.peer_addr()
    }
}

fn map_timeout(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => timed_out(),
        _ => e,
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.set_read_timeout(Some(remaining(self.deadline)?))?;
        self.sock.read(buf).map_err(map_timeout)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.set_write_timeout(Some(remaining(self.deadline)?))?;
        self.sock.write(buf).map_err(map_timeout)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl Stream for DeadlineStream {}

/// Resolves `host` and connects to the first reachable address, splitting the
/// remaining time budget between the candidates.
pub fn connect(host: &str, port: u16, deadline: Instant) -> io::Result<DeadlineStream> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses found for {host}"),
        ));
    }

    let total = addrs.len();
    let mut last_err = timed_out();
    for (i, addr) in addrs.into_iter().enumerate() {
        let budget = remaining(deadline)? / (total - i) as u32;
        match TcpStream::connect_timeout(&addr, budget) {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                return Ok(DeadlineStream { sock, deadline });
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}
