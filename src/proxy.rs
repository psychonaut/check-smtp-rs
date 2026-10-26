//! HAProxy PROXY protocol v1 header.
//! <http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt>

use std::net::SocketAddr;

/// Builds `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n`, where the source
/// is our local address and the destination is the server (same as upstream).
pub fn v1_header(local: SocketAddr, remote: SocketAddr) -> Result<String, String> {
    // Normalise IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to plain IPv4.
    let (l, r) = (local.ip().to_canonical(), remote.ip().to_canonical());
    let proto = match (l.is_ipv4(), r.is_ipv4()) {
        (true, true) => "TCP4",
        (false, false) => "TCP6",
        _ => return Err("proxyproto: mixed IPv4/IPv6 endpoints".into()),
    };
    Ok(format!(
        "PROXY {proto} {l} {r} {} {}\r\n",
        local.port(),
        remote.port()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp4() {
        let h = v1_header("10.0.0.1:4000".parse().unwrap(), "10.0.0.2:25".parse().unwrap());
        assert_eq!(h.unwrap(), "PROXY TCP4 10.0.0.1 10.0.0.2 4000 25\r\n");
    }

    #[test]
    fn tcp6() {
        let h = v1_header("[::1]:4000".parse().unwrap(), "[::1]:25".parse().unwrap());
        assert_eq!(h.unwrap(), "PROXY TCP6 ::1 ::1 4000 25\r\n");
    }

    #[test]
    fn mapped_v4_is_canonicalised() {
        let h = v1_header(
            "[::ffff:10.0.0.1]:4000".parse().unwrap(),
            "[::ffff:10.0.0.2]:25".parse().unwrap(),
        );
        assert_eq!(h.unwrap(), "PROXY TCP4 10.0.0.1 10.0.0.2 4000 25\r\n");
    }
}
