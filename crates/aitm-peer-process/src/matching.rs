//! The socket match rule (spec D4): a scanned TCP socket `(laddr, lport, faddr,
//! fport)` owns a wanted [`Tuple`] when its local end is the client and its
//! foreign end is the proxy, after IPv4-mapped IPv6 addresses are folded to IPv4.

use std::net::IpAddr;

use crate::types::Tuple;

// Consumed by the macOS and Linux scanners; on any other OS `ProcessResolver`
// is the `NoScanner` stub and nothing calls these outside the tests.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4; leave
/// everything else alone, so `127.0.0.1` and `::ffff:127.0.0.1` compare equal.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
/// `true` when the scanned socket's local end is `wanted.client` and its foreign
/// end is `wanted.proxy`, comparing ports exactly and addresses canonically.
pub(crate) fn tuple_matches(
    laddr: IpAddr,
    lport: u16,
    faddr: IpAddr,
    fport: u16,
    wanted: &Tuple,
) -> bool {
    lport == wanted.client.port()
        && fport == wanted.proxy.port()
        && canonical(laddr) == canonical(wanted.client.ip())
        && canonical(faddr) == canonical(wanted.proxy.ip())
}

// libproc only: on Linux the ports come from `/proc/net/tcp` in host order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// Decode a libproc `insi_lport` / `insi_fport`: the kernel stores the 16-bit
/// network-order port in the low half of an `int`.
pub(crate) fn port_from_libproc(raw: i32) -> u16 {
    u16::from_be((raw as u32 & 0xFFFF) as u16)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{canonical, port_from_libproc, tuple_matches};
    use crate::types::Tuple;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn wanted() -> Tuple {
        Tuple {
            client: "127.0.0.1:49864".parse::<SocketAddr>().unwrap(),
            proxy: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        }
    }

    #[test]
    fn canonical_folds_mapped_v4_and_leaves_the_rest() {
        assert_eq!(canonical(v6("::ffff:127.0.0.1")), v4("127.0.0.1"));
        assert_eq!(canonical(v4("10.0.0.1")), v4("10.0.0.1"));
        assert_eq!(canonical(v6("::1")), v6("::1"));
        assert_eq!(canonical(v6("2001:db8::1")), v6("2001:db8::1"));
    }

    #[test]
    fn mapped_v4_local_address_matches_a_v4_client() {
        assert!(tuple_matches(
            v6("::ffff:127.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8080,
            &wanted()
        ));
    }

    #[test]
    fn plain_v4_matches_itself() {
        assert!(tuple_matches(
            v4("127.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8080,
            &wanted()
        ));
    }

    #[test]
    fn a_different_local_port_does_not_match() {
        assert!(!tuple_matches(
            v4("127.0.0.1"),
            49865,
            v4("127.0.0.1"),
            8080,
            &wanted()
        ));
    }

    #[test]
    fn a_different_foreign_port_does_not_match() {
        assert!(!tuple_matches(
            v4("127.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8081,
            &wanted()
        ));
    }

    #[test]
    fn a_different_local_address_does_not_match() {
        assert!(!tuple_matches(
            v4("10.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8080,
            &wanted()
        ));
    }

    #[test]
    fn the_reversed_direction_does_not_match() {
        // The proxy's own accepted socket has local = proxy, foreign = client.
        assert!(!tuple_matches(
            v4("127.0.0.1"),
            8080,
            v4("127.0.0.1"),
            49864,
            &wanted()
        ));
    }

    #[test]
    fn libproc_port_is_network_order_in_the_low_half() {
        assert_eq!(port_from_libproc(0x406f), 28480);
        assert_eq!(port_from_libproc(0x1F90), 36895); // 8080 stored as 0x901F on the wire
        assert_eq!(port_from_libproc(0x901F), 8080);
        assert_eq!(port_from_libproc(0x7FFF_0050), 20480); // high half is ignored
    }

    /// `insi_lport` is a C `int`; garbage in the high half (including the sign
    /// bit) must never reach the port.
    #[test]
    fn libproc_port_ignores_the_high_half_even_with_the_sign_bit_set() {
        assert_eq!(port_from_libproc(-1), 0xFFFF);
        assert_eq!(port_from_libproc(i32::MIN | 0x901F), 8080);
        assert_eq!(port_from_libproc(0), 0);
    }

    /// `::1` is not `127.0.0.1`: only the IPv4-mapped form folds (spec D4).
    #[test]
    fn a_v6_loopback_client_is_not_folded_onto_v4() {
        let wanted = Tuple {
            client: "[::1]:49864".parse::<SocketAddr>().unwrap(),
            proxy: "[::1]:8080".parse::<SocketAddr>().unwrap(),
        };
        assert!(tuple_matches(v6("::1"), 49864, v6("::1"), 8080, &wanted));
        assert!(!tuple_matches(
            v4("127.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8080,
            &wanted
        ));
        assert!(!tuple_matches(
            v6("::ffff:127.0.0.1"),
            49864,
            v6("::ffff:127.0.0.1"),
            8080,
            &wanted
        ));
    }

    /// A dual-stack listener hands the core a mapped peer; the client's own
    /// socket may be plain v4. Canonicalisation applies to the wanted side too.
    #[test]
    fn a_mapped_v4_wanted_tuple_matches_a_plain_v4_socket() {
        let wanted = Tuple {
            client: "[::ffff:127.0.0.1]:49864".parse::<SocketAddr>().unwrap(),
            proxy: "[::ffff:127.0.0.1]:8080".parse::<SocketAddr>().unwrap(),
        };
        assert!(tuple_matches(
            v4("127.0.0.1"),
            49864,
            v4("127.0.0.1"),
            8080,
            &wanted
        ));
    }
}
