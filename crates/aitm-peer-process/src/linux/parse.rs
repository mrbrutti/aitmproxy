//! Parsers for the `/proc` text the Linux scanner reads. Pure functions over
//! `&str`; every malformed input is `None`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// Linux-only in production: the consumer, `linux::scan`, is built on other hosts
// only under `cfg(test)`, so there these are reachable from the tests alone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// One row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Parse one data row of `/proc/net/tcp` (`v6 == false`, 8 hex chars per address)
/// or `/proc/net/tcp6` (`v6 == true`, 32 hex chars as four native-endian `u32`
/// words). Ports are host-order hex. The header line and anything short or
/// non-hex is `None`.
pub(crate) fn parse_tcp_row(line: &str, v6: bool) -> Option<TcpRow> {
    let mut fields = line.split_ascii_whitespace();
    let _sl = fields.next()?;
    let local = parse_hex_endpoint(fields.next()?, v6)?;
    let remote = parse_hex_endpoint(fields.next()?, v6)?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    let _tx_rx_queue = fields.next()?;
    let _tr_when = fields.next()?;
    let _retrnsmt = fields.next()?;
    let uid = fields.next()?.parse::<u32>().ok()?;
    let _timeout = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    Some(TcpRow {
        local,
        remote,
        state,
        uid,
        inode,
    })
}

/// `ADDR:PORT` where `ADDR` is 8 (v4) or 32 (v6) hex chars of native-endian
/// `u32` words and `PORT` is 4 hex chars in host order.
fn parse_hex_endpoint(word: &str, v6: bool) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = word.split_once(':')?;
    if port_hex.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for (i, chunk) in octets.chunks_exact_mut(4).enumerate() {
            let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(addr_hex, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Field 22 (`starttime`) of `/proc/<pid>/stat`. The second field, `comm`, is in
/// parentheses and may contain spaces or parentheses itself, so fields are counted
/// from the **last** `)`.
pub(crate) fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let (_, after_comm) = stat.rsplit_once(')')?;
    // `after_comm` starts at field 3 (`state`); starttime is field 22, so it is
    // the 20th whitespace-separated word here (index 19).
    after_comm
        .split_ascii_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The executable basename from a `/proc/<pid>/exe` link target, with the
/// ` (deleted)` suffix the kernel appends to an unlinked binary stripped.
pub(crate) fn exe_basename(link: &str) -> Option<String> {
    let path = link.strip_suffix(" (deleted)").unwrap_or(link);
    let base = path.rsplit('/').next()?;
    if base.is_empty() {
        return None;
    }
    Some(base.to_string())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// The inode `N` of a `/proc/<pid>/fd/<n>` link target of the form `socket:[N]`;
/// `None` for anything else (a file path, a pipe, an anon inode).
pub(crate) fn fd_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse::<u64>()
        .ok()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{exe_basename, fd_socket_inode, parse_stat_starttime, parse_tcp_row, TcpRow};

    const V4_ROW: &str = "   0: 0100007F:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_a_loopback_v4_row() {
        assert_eq!(
            parse_tcp_row(V4_ROW, false),
            Some(TcpRow {
                local: sa("127.0.0.1:49864"),
                remote: sa("127.0.0.1:8080"),
                state: 1,
                uid: 1000,
                inode: 12345,
            })
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_a_v6_loopback_row() {
        let row = "   1: 00000000000000000000000001000000:C2C8 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000   501        0 777 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(
            parse_tcp_row(row, true),
            Some(TcpRow {
                local: sa("[::1]:49864"),
                remote: sa("[::1]:8080"),
                state: 1,
                uid: 501,
                inode: 777,
            })
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn parses_a_v4_mapped_v6_row() {
        let row = "   2: 0000000000000000FFFF00000100007F:C2C8 0000000000000000FFFF00000100007F:1F90 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(
            parse_tcp_row(row, true),
            Some(TcpRow {
                local: sa("[::ffff:127.0.0.1]:49864"),
                remote: sa("[::ffff:127.0.0.1]:8080"),
                state: 0x0A,
                uid: 1000,
                inode: 4242,
            })
        );
    }

    #[test]
    fn the_header_line_is_none() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        assert_eq!(parse_tcp_row(header, false), None);
    }

    #[test]
    fn a_short_row_is_none() {
        assert_eq!(
            parse_tcp_row("   0: 0100007F:C2C8 0100007F:1F90 01", false),
            None
        );
        assert_eq!(parse_tcp_row("", false), None);
    }

    #[test]
    fn a_non_hex_row_is_none() {
        let bad = "   0: 0100007G:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(parse_tcp_row(bad, false), None);
    }

    #[test]
    fn a_v4_address_in_a_v6_table_is_none() {
        // 8 hex chars where 32 are required: wrong width, not a guess.
        assert_eq!(parse_tcp_row(V4_ROW, true), None);
    }

    #[test]
    fn starttime_is_field_22_after_the_last_paren() {
        assert_eq!(
            parse_stat_starttime(
                "1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 98765 1000 2"
            ),
            Some(98765)
        );
    }

    #[test]
    fn starttime_survives_parens_inside_comm() {
        assert_eq!(
            parse_stat_starttime(
                "77 (a) b) c) R 1 77 77 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 555 1000 2 3 4"
            ),
            Some(555)
        );
    }

    #[test]
    fn starttime_of_a_truncated_stat_is_none() {
        assert_eq!(
            parse_stat_starttime("1234 (my proc) S 1 1234 1234 0 -1"),
            None
        );
        assert_eq!(parse_stat_starttime("no parens here"), None);
        assert_eq!(parse_stat_starttime(""), None);
    }

    #[test]
    fn exe_basename_strips_the_directory_and_the_deleted_marker() {
        assert_eq!(exe_basename("/usr/bin/curl"), Some("curl".to_string()));
        assert_eq!(
            exe_basename("/usr/bin/curl (deleted)"),
            Some("curl".to_string())
        );
    }

    #[test]
    fn exe_basename_of_nothing_is_none() {
        assert_eq!(exe_basename(""), None);
        assert_eq!(exe_basename("/"), None);
    }

    #[test]
    fn fd_socket_inode_reads_the_socket_form_only() {
        assert_eq!(fd_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(fd_socket_inode("/dev/null"), None);
        assert_eq!(fd_socket_inode("pipe:[999]"), None);
        assert_eq!(fd_socket_inode("socket:[abc]"), None);
        assert_eq!(fd_socket_inode("socket:[12345"), None);
    }

    #[test]
    fn a_port_of_the_wrong_width_is_none() {
        let three = "   0: 0100007F:C2C 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1";
        let five = "   0: 0100007F:C2C80 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(parse_tcp_row(three, false), None);
        assert_eq!(parse_tcp_row(five, false), None);
    }

    #[test]
    fn non_numeric_uid_or_inode_is_none() {
        let bad_uid = "   0: 0100007F:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  abcd        0 12345 1 0000000000000000 20 4 30 10 -1";
        let bad_inode = "   0: 0100007F:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 -1 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(parse_tcp_row(bad_uid, false), None);
        assert_eq!(parse_tcp_row(bad_inode, false), None);
    }

    #[test]
    fn a_v6_address_in_a_v4_table_is_none() {
        let row = "   1: 00000000000000000000000001000000:C2C8 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000   501        0 777 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(parse_tcp_row(row, false), None);
    }

    #[test]
    fn starttime_that_is_not_a_number_is_none() {
        assert_eq!(
            parse_stat_starttime(
                "1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 abc 1000 2"
            ),
            None
        );
    }

    #[test]
    fn exe_basename_without_a_directory_is_the_name_itself() {
        assert_eq!(exe_basename("curl"), Some("curl".to_string()));
        assert_eq!(exe_basename(" (deleted)"), None);
        assert_eq!(exe_basename("/usr/bin/ (deleted)"), None);
    }
}
