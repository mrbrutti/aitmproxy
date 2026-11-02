//! The audited libproc calls, behind safe wrappers (spec D2, D4; plan Task 3).
//!
//! This is the **only** module in the workspace that may use `unsafe`: the crate
//! restates `unsafe_code = "deny"` and this file lifts it with the module-level
//! `allow` below. Every `unsafe` block states its invariant in a `// SAFETY:`
//! comment and the Security reviewer signs each one off.
//!
//! The `#[repr(C)]` mirrors below copy the layouts of `sys/proc_info.h` from the
//! macOS SDK on this Mac (`$(xcrun --show-sdk-path)/usr/include/sys/proc_info.h`,
//! measured in research 24 §3.1, corrected 2026-11-01: `soi_kind` / `soi_proto`
//! sit at 232 / 240 *inside `socket_info`*, i.e. 256 / 264 inside
//! `socket_fdinfo`). `tests::socket_fdinfo_layout_matches_the_sdk` pins the
//! mirrors to the offsets measured from the SDK on 2026-11-01 with a C
//! `offsetof` probe (spec AC8): it catches a drift of the *Rust* mirrors, not a
//! change in the header itself, which only re-running the probe would show.
//!
//! Every wrapper is **fail-closed**: a short read, an unexpected `soi_kind`, an
//! unknown address family, `EPERM`, `ESRCH`, `EBADF`, `ENOTSOCK` or any other
//! error is `None` / an empty collection, never a guess.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::matching::{port_from_libproc, tuple_matches};
use crate::types::{Probe, ProcessKey, Tuple};

// ---------------------------------------------------------------------------
// Constants (`sys/proc_info.h`, SDK on this Mac; values pinned in research 24).
// ---------------------------------------------------------------------------

/// `proc_listpids` selector: every pid on the system (line 51 of the header).
const PROC_ALL_PIDS: u32 = 1;
/// `proc_pidinfo` flavour: the open-file table as `proc_fdinfo` entries.
const PROC_PIDLISTFDS: i32 = 1;
/// `proc_pidinfo` flavour: `proc_bsdinfo` (uid, start time, ...).
const PROC_PIDTBSDINFO: i32 = 3;
/// `proc_pidfdinfo` flavour: `socket_fdinfo` for a socket descriptor.
const PROC_PIDFDSOCKETINFO: i32 = 3;
/// `proc_fdinfo.proc_fdtype` of a socket; the only type ever passed on to
/// `proc_pidfdinfo` (spec D4: never vnodes).
const PROX_FDTYPE_SOCKET: u32 = 2;
/// `socket_info.soi_kind` when `soi_proto` holds a `tcp_sockinfo`.
const SOCKINFO_TCP: i32 = 2;
/// `in_sockinfo.insi_vflag` bit: the address unions hold `in4in6_addr`.
const INI_IPV4: u8 = 0x1;
/// `in_sockinfo.insi_vflag` bit: the address unions hold `in6_addr`.
const INI_IPV6: u8 = 0x2;
/// `PROC_PIDPATHINFO_MAXSIZE` = `4 * MAXPATHLEN`: the buffer `proc_pidpath` wants.
const PID_PATH_BUF: usize = 4096;
/// `proc_name` writes at most `2 * MAXCOMLEN` bytes; 256 is generous.
const PID_NAME_BUF: usize = 256;

// ---------------------------------------------------------------------------
// `#[repr(C)]` mirrors. Names as in the header; fields we never read are blobs.
// ---------------------------------------------------------------------------

/// One entry of the `PROC_PIDLISTFDS` table (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
struct proc_fdinfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

/// `struct in_sockinfo` (80 bytes). The two address fields are the raw 16-byte
/// unions; [`decode_addr`] reads them by `insi_vflag`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
struct in_sockinfo {
    pub insi_fport: i32,
    pub insi_lport: i32,
    pub insi_gencnt: u64,
    pub insi_flags: u32,
    pub insi_flow: u32,
    pub insi_vflag: u8,
    pub insi_ip_ttl: u8,
    /// `rfu_1` plus the padding the `uint64_t`-aligned union forces (6 bytes).
    _pad: [u8; 6],
    pub insi_faddr: [u8; 16],
    pub insi_laddr: [u8; 16],
    /// `insi_v4` + `insi_v6` (16 bytes); not read.
    _tail: [u8; 16],
}

/// `struct tcp_sockinfo` (120 bytes): the `in_sockinfo`, the state, then the
/// timers / mss / flags / pcb handle we never read.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
struct tcp_sockinfo {
    pub tcpsi_ini: in_sockinfo,
    pub tcpsi_state: i32,
    /// `tcpsi_timer[4]`, `tcpsi_mss`, `tcpsi_flags`, `rfu_1`, `tcpsi_tp` (36 bytes).
    _rest: [u8; 36],
}

/// `struct socket_info` (768 bytes), the `psi` member of `socket_fdinfo`. Its
/// offsets (C `offsetof` probe against the SDK header, 2026-11-01): `soi_stat`
/// 0 (136 bytes), `soi_so` 136, `soi_pcb` 144, `soi_type` 152, `soi_protocol`
/// 156, `soi_family` 160, then options / linger / state / queue lengths /
/// `soi_rcv` / `soi_snd` up to `soi_kind` at 232 and the 528-byte `soi_proto`
/// union at 240. Fields we never read are blobs. `align(8)` matches the C type
/// (it holds `uint64_t`s) so the union arm can be read in place.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types, dead_code)]
struct socket_info {
    /// `soi_stat` (136) + `soi_so` (8) + `soi_pcb` (8).
    _soi_head: [u8; 152],
    _soi_type: i32,
    pub soi_protocol: i32,
    pub soi_family: i32,
    /// `soi_options` .. `soi_snd` (164..232).
    _soi_mid: [u8; 68],
    pub soi_kind: i32,
    /// Padding the 8-aligned union forces after the `int`.
    _pad: i32,
    pub soi_proto: [u8; 528],
}

/// `struct socket_fdinfo` (792 bytes): `proc_fileinfo pfi` (24 bytes, skipped),
/// then [`socket_info`] `psi` at 24, so `soi_kind` sits at 256 and `soi_proto`
/// at 264 of the buffer `proc_pidfdinfo` fills.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct socket_fdinfo {
    _pfi: [u8; 24],
    pub psi: socket_info,
}

impl socket_fdinfo {
    /// An all-zero buffer for the kernel to fill; no `unsafe` needed.
    const ZERO: Self = Self {
        _pfi: [0; 24],
        psi: socket_info {
            _soi_head: [0; 152],
            _soi_type: 0,
            soi_protocol: 0,
            soi_family: 0,
            _soi_mid: [0; 68],
            soi_kind: 0,
            _pad: 0,
            soi_proto: [0; 528],
        },
    };
}

const _: () = assert!(size_of::<socket_fdinfo>() == 792);
const _: () = assert!(size_of::<socket_info>() == 768);
const _: () = assert!(size_of::<tcp_sockinfo>() == 120);
const _: () = assert!(size_of::<in_sockinfo>() == 80);
const _: () = assert!(size_of::<proc_fdinfo>() == 8);
const _: () = assert!(size_of::<libc::proc_bsdinfo>() == 136);
const _: () = assert!(size_of::<tcp_sockinfo>() <= 528);

// ---------------------------------------------------------------------------
// Safe wrappers. `find_owners_raw`, `find_owners_among_raw`, `pid_path` and
// `pid_name` are the crate-visible entry points `macos::scan::MacScanner`
// calls; everything else is a private building block (quality finding Q3:
// `tcp_socket` on an arbitrary fd must not be reachable from other modules).
// ---------------------------------------------------------------------------

/// `pid` as the `int` libproc wants; `None` for a value no process can have.
fn c_pid(pid: u32) -> Option<libc::c_int> {
    libc::c_int::try_from(pid).ok()
}

/// A libproc byte count as a usize; `None` for `<= 0` (error, or nothing).
fn positive_len(rc: libc::c_int) -> Option<usize> {
    if rc <= 0 {
        None
    } else {
        usize::try_from(rc).ok()
    }
}

/// Every pid on the system, ascending and de-duplicated, via
/// `proc_listpids(PROC_ALL_PIDS)` with the usual two-call sizing (a size query,
/// then a buffer with slack for pids forked in between). Empty on any error.
fn list_pids() -> Vec<u32> {
    // SAFETY: a null buffer with size 0 is the documented size query: libproc
    // writes nothing and returns the byte count it would need.
    let needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    let Some(needed) = positive_len(needed) else {
        return Vec::new();
    };
    let cap = needed / size_of::<libc::pid_t>() + 64;
    let Ok(cap_bytes) = libc::c_int::try_from(cap * size_of::<libc::pid_t>()) else {
        return Vec::new();
    };
    let mut buf = vec![0 as libc::pid_t; cap];
    // SAFETY: `buf` is a live, writable, properly aligned `Vec<pid_t>` of exactly
    // `cap` elements (`cap_bytes` bytes); libproc writes at most `cap_bytes` bytes
    // into it and returns how many it wrote. The pointer is valid for the whole
    // call and not aliased.
    let written = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            buf.as_mut_ptr().cast::<c_void>(),
            cap_bytes,
        )
    };
    let Some(written) = positive_len(written) else {
        return Vec::new();
    };
    buf.truncate((written / size_of::<libc::pid_t>()).min(cap));
    let mut pids: Vec<u32> = buf
        .into_iter()
        .filter(|&p| p > 0)
        .filter_map(|p| u32::try_from(p).ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// The socket descriptors of `pid` (`PROC_PIDLISTFDS`, filtered to
/// `PROX_FDTYPE_SOCKET`). `None` when the table cannot be read (`EPERM` for
/// another user's process, `ESRCH` for a gone one) or has no entries at all;
/// `Some(vec![])` when it has entries but none is a socket.
fn socket_fds(pid: u32) -> Option<Vec<i32>> {
    let pid = c_pid(pid)?;
    // SAFETY: a null buffer with size 0 is the documented size query; libproc
    // writes nothing and returns the byte count the fd table needs (or <= 0).
    let needed = unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let needed = positive_len(needed)?;
    let cap = needed / size_of::<proc_fdinfo>() + 32;
    let cap_bytes = libc::c_int::try_from(cap * size_of::<proc_fdinfo>()).ok()?;
    let mut buf = vec![
        proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        cap
    ];
    // SAFETY: `buf` is a live, writable, 4-byte-aligned `Vec<proc_fdinfo>` of
    // exactly `cap` entries (`cap_bytes` bytes, `proc_fdinfo` being the 8-byte
    // `#[repr(C)]` mirror the pins check); libproc writes at most `cap_bytes`
    // bytes of `proc_fdinfo` entries and returns how many bytes it wrote. Any
    // bit pattern is a valid `proc_fdinfo` (two plain integers). The pointer is
    // valid for the whole call and not aliased.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast::<c_void>(),
            cap_bytes,
        )
    };
    let written = positive_len(written)?;
    buf.truncate((written / size_of::<proc_fdinfo>()).min(cap));
    Some(
        buf.into_iter()
            .filter(|e| e.proc_fdtype == PROX_FDTYPE_SOCKET)
            .map(|e| e.proc_fd)
            .collect(),
    )
}

/// The four-tuple of one TCP socket, decoded per spec D4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpSocket {
    pub laddr: IpAddr,
    pub lport: u16,
    pub faddr: IpAddr,
    pub fport: u16,
}

/// Decode one 16-byte `insi_laddr` / `insi_faddr` union by `insi_vflag`:
/// `INI_IPV4` → the `in_addr` at bytes 12..16 of `in4in6_addr`; `INI_IPV6` → the
/// whole `in6_addr`; anything else → `None` (fail closed).
fn decode_addr(vflag: u8, raw: &[u8; 16]) -> Option<IpAddr> {
    if vflag & INI_IPV4 != 0 {
        let octets: [u8; 4] = raw[12..16].try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if vflag & INI_IPV6 != 0 {
        Some(IpAddr::V6(Ipv6Addr::from(*raw)))
    } else {
        None
    }
}

/// The TCP four-tuple behind `fd` of `pid` (`PROC_PIDFDSOCKETINFO`). `None`
/// unless the kernel wrote the full 792-byte `socket_fdinfo`, `soi_kind` is
/// `SOCKINFO_TCP`, and both addresses decode.
fn tcp_socket(pid: u32, fd: i32) -> Option<TcpSocket> {
    let pid = c_pid(pid)?;
    let mut info = socket_fdinfo::ZERO;
    let size = libc::c_int::try_from(size_of::<socket_fdinfo>()).ok()?;
    // SAFETY: `info` is a live, writable, 8-byte-aligned `socket_fdinfo` of
    // exactly `size` (792) bytes, the `#[repr(C)]` mirror of the C struct whose
    // size and offsets (`psi` at 24, `soi_kind` at 256, `soi_proto` at 264) the
    // pin test checks against the SDK; libproc writes at most `size` bytes into
    // it and returns how many it wrote. Every bit pattern is a valid
    // `socket_fdinfo` (byte arrays and `i32`s). `pid` and `fd` are
    // only integers handed to the kernel: a stale or non-socket descriptor makes
    // the call fail with an errno (`rc <= 0`, checked below), never UB.
    let rc = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            (&mut info as *mut socket_fdinfo).cast::<c_void>(),
            size,
        )
    };
    if positive_len(rc)? != size_of::<socket_fdinfo>() {
        return None; // short read: the kernel did not fill the union arm
    }
    if info.psi.soi_kind != SOCKINFO_TCP {
        return None;
    }
    // SAFETY: `info.psi.soi_proto` is a live 528-byte array (offset 264 of the
    // 792-byte buffer, as the pin test checks against the SDK); `tcp_sockinfo`
    // is 120 bytes (`const` asserted `<= 528`), so the read stays in bounds.
    // Every bit pattern is a valid `tcp_sockinfo` (integers and byte arrays, no
    // padding bytes are interpreted). `read_unaligned` carries no alignment
    // requirement, so the `align(8)` of the mirrors is a convenience, not a
    // precondition.
    let tcp: tcp_sockinfo =
        unsafe { std::ptr::read_unaligned(info.psi.soi_proto.as_ptr().cast::<tcp_sockinfo>()) };
    let ini = tcp.tcpsi_ini;
    Some(TcpSocket {
        laddr: decode_addr(ini.insi_vflag, &ini.insi_laddr)?,
        lport: port_from_libproc(ini.insi_lport),
        faddr: decode_addr(ini.insi_vflag, &ini.insi_faddr)?,
        fport: port_from_libproc(ini.insi_fport),
    })
}

/// Read a NUL-free byte string libproc wrote into `buf[..len]`.
fn utf8_prefix(buf: &[u8], len: usize) -> Option<String> {
    let bytes = buf.get(..len)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

/// The executable path of `pid` (`proc_pidpath`). `None` on any error or if the
/// kernel's bytes are not UTF-8.
pub(crate) fn pid_path(pid: u32) -> Option<String> {
    let pid = c_pid(pid)?;
    let mut buf = [0u8; PID_PATH_BUF];
    let size = u32::try_from(PID_PATH_BUF).ok()?;
    // SAFETY: `buf` is a live, writable byte array of exactly `size` (4096 =
    // `PROC_PIDPATHINFO_MAXSIZE`) bytes; libproc writes at most `size` bytes and
    // returns the length written (or <= 0 on error). The pointer is valid for
    // the whole call and not aliased.
    let rc = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), size) };
    utf8_prefix(&buf, positive_len(rc)?)
}

/// The short name of `pid` (`proc_name`, at most `2 * MAXCOMLEN` bytes). `None`
/// on any error or if the bytes are not UTF-8.
pub(crate) fn pid_name(pid: u32) -> Option<String> {
    let pid = c_pid(pid)?;
    let mut buf = [0u8; PID_NAME_BUF];
    let size = u32::try_from(PID_NAME_BUF).ok()?;
    // SAFETY: `buf` is a live, writable byte array of exactly `size` (256) bytes;
    // libproc writes at most `size` bytes and returns the length written (or <= 0
    // on error). The pointer is valid for the whole call and not aliased.
    let rc = unsafe { libc::proc_name(pid, buf.as_mut_ptr().cast::<c_void>(), size) };
    utf8_prefix(&buf, positive_len(rc)?)
}

/// The start time of `pid` in microseconds since the epoch
/// (`PROC_PIDTBSDINFO` → `pbi_start_tvsec * 1_000_000 + pbi_start_tvusec`).
/// `None` unless the full 136-byte `proc_bsdinfo` was written.
fn pid_start_micros(pid: u32) -> Option<u64> {
    let pid = c_pid(pid)?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: `info` is a live, writable, properly aligned `proc_bsdinfo` of
    // exactly `size` (136) bytes, zero-initialised; libproc writes at most `size`
    // bytes into it and returns how many it wrote. The pointer is valid for the
    // whole call and not aliased.
    let rc = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if positive_len(rc)? != size_of::<libc::proc_bsdinfo>() {
        return None;
    }
    // SAFETY: the kernel wrote all `size` bytes (checked above), and even the
    // zeroed buffer is a valid `proc_bsdinfo` (integers and `c_char` arrays only),
    // so the value is fully initialised.
    let info = unsafe { info.assume_init() };
    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

/// The spec D4 scan: pids ascending, `skip_pid` skipped, the deadline checked
/// before each pid and every [`FD_DEADLINE_STRIDE`] fds within one, every socket
/// fd of each pid decoded and matched against the tuples not yet found; the
/// first (lowest) matching pid wins. `start` comes from
/// [`pid_start_micros`] for matched pids only, `0` if the kernel would not say.
/// Any per-pid or per-fd failure is a skip. Tuples not found by `deadline` are
/// absent from the result.
pub(crate) fn find_owners_raw(
    wanted: &[Tuple],
    deadline: Instant,
    skip_pid: Option<u32>,
) -> HashMap<Tuple, ProcessKey> {
    if wanted.is_empty() {
        return HashMap::new();
    }
    walk_pids(wanted, deadline, skip_pid, &list_pids()).owners
}

/// The same match over **only** `pids` (F2, 2026-11-01: the coalescer's warm
/// set), in the order given; a pid whose fd table cannot be read or holds no
/// socket fd (`Probe::gone`'s contract, same as the Linux walk) is reported in
/// `gone`. One `proc_pidinfo(PROC_PIDLISTFDS)` plus one
/// `proc_pidfdinfo` per socket fd per pid; no `proc_listpids`.
pub(crate) fn find_owners_among_raw(
    wanted: &[Tuple],
    deadline: Instant,
    skip_pid: Option<u32>,
    pids: &[u32],
) -> Probe {
    walk_pids(wanted, deadline, skip_pid, pids)
}

/// How many socket fds of one pid are decoded between deadline checks
/// (security finding S3, 2026-11-01): a single process with tens of thousands
/// of sockets must not carry the walk past the deadline on its own.
const FD_DEADLINE_STRIDE: usize = 64;

/// The per-pid body shared by the full scan and the targeted probe.
fn walk_pids(wanted: &[Tuple], deadline: Instant, skip_pid: Option<u32>, pids: &[u32]) -> Probe {
    let mut probe = Probe {
        owners: HashMap::with_capacity(wanted.len()),
        gone: Vec::new(),
    };
    let mut starts: HashMap<u32, u64> = HashMap::new();
    for &pid in pids {
        if probe.owners.len() == wanted.len() || Instant::now() >= deadline {
            break;
        }
        if Some(pid) == skip_pid {
            continue;
        }
        let Some(fds) = socket_fds(pid).filter(|fds| !fds.is_empty()) else {
            probe.gone.push(pid);
            continue;
        };
        for (i, fd) in fds.into_iter().enumerate() {
            if i % FD_DEADLINE_STRIDE == FD_DEADLINE_STRIDE - 1 && Instant::now() >= deadline {
                return probe;
            }
            let Some(sock) = tcp_socket(pid, fd) else {
                continue;
            };
            for tuple in wanted {
                if probe.owners.contains_key(tuple) {
                    continue;
                }
                if tuple_matches(sock.laddr, sock.lport, sock.faddr, sock.fport, tuple) {
                    let start = *starts
                        .entry(pid)
                        .or_insert_with(|| pid_start_micros(pid).unwrap_or(0));
                    probe.owners.insert(*tuple, ProcessKey { pid, start });
                }
            }
        }
    }
    probe
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    use super::{
        decode_addr, find_owners_among_raw, find_owners_raw, in_sockinfo, list_pids, pid_name,
        pid_path, pid_start_micros, proc_fdinfo, socket_fdinfo, socket_fds, socket_info,
        tcp_socket, tcp_sockinfo, utf8_prefix, INI_IPV4, INI_IPV6,
    };
    use crate::types::Tuple;

    /// AC8: the mirrors match `sys/proc_info.h` of the SDK on this Mac (research 24 §3.1).
    #[test]
    fn socket_fdinfo_layout_matches_the_sdk() {
        assert_eq!(size_of::<socket_fdinfo>(), 792);
        assert_eq!(offset_of!(socket_fdinfo, psi), 24);
        assert_eq!(size_of::<socket_info>(), 768);
        // Inside `socket_info` (research 24 §3.1, corrected 2026-11-01 by a C
        // `offsetof` probe): 156 / 160 / 232 / 240 ...
        assert_eq!(offset_of!(socket_info, soi_protocol), 156);
        assert_eq!(offset_of!(socket_info, soi_family), 160);
        assert_eq!(offset_of!(socket_info, soi_kind), 232);
        assert_eq!(offset_of!(socket_info, soi_proto), 240);
        // ... so inside `socket_fdinfo` (what `proc_pidfdinfo` fills): 180 / 184 / 256 / 264.
        assert_eq!(offset_of!(socket_fdinfo, psi.soi_protocol), 180);
        assert_eq!(offset_of!(socket_fdinfo, psi.soi_family), 184);
        assert_eq!(offset_of!(socket_fdinfo, psi.soi_kind), 256);
        assert_eq!(offset_of!(socket_fdinfo, psi.soi_proto), 264);
        assert_eq!(
            size_of::<socket_info>() - offset_of!(socket_info, soi_proto),
            528
        );
        assert_eq!(size_of::<in_sockinfo>(), 80);
        assert_eq!(offset_of!(in_sockinfo, insi_lport), 4);
        assert_eq!(offset_of!(in_sockinfo, insi_vflag), 24);
        assert_eq!(offset_of!(in_sockinfo, insi_faddr), 32);
        assert_eq!(offset_of!(in_sockinfo, insi_laddr), 48);
        assert_eq!(offset_of!(tcp_sockinfo, tcpsi_state), 80);
        assert_eq!(size_of::<proc_fdinfo>(), 8);
        // Not in AC8 but load-bearing for the bounds checks below.
        assert_eq!(size_of::<tcp_sockinfo>(), 120);
        assert_eq!(size_of::<libc::proc_bsdinfo>(), 136);
    }

    fn accepted_pair(bind: &str) -> (TcpListener, TcpStream, TcpStream, Tuple) {
        let listener = TcpListener::bind(bind).expect("bind loopback listener");
        let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (accepted, peer) = listener.accept().expect("accept");
        let tuple = Tuple {
            client: peer,
            proxy: accepted.local_addr().unwrap(),
        };
        (listener, client, accepted, tuple)
    }

    /// AC9 (Terminal: binds a loopback socket).
    #[test]
    fn self_resolution_v4() {
        let (_l, _c, _a, tuple) = accepted_pair("127.0.0.1:0");
        let owners = find_owners_raw(&[tuple], Instant::now() + Duration::from_secs(1), None);
        assert_eq!(owners[&tuple].pid, std::process::id());
    }

    /// AC9 (Terminal: binds a loopback socket).
    #[test]
    fn self_resolution_v6() {
        let (_l, _c, _a, tuple) = accepted_pair("[::1]:0");
        let owners = find_owners_raw(&[tuple], Instant::now() + Duration::from_secs(1), None);
        assert_eq!(owners[&tuple].pid, std::process::id());
    }

    /// AC9 (Terminal: binds a loopback socket). A client port that belonged to a
    /// socket we have since dropped owns nothing.
    #[test]
    fn closed_port_resolves_nothing() {
        let tuple = {
            let (_l, _c, _a, tuple) = accepted_pair("127.0.0.1:0");
            tuple
        };
        let owners = find_owners_raw(&[tuple], Instant::now() + Duration::from_secs(1), None);
        assert!(owners.is_empty(), "stale tuple matched: {owners:?}");
    }

    /// launchd (pid 1) belongs to root: its fd table is `EPERM` for us, which is a
    /// skip (`None`), not a panic. And the pid list is real.
    #[test]
    fn other_users_pids_are_skipped_not_errors() {
        assert_eq!(socket_fds(1), None);
        assert!(list_pids().len() > 1);
        assert!(list_pids().contains(&std::process::id()));
    }

    /// The read-only wrappers work on our own pid inside the sandbox.
    #[test]
    fn own_pid_is_readable() {
        let me = std::process::id();
        assert!(socket_fds(me).is_some());
        let path = pid_path(me).expect("own path");
        assert!(
            path.rsplit('/')
                .next()
                .unwrap()
                .starts_with("aitm_peer_process"),
            "path = {path}"
        );
        let name = pid_name(me).expect("own name");
        assert!(name.starts_with("aitm_peer_process"), "name = {name}");
        let start = pid_start_micros(me).expect("own start");
        assert!(start > 1_600_000_000 * 1_000_000, "start = {start}");
    }

    /// `pid_*` on a pid that cannot exist is `None`, not a panic or garbage.
    #[test]
    fn impossible_pid_yields_none() {
        assert_eq!(pid_path(i32::MAX as u32), None);
        assert_eq!(pid_name(i32::MAX as u32), None);
        assert_eq!(pid_start_micros(i32::MAX as u32), None);
        assert_eq!(socket_fds(i32::MAX as u32), None);
    }

    /// AC9 (Terminal: binds a loopback socket). F2: a warm probe of our own pid
    /// names this process without walking the pid list.
    #[test]
    fn warm_probe_names_this_process_without_a_full_scan() {
        let (_l, _c, _a, tuple) = accepted_pair("127.0.0.1:0");
        let me = std::process::id();
        let probe = find_owners_among_raw(
            &[tuple],
            Instant::now() + Duration::from_secs(1),
            None,
            &[me],
        );
        assert_eq!(probe.owners[&tuple].pid, me);
        assert!(probe.gone.is_empty(), "{:?}", probe.gone);
    }

    /// F2 (sandbox): launchd's fd table is `EPERM` and an impossible pid is
    /// `ESRCH`; a probe reports both as `gone` and finds nothing. Our own pid
    /// has sockets (the test harness), so it is probed, matches a tuple nobody
    /// owns on nothing, and is not gone.
    #[test]
    fn a_targeted_probe_reports_unreadable_pids_gone() {
        let nobody = Tuple {
            client: "127.0.0.1:1".parse().unwrap(),
            proxy: "127.0.0.1:2".parse().unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let probe = find_owners_among_raw(&[nobody], deadline, None, &[1, i32::MAX as u32]);
        assert!(probe.owners.is_empty(), "{:?}", probe.owners);
        assert_eq!(probe.gone, vec![1, i32::MAX as u32]);

        let me = std::process::id();
        let probe = find_owners_among_raw(&[nobody], deadline, None, &[me]);
        assert!(probe.owners.is_empty(), "{:?}", probe.owners);
        assert!(probe.gone.is_empty(), "{:?}", probe.gone);

        // The skipped pid is neither walked nor reported.
        let probe = find_owners_among_raw(&[nobody], deadline, Some(1), &[1]);
        assert!(probe.gone.is_empty(), "{:?}", probe.gone);
    }

    /// D4: the 16-byte address unions decode by `insi_vflag` — `INI_IPV4` reads
    /// the `in_addr` at bytes 12..16 of `in4in6_addr`, `INI_IPV6` the whole
    /// `in6_addr`, and an unknown flag is `None` (fail closed), never a guess.
    #[test]
    fn decode_addr_follows_insi_vflag() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut v4 = [0xAAu8; 16];
        v4[12..16].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(
            decode_addr(INI_IPV4, &v4),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(
            decode_addr(INI_IPV6, &v6),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(decode_addr(0, &v4), None);
        assert_eq!(decode_addr(0x4, &v4), None);
        // Both bits set: the v4 arm wins, as in the header's `in4in6_addr` use.
        assert_eq!(
            decode_addr(INI_IPV4 | INI_IPV6, &v4),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    /// D4: a vnode descriptor is never listed as a socket and `tcp_socket` on
    /// it (or on a bad fd, or on another user's pid) is `None`, not a panic.
    #[test]
    fn a_vnode_fd_is_neither_listed_nor_a_tcp_socket() {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = file.as_raw_fd();
        let me = std::process::id();
        assert_eq!(tcp_socket(me, fd), None);
        assert!(
            !socket_fds(me).unwrap_or_default().contains(&fd),
            "a vnode fd must be filtered out of the socket list"
        );
        assert_eq!(tcp_socket(me, i32::MAX), None); // EBADF
        assert_eq!(tcp_socket(1, 0), None); // EPERM (launchd)
    }

    /// The byte strings libproc writes are read up to the first NUL and only
    /// if they are UTF-8; a length past the buffer is a short read.
    #[test]
    fn utf8_prefix_stops_at_nul_and_rejects_invalid_bytes() {
        assert_eq!(utf8_prefix(b"curl\0junk", 9), Some("curl".to_string()));
        assert_eq!(utf8_prefix(b"curl", 4), Some("curl".to_string()));
        assert_eq!(utf8_prefix(b"cu\xffrl", 5), None);
        assert_eq!(utf8_prefix(b"curl", 10), None);
    }

    /// The deadline is checked before every pid: an already-expired deadline
    /// walks nothing and so reports nothing gone (sandbox: no sockets bound).
    #[test]
    fn an_expired_deadline_walks_no_pid() {
        let nobody = Tuple {
            client: "127.0.0.1:1".parse().unwrap(),
            proxy: "127.0.0.1:2".parse().unwrap(),
        };
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let probe = find_owners_among_raw(&[nobody], past, None, &[1, i32::MAX as u32]);
        assert!(probe.owners.is_empty());
        assert!(
            probe.gone.is_empty(),
            "nothing was probed: {:?}",
            probe.gone
        );
        assert!(find_owners_raw(&[nobody], past, None).is_empty());
        assert!(find_owners_raw(&[], Instant::now() + Duration::from_secs(1), None).is_empty());
    }
}
