// l4-tcp-syn-probe.rhai — operator command
// `l4.tcp_probe { dst, port, interface, timeout_ms? }`: send one TCP SYN and
// classify the reply as open (SYN-ACK), closed (RST), or filtered (no reply).
// A single-packet connectivity/state check, not a sweep.
//
// ACTIVE L4: one crafted packet via l4.send_recv, gated by the L4 guard's
// Inject+Capture capability and scope (deny-by-default). Operator-invoked only.
// For authorised testing only.
//
// `l4` is named inside `tcp_probe()`, which runs when the command is invoked.
// A closure captures every outer name when it is created, so naming `l4` in
// the command closure would fail `load(reg)` whenever the L4 layer is off —
// before the `try` could catch it.
const NAME = "l4-tcp-syn-probe";
const API  = "1";

fn tcp_probe(dst, port, interface, timeout) {
    let spec = #{ layers: [
        #{ ipv4: #{ dst: dst } },
        #{ tcp: #{ dst_port: port, flags: 2 } },  // flags=2 = SYN
    ]};
    let r = l4.send_recv(spec, dst, interface, port, timeout);
    let kind = r.outcome.kind;
    if kind == "no_response" { return `${dst}:${port} FILTERED (no reply in ${timeout}ms)`; }
    let flags = "";
    if type_of(r.outcome.packet) == "map" && type_of(r.outcome.packet.tcp) == "map" {
        flags = r.outcome.packet.tcp.flags;
    }
    if flags.contains("S") && flags.contains("A") {
        return `${dst}:${port} OPEN (SYN-ACK)`;
    } else if flags.contains("R") {
        return `${dst}:${port} CLOSED (RST)`;
    }
    `${dst}:${port} replied (flags=${flags}, kind=${kind})`
}

fn load(reg) {
    reg.add_command("l4.tcp_probe", "Single TCP SYN to { dst, port, interface } -> open/closed/filtered", |args| {
        if type_of(args.dst) != "string" || type_of(args.interface) != "string" || args.port == () {
            return "usage: l4.tcp_probe { dst: \"1.2.3.4\", port: 443, interface: \"en0\" }";
        }
        let timeout = if args.timeout_ms == () { 1000 } else { args.timeout_ms };
        try {
            tcp_probe(args.dst, args.port, args.interface, timeout)
        } catch (e) {
            `l4.tcp_probe failed (is the L4 layer enabled and the target in scope?): ${e}`
        }
    });
}
