// l4-udp-probe.rhai — operator command
// `l4.udp_probe { dst, port, interface, timeout_ms? }`: send one empty UDP
// datagram and report whether a reply (or ICMP error) returns. A single-packet
// reachability check for a UDP service.
//
// ACTIVE L4: one crafted packet via l4.send_recv, gated by the L4 guard's
// Inject+Capture capability and scope. Operator-invoked only. Authorised use only.
//
// `l4` is named inside `udp_probe()`, which runs when the command is invoked.
// A closure captures every outer name when it is created, so naming `l4` in
// the command closure would fail `load(reg)` whenever the L4 layer is off —
// before the `try` could catch it.
const NAME = "l4-udp-probe";
const API  = "1";

fn udp_probe(dst, port, interface, timeout) {
    let spec = #{ layers: [
        #{ ipv4: #{ dst: dst } },
        #{ udp: #{ dst_port: port } },
    ]};
    let r = l4.send_recv(spec, dst, interface, port, timeout);
    let kind = r.outcome.kind;
    if kind == "no_response" {
        return `${dst}:${port}/udp no reply in ${timeout}ms (open|filtered)`;
    }
    `${dst}:${port}/udp replied (kind=${kind})`
}

fn load(reg) {
    reg.add_command("l4.udp_probe", "Single UDP datagram to { dst, port, interface }", |args| {
        if type_of(args.dst) != "string" || type_of(args.interface) != "string" || args.port == () {
            return "usage: l4.udp_probe { dst: \"1.2.3.4\", port: 53, interface: \"en0\" }";
        }
        let timeout = if args.timeout_ms == () { 1000 } else { args.timeout_ms };
        try {
            udp_probe(args.dst, args.port, args.interface, timeout)
        } catch (e) {
            `l4.udp_probe failed (is the L4 layer enabled and the target in scope?): ${e}`
        }
    });
}
