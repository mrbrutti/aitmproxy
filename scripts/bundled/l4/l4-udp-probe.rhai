// l4-udp-probe.rhai — operator command
// `l4.udp_probe { dst, port, interface, timeout_ms? }`: send one empty UDP
// datagram and report whether a reply (or ICMP error) returns. A single-packet
// reachability check for a UDP service.
//
// ACTIVE L4: one crafted packet via l4.send_recv, gated by the L4 guard's
// Inject+Capture capability and scope. Operator-invoked only. Authorised use only.
const NAME = "l4-udp-probe";
const API  = "1";

fn load(reg) {
    reg.add_command("l4.udp_probe", "Single UDP datagram to { dst, port, interface }", |args| {
        if type_of(args.dst) != "string" || type_of(args.interface) != "string" || args.port == () {
            return "usage: l4.udp_probe { dst: \"1.2.3.4\", port: 53, interface: \"en0\" }";
        }
        let timeout = if args.timeout_ms == () { 1000 } else { args.timeout_ms };
        let spec = #{ layers: [
            #{ ipv4: #{ dst: args.dst } },
            #{ udp: #{ dst_port: args.port } },
        ]};
        try {
            let r = l4.send_recv(spec, args.dst, args.interface, args.port, timeout);
            let kind = r.outcome.kind;
            if kind == "no_response" {
                return `${args.dst}:${args.port}/udp no reply in ${timeout}ms (open|filtered)`;
            }
            `${args.dst}:${args.port}/udp replied (kind=${kind})`
        } catch (e) {
            `l4.udp_probe failed (is the L4 layer enabled and the target in scope?): ${e}`
        }
    });
}
