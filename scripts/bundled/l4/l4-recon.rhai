// l4-recon.rhai — operator command `l4.recon`: list capture-capable interfaces
// and the current L4 scope. Read-only; it touches no wire.
//
// Requires the L4 layer to be enabled (deny-by-default). Registers a command
// only; it runs nothing until invoked. For authorised testing only.
const NAME = "l4-recon";
const API  = "1";

fn load(reg) {
    reg.add_command("l4.recon", "List L4 interfaces and current scope (read-only)", |args| {
        try {
            let ifaces = l4.interfaces();
            let scope = l4.scope.list();
            `interfaces: ${ifaces}\nscope: ${scope}`
        } catch (e) {
            `l4 is not available (is the L4 layer enabled?): ${e}`
        }
    });
}
