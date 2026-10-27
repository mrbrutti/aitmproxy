//! The `aitm` binary. Wiring from `Config` lands in Task 28; for now it is a
//! placeholder so the workspace builds end to end.

fn main() {
    println!("aitm {}", aitm_core::VERSION);
}
