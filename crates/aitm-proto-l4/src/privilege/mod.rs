//! Privilege: the contracts both ends of the L4 capture-privilege boundary share,
//! the report `l4.privilege` answers with, and the pure decision table behind it.

pub mod availability;
pub mod contract;
pub mod derive;
pub mod linux;
pub mod macos;
pub mod report;
