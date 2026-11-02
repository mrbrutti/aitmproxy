//! Crawler v2: the `Crawler` trait, the shared frontier and the two engines
//! (browser and client) that fill it (spec D8.1, tasks 4 and 14 to 18).

pub(crate) mod browser;
pub(crate) mod client;
pub(crate) mod extract;
pub(crate) mod frontier;
pub(crate) mod seeds;
pub(crate) mod values;
