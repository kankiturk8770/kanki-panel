//! Kanki Tunnel: encrypted tunnels between servers (entry -> exit), managed from the panel.
pub mod agent;
pub mod awg;
pub mod dual;
pub mod engine;
pub mod h2ws;
pub mod hq;
pub mod link;
pub mod mux;
pub mod obfs;
pub mod panel;
pub mod probe;
pub mod quic;
pub mod salamander;

#[cfg(test)]
mod tests;
