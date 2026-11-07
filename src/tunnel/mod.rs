//! Kanki Tunnel: encrypted tunnels between servers (entry -> exit), managed from the panel.
pub mod agent;
#[path = "transport/awg.rs"]
pub mod awg;
#[path = "transport/dgram.rs"]
pub mod dgram;
#[path = "transport/dual.rs"]
pub mod dual;
pub mod engine;
#[path = "transport/faketcp.rs"]
pub mod faketcp;
#[path = "transport/fec.rs"]
pub mod fec;
#[path = "transport/game.rs"]
pub mod game;
#[path = "transport/h2ws.rs"]
pub mod h2ws;
#[path = "transport/hy2t.rs"]
pub mod hy2t;
#[path = "transport/hq.rs"]
pub mod hq;
pub mod link;
#[path = "transport/mux.rs"]
pub mod mux;
#[path = "transport/obfs.rs"]
pub mod obfs;
pub mod panel;
pub mod probe;
pub mod quality;
#[path = "transport/quic.rs"]
pub mod quic;
#[path = "transport/salamander.rs"]
pub mod salamander;

#[cfg(test)]
mod tests;
