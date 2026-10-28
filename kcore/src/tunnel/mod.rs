//! The panel's tunnel transports, compiled from the panel's own files (nothing is copied).
#![allow(dead_code)]
#[path = "../../../src/tunnel/dual.rs"]
pub mod dual;
#[path = "../../../src/tunnel/faketcp.rs"]
pub mod faketcp;
#[path = "../../../src/tunnel/fec.rs"]
pub mod fec;
#[path = "../../../src/tunnel/game.rs"]
pub mod game;
#[path = "../../../src/tunnel/h2ws.rs"]
pub mod h2ws;
#[path = "../../../src/tunnel/hq.rs"]
pub mod hq;
#[path = "../../../src/tunnel/kcore/mod.rs"]
pub mod kcore;
#[path = "../../../src/tunnel/link.rs"]
pub mod link;
#[path = "../../../src/tunnel/mux.rs"]
pub mod mux;
#[path = "../../../src/tunnel/obfs.rs"]
pub mod obfs;
#[path = "../../../src/tunnel/probe.rs"]
pub mod probe;
#[path = "../../../src/tunnel/quic.rs"]
pub mod quic;
#[path = "../../../src/tunnel/salamander.rs"]
pub mod salamander;
