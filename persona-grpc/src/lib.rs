//! SPIFFE Workload API gRPC server.

pub mod consumer_attest;
pub mod server;
pub mod service;

/// Generated types and service traits from the SPIFFE Workload API proto.
pub mod workload {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}
