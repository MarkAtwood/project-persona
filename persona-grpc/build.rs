/// Every proto compiled into this crate, named once so the rebuild trigger and
/// the compiler input cannot drift apart.
const PROTOS: &[&str] = &["../proto/spiffe/workload/workload.proto"];

/// Root the protos are compiled against, and the prefix their imports resolve from.
const INCLUDE: &str = "../proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Without these, Cargo falls back to rerunning this script when a file
    // inside the package changes. The protos live at the workspace root,
    // outside persona-grpc/, so they are not in that set: editing one and
    // rebuilding reused the code generated from the previous version, and the
    // mismatch surfaced later as a type error or a wire-format bug rather than
    // as a stale build.
    for proto in PROTOS {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed={INCLUDE}");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(PROTOS, &[INCLUDE])?;
    Ok(())
}
