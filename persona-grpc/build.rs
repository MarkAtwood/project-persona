/// Every proto compiled into this crate, named once so the rebuild trigger and
/// the compiler input cannot drift apart.
const PROTOS: &[&str] = &["../proto/spiffe/workload/workload.proto"];

/// Root the protos are compiled against, and the prefix their imports resolve from.
///
// ponytail: the protos live above the package root, so this crate builds only
//   from inside the workspace checkout | ceiling: `cargo package`, `cargo
//   vendor` and docs.rs all exclude files above the package root, so a
//   packaged persona-grpc would fail here with a missing-file error that says
//   nothing about packaging | upgrade path: `git mv proto persona-grpc/proto`
//   and drop the `../` from both constants -- the tree is one file and nothing
//   else references it. Deliberately not done: every crate here is
//   `publish = false`, so the workspace is the only consumer and one shared
//   proto/ directory is the honest layout for it.
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
