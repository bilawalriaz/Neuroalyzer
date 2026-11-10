fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!("cargo:rerun-if-changed=neuralyzer.rc");
    println!("cargo:rerun-if-changed=assets/neuralyzer.ico");
    embed_resource::compile_for("neuralyzer.rc", ["neuralyzer"], embed_resource::NONE)
        .manifest_required()
        .expect("embed the Neuralyzer executable icon");
}
