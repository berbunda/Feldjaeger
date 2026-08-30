fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=assets/feldjaeger.rc");
        println!("cargo:rerun-if-changed=assets/feldjaeger.ico");
        // Icon-only resource — cosmetic, so a missing RC compiler must not fail the build.
        embed_resource::compile("assets/feldjaeger.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("failed to compile assets/feldjaeger.rc");
    }
}
