// neuroalyzer patch: upstream forces the static C runtime (/MT), which clashes
// with ONNX Runtime's /MD build on Windows (LNK2038). Follow the target's
// crt-static setting instead.
#[cfg(feature = "cpp")]
#[cfg(not(target_os = "macos"))]
fn main() {
    let crt_static = std::env::var("CARGO_CFG_TARGET_FEATURE").is_ok_and(|f| f.split(',').any(|x| x == "crt-static"));
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++11")
        .static_crt(crt_static)
        .file("src/esaxx.cpp")
        .include("src")
        .compile("esaxx");
}

#[cfg(feature = "cpp")]
#[cfg(target_os = "macos")]
fn main() {
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++11")
        .flag("-stdlib=libc++")
        .static_crt(true)
        .file("src/esaxx.cpp")
        .include("src")
        .compile("esaxx");
}

#[cfg(not(feature = "cpp"))]
fn main() {}
