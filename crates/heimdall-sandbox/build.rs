/// Add rpath so the binary finds libwebgpu_dawn next to it at runtime.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.contains("apple-darwin") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path");
    } else if target.contains("unknown-linux") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
}
