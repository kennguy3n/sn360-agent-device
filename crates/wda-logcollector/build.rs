fn main() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("CARGO_FEATURE_LINUX_JOURNAL").is_ok() {
            println!("cargo:rustc-link-lib=systemd");
        }
    }
}
