

fn main() -> miette::Result<()> {
    let path = std::path::PathBuf::from("src");
    let lib_path = std::path::PathBuf::from("/opt/homebrew/include");
    let mut b = autocxx_build::Builder::new("src/lib.rs", [&path, &lib_path]).build()?;
    b
        .flag_if_supported("-std=c++14")
        .compile("bicycl");

    // let mut b_main = autocxx_build::Builder::new("src/main.rs", [&path]).build()?;
    // b_main
    //     .flag_if_supported("-std=c++14")
    //     .compile("bicycl");


    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/bicycl.h");
    Ok(())
}