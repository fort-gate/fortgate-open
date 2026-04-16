fn main() {
    println!("cargo:rerun-if-changed=../program/src/main.rs");
    println!("cargo:rerun-if-changed=../program/Cargo.toml");
    sp1_build::build_program_with_args("../program", Default::default());
}
