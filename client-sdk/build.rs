fn main() {
    uniffi_build::generate_scaffolding("./src/fortgate_id.udl")
        .expect("uniffi scaffolding");
}
