pub mod types;
pub mod cert_parser;
pub mod blinded_witness;
pub mod hardware;

uniffi::include_scaffolding!("fortgate_id");

pub fn version() -> String {
    "0.1.0".to_string()
}
