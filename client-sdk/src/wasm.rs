//! API WebAssembly (`wasm-pack`) para integraciones Node/Web.
//! Requiere `getrandom` con feature `js` (ver `Cargo.toml` target wasm32).

use wasm_bindgen::prelude::*;

fn fortgate_error_to_js_string(e: &crate::FortgateError) -> String {
    match e {
        crate::FortgateError::ParseError => "ParseError".to_string(),
        crate::FortgateError::InvalidAlgorithm => "InvalidAlgorithm".to_string(),
        crate::FortgateError::RfcNotFound => "RfcNotFound".to_string(),
        crate::FortgateError::CryptoError => "CryptoError".to_string(),
    }
}

#[wasm_bindgen(js_name = create_fortgate_witness_wasm)]
pub fn create_fortgate_witness_wasm(cert_der: &[u8]) -> Result<JsValue, JsValue> {
    let pkg = crate::create_fortgate_witness(cert_der).map_err(|e| {
        JsValue::from_str(&fortgate_error_to_js_string(&e))
    })?;
    serde_wasm_bindgen::to_value(&pkg).map_err(|e| JsValue::from_str(&e.to_string()))
}
