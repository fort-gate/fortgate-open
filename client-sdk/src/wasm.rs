//! API WebAssembly (`wasm-pack`) para integraciones Node/Web.
//! Requiere `getrandom` con feature `js` (ver `Cargo.toml` target wasm32).

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = create_fortgate_witness_wasm)]
pub fn create_fortgate_witness_wasm(cert_der: &[u8]) -> Result<JsValue, JsValue> {
    let pkg = crate::create_fortgate_witness(cert_der).map_err(|e| {
        JsValue::from_str(&format!("FortgateError: {:?}", e))
    })?;
    serde_wasm_bindgen::to_value(&pkg).map_err(|e| JsValue::from_str(&e.to_string()))
}
