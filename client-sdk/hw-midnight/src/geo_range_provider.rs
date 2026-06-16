//! Provider Midnight para `geo-range-v1`.

use crate::error::HwMidnightError;
use crate::geo::{deg_to_e6, e6_to_deg, validate_inside_range};
use crate::geo_range::{GeoRangeRelationV1, GeoRangeWitness};
use crate::midnight_provider::MidnightCircuitProvider;
use crate::types::{
    GeoProofPackage, GeoRangePublicInputs, GEO_CIRCUIT_VERSION, PACKAGE_VERSION, PROOF_PROVIDER_ID,
    now_rfc3339,
};

pub struct MidnightGeoRangeProvider {
    inner: MidnightCircuitProvider<GeoRangeRelationV1>,
}

impl Default for MidnightGeoRangeProvider {
    fn default() -> Self {
        Self {
            inner: MidnightCircuitProvider::new(GeoRangeRelationV1, GEO_CIRCUIT_VERSION),
        }
    }
}

impl MidnightGeoRangeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn setup_keys(&self) -> Result<(), HwMidnightError> {
        self.inner.setup_keys()
    }

    pub fn prove_coords(
        &self,
        center_lat: f64,
        center_lon: f64,
        actual_lat: f64,
        actual_lon: f64,
        radius_meters: u32,
    ) -> Result<GeoProofPackage, HwMidnightError> {
        validate_inside_range(center_lat, center_lon, actual_lat, actual_lon, radius_meters)?;

        let center_lat_e6 = deg_to_e6(center_lat);
        let center_lon_e6 = deg_to_e6(center_lon);
        let actual_lat_e6 = deg_to_e6(actual_lat);
        let actual_lon_e6 = deg_to_e6(actual_lon);

        let instance = GeoRangeRelationV1::build_instance(
            center_lat_e6,
            center_lon_e6,
            radius_meters,
            true,
            center_lat,
        )
        .map_err(|e| HwMidnightError::Geo(e.to_string()))?;

        let public_inputs = GeoRangePublicInputs {
            center_lat_e6,
            center_lon_e6,
            radius_meters,
            inside_range: true,
        };

        let witness = GeoRangeWitness {
            actual_lat_e6,
            actual_lon_e6,
        };

        let (proof_bytes, proving_time_ms) = self.inner.prove(&instance, witness)?;

        Ok(GeoProofPackage {
            package_version: PACKAGE_VERSION.to_string(),
            proof_provider_id: PROOF_PROVIDER_ID.to_string(),
            circuit_version: GEO_CIRCUIT_VERSION.to_string(),
            public_inputs,
            proof_bytes,
            verifying_key_ref: self.inner.verifying_key_ref(),
            proving_time_ms,
            created_at: now_rfc3339(),
        })
    }

    pub fn verify(&self, package: &GeoProofPackage) -> Result<(), HwMidnightError> {
        if package.circuit_version != GEO_CIRCUIT_VERSION {
            return Err(HwMidnightError::Verify("circuit_version geo-range mismatch".into()));
        }
        if !package.public_inputs.inside_range {
            return Err(HwMidnightError::Verify(
                "inside_range=false no es válido en PoC".into(),
            ));
        }

        let center_lat = e6_to_deg(package.public_inputs.center_lat_e6);
        let instance = GeoRangeRelationV1::build_instance(
            package.public_inputs.center_lat_e6,
            package.public_inputs.center_lon_e6,
            package.public_inputs.radius_meters,
            true,
            center_lat,
        )
        .map_err(|e| HwMidnightError::Geo(e.to_string()))?;

        self.inner.verify(&instance, &package.proof_bytes)
    }

    pub fn write_package(path: &std::path::Path, package: &GeoProofPackage) -> Result<(), HwMidnightError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(package)?)?;
        Ok(())
    }

    pub fn read_package(path: &std::path::Path) -> Result<GeoProofPackage, HwMidnightError> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}
