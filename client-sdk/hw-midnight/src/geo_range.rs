//! Circuito Midnight `geo-range-v1`: distancia euclídea escalada ≤ radio (PoC ≤200 m).

use crate::circuit_util::{assign_public_bytes, assign_public_scalar};
use crate::geo::{cos_lat_million, METERS_PER_DEGREE_LAT, MAX_RADIUS_METERS};
use midnight_circuits::instructions::{
    ArithInstructions, AssertionInstructions, AssignmentInstructions,
};
use group::ff::Field;
use midnight_circuits::types::{AssignedByte, AssignedNative, Instantiable};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoRangeCircuitInstance {
    pub center_lat_e6: i32,
    pub center_lon_e6: i32,
    pub radius_meters: u32,
    /// 1 = dentro de rango, 0 = fuera (demo inválida).
    pub inside_range: u8,
    pub lon_scale: i64,
    pub bound_sq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoRangeWitness {
    pub actual_lat_e6: i32,
    pub actual_lon_e6: i32,
}

#[derive(Clone, Default)]
pub struct GeoRangeRelationV1;

impl GeoRangeRelationV1 {
    pub fn build_instance(
        center_lat_e6: i32,
        center_lon_e6: i32,
        radius_meters: u32,
        inside_range: bool,
        center_lat_deg: f64,
    ) -> Result<GeoRangeCircuitInstance, &'static str> {
        if radius_meters > MAX_RADIUS_METERS {
            return Err("radius exceeds MAX_RADIUS_METERS");
        }
        let lon_scale = METERS_PER_DEGREE_LAT * cos_lat_million(center_lat_deg) / 1_000_000;
        let bound = u64::from(radius_meters) * 1_000_000;
        let bound_sq = bound.saturating_mul(bound);
        Ok(GeoRangeCircuitInstance {
            center_lat_e6,
            center_lon_e6,
            radius_meters,
            inside_range: u8::from(inside_range),
            lon_scale,
            bound_sq,
        })
    }

    pub fn scaled_distance_sq(
        center_lat_e6: i32,
        center_lon_e6: i32,
        actual_lat_e6: i32,
        actual_lon_e6: i32,
        center_lat_deg: f64,
    ) -> u64 {
        let dlat = i64::from(actual_lat_e6) - i64::from(center_lat_e6);
        let dlon = i64::from(actual_lon_e6) - i64::from(center_lon_e6);
        let lat_term = dlat.saturating_mul(METERS_PER_DEGREE_LAT);
        let lon_scale = METERS_PER_DEGREE_LAT * cos_lat_million(center_lat_deg) / 1_000_000;
        let lon_term = dlon.saturating_mul(lon_scale);
        let lat_sq = u64::try_from(lat_term.saturating_mul(lat_term)).unwrap_or(u64::MAX);
        let lon_sq = u64::try_from(lon_term.saturating_mul(lon_term)).unwrap_or(u64::MAX);
        lat_sq.saturating_add(lon_sq)
    }
}

impl Relation for GeoRangeRelationV1 {
    type Instance = GeoRangeCircuitInstance;
    type Witness = GeoRangeWitness;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        let mut out = Vec::new();
        out.extend(
            instance
                .center_lat_e6
                .to_le_bytes()
                .iter()
                .flat_map(AssignedByte::<F>::as_public_input),
        );
        out.extend(
            instance
                .center_lon_e6
                .to_le_bytes()
                .iter()
                .flat_map(AssignedByte::<F>::as_public_input),
        );
        out.extend(
            instance
                .radius_meters
                .to_le_bytes()
                .iter()
                .flat_map(AssignedByte::<F>::as_public_input),
        );
        out.push(F::from(instance.inside_range as u64));
        out.push(F::from(instance.lon_scale as u64));
        out.push(F::from(instance.bound_sq));
        Ok(out)
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let center_lat = instance.map(|i| i.center_lat_e6);
        let center_lon = instance.map(|i| i.center_lon_e6);
        let radius = instance.map(|i| i.radius_meters);
        let inside = instance.map(|i| F::from(i.inside_range as u64));
        let lon_scale = instance.map(|i| F::from(i.lon_scale as u64));
        let bound_sq = instance.map(|i| F::from(i.bound_sq));

        assign_public_bytes(std_lib, layouter, center_lat.map(i32_to_le_bytes))?;
        assign_public_bytes(std_lib, layouter, center_lon.map(i32_to_le_bytes))?;
        assign_public_bytes(std_lib, layouter, radius.map(u32_to_le_bytes))?;

        let inside_flag = assign_public_scalar(std_lib, layouter, inside)?;
        let lon_scale_a = assign_public_scalar(std_lib, layouter, lon_scale)?;
        let bound_sq_a = assign_public_scalar(std_lib, layouter, bound_sq)?;

        let actual_lat = witness.map(|w| w.actual_lat_e6);
        let actual_lon = witness.map(|w| w.actual_lon_e6);

        let c_lat = std_lib.assign(layouter, center_lat.map(i32_to_field))?;
        let c_lon = std_lib.assign(layouter, center_lon.map(i32_to_field))?;
        let a_lat = std_lib.assign(layouter, actual_lat.map(i32_to_field))?;
        let a_lon = std_lib.assign(layouter, actual_lon.map(i32_to_field))?;

        let dlat = std_lib.sub(layouter, &a_lat, &c_lat)?;
        let dlon = std_lib.sub(layouter, &a_lon, &c_lon)?;

        let lat_term = mul_i64(std_lib, layouter, &dlat, METERS_PER_DEGREE_LAT)?;
        let lon_term = mul_i64_by_native(std_lib, layouter, &dlon, &lon_scale_a)?;
        let lat_sq = std_lib.mul(layouter, &lat_term, &lat_term, None)?;
        let lon_sq = std_lib.mul(layouter, &lon_term, &lon_term, None)?;
        let dist_sq = std_lib.add(layouter, &lat_sq, &lon_sq)?;

        let is_inside = std_lib.lower_than(layouter, &dist_sq, &bound_sq_a, 64)?;
        std_lib.assert_true(layouter, &is_inside)?;

        let one = std_lib.assign_fixed(layouter, F::ONE)?;
        std_lib.assert_equal(layouter, &inside_flag, &one)?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            nr_pow2range_cols: 4,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.used_chips().write(writer)
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _ = ZkStdLibArch::read(reader)?;
        Ok(Self)
    }
}

fn mul_i64(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
    scalar: i64,
) -> Result<AssignedNative<F>, Error> {
    let s = std_lib.assign_fixed(layouter, F::from(scalar as u64))?;
    std_lib.mul(layouter, x, &s, None)
}

fn i32_to_le_bytes(x: i32) -> [u8; 4] {
    x.to_le_bytes()
}

fn u32_to_le_bytes(x: u32) -> [u8; 4] {
    x.to_le_bytes()
}

fn i32_to_field(x: i32) -> F {
    F::from(x as i64 as u64)
}

fn mul_i64_by_native(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
    scalar: &AssignedNative<F>,
) -> Result<AssignedNative<F>, Error> {
    std_lib.mul(layouter, x, scalar, None)
}
