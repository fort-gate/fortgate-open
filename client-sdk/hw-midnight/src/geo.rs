//! Georango: Haversine off-circuit y límites para el circuito ZK.

use crate::error::HwMidnightError;

pub const MAX_RADIUS_METERS: u32 = 200;
pub const METERS_PER_DEGREE_LAT: i64 = 111_320;

/// Lat/lon en grados → microgrados (×10⁶).
pub fn deg_to_e6(deg: f64) -> i32 {
    (deg * 1_000_000.0).round() as i32
}

pub fn e6_to_deg(e6: i32) -> f64 {
    f64::from(e6) / 1_000_000.0
}

/// Distancia Haversine en metros (off-circuit, referencia para witness).
pub fn haversine_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    R * c
}

/// `cos(center_lat)` × 10⁶ para escalar longitud en el circuito entero.
pub fn cos_lat_million(center_lat_deg: f64) -> i64 {
    (center_lat_deg.to_radians().cos() * 1_000_000.0).round() as i64
}

pub fn lon_meters_per_e6(center_lat_deg: f64) -> i64 {
    METERS_PER_DEGREE_LAT * cos_lat_million(center_lat_deg) / 1_000_000
}

/// Valida coords; devuelve distancia si está dentro del radio.
pub fn validate_inside_range(
    center_lat: f64,
    center_lon: f64,
    actual_lat: f64,
    actual_lon: f64,
    radius_meters: u32,
) -> Result<f64, HwMidnightError> {
    if radius_meters > MAX_RADIUS_METERS {
        return Err(HwMidnightError::Geo(format!(
            "radio {radius_meters}m excede máximo {MAX_RADIUS_METERS}m"
        )));
    }
    let dist = haversine_meters(center_lat, center_lon, actual_lat, actual_lon);
    if dist > f64::from(radius_meters) {
        return Err(HwMidnightError::Geo(format!(
            "fuera de rango: {dist:.1}m > {radius_meters}m"
        )));
    }
    Ok(dist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdmx_nearby_inside_200m() {
        let dist = haversine_meters(19.4320, -99.1330, 19.4326, -99.1332);
        assert!(dist < 200.0);
        validate_inside_range(19.4320, -99.1330, 19.4326, -99.1332, 200).unwrap();
    }

    #[test]
    fn far_point_rejected() {
        assert!(validate_inside_range(19.4320, -99.1330, 19.4400, -99.1332, 200).is_err());
    }
}
