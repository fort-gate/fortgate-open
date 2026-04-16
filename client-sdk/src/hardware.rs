use crate::types::SecurityTier;

pub struct HardwareSensor;

impl HardwareSensor {
    /// Detecta el nivel de seguridad simulado.
    /// P2.2: Lógica por plataforma documentada para auditoría.
    pub fn detect_tier() -> SecurityTier {
        #[cfg(target_os = "ios")]
        { SecurityTier::Maximum } // Asumimos Secure Enclave en iOS
        
        #[cfg(target_os = "android")]
        { SecurityTier::High } // TEE por defecto en Android
        
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        { SecurityTier::Medium } // Desktop/Web es Tier 3 por defecto
    }

    pub fn calculate_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f32 {
        let r = 6371000.0;
        let d_lat = (lat2 - lat1).to_radians();
        let d_lon = (lon2 - lon1).to_radians();
        let a = (d_lat / 2.0).sin().powi(2) +
                lat1.to_radians().cos() * lat2.to_radians().cos() *
                (d_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        (r * c) as f32
    }
}
