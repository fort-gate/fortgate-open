//! Caché en memoria de artefactos pesados de proving (SRS, pk, vk).
//!
//! Cada `prove()`/`verify()` recargaba el SRS Filecoin y las llaves desde disco. En
//! `prove_all` eso se paga tres veces y representa ~44% del wall-clock de la prueba.
//!
//! El caché es global al proceso (no por instancia de provider) porque el código
//! construye providers nuevos en cada llamada, p. ej. `MidnightHwTrustProvider::new()`
//! dentro de `demo_runner`. Un caché por instancia no se reutilizaría nunca.
//!
//! Los valores se guardan tras un `OnceLock<Mutex<..>>`; las llaves se indexan por
//! `circuit_id` y el SRS por su `k`. Como el tipo de `MidnightPK<R>` depende de la
//! relation, se almacena con borrado de tipo (`Any`) y se recupera con `downcast`.
//! El `downcast` no puede fallar en la práctica: un `circuit_id` siempre corresponde
//! a la misma relation, pero si fallara se recalcula en vez de entrar en pánico.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// `k` óptimo por relation, memoizado.
///
/// `optimal_k` no lee disco pero tampoco es barato: prueba `k` de 9 a 25 y en cada paso
/// sintetiza el circuito entero vía `cost_model`. Se llamaba en cada `prove()` y en cada
/// `verify()`, antes incluso de consultar el caché de SRS. Para una relation dada el
/// resultado es constante, así que basta calcularlo una vez.
pub fn optimal_k_cached<R: midnight_zk_stdlib::Relation + 'static>(relation: &R) -> u32 {
    static CACHE: OnceLock<Mutex<HashMap<TypeId, u32>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let id = TypeId::of::<R>();

    if let Some(k) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&id) {
        return *k;
    }
    let k = midnight_zk_stdlib::optimal_k(relation);
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, k);
    k
}

type AnyArc = Arc<dyn Any + Send + Sync>;

fn srs_cache() -> &'static Mutex<HashMap<u32, AnyArc>> {
    static CACHE: OnceLock<Mutex<HashMap<u32, AnyArc>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key_cache() -> &'static Mutex<HashMap<(&'static str, KeyKind), AnyArc>> {
    static CACHE: OnceLock<Mutex<HashMap<(&'static str, KeyKind), AnyArc>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Proving,
    Verifying,
}

/// Devuelve el valor cacheado para `k`, o lo construye con `build` y lo guarda.
pub fn srs_or_init<T, E>(k: u32, build: impl FnOnce() -> Result<T, E>) -> Result<Arc<T>, E>
where
    T: Send + Sync + 'static,
{
    get_or_init(srs_cache(), k, build)
}

/// Igual que [`srs_or_init`] pero indexado por `(circuit_id, tipo de llave)`.
pub fn key_or_init<T, E>(
    circuit_id: &'static str,
    kind: KeyKind,
    build: impl FnOnce() -> Result<T, E>,
) -> Result<Arc<T>, E>
where
    T: Send + Sync + 'static,
{
    get_or_init(key_cache(), (circuit_id, kind), build)
}

/// Descarta las llaves cacheadas de un circuito.
///
/// `setup_keys` reescribe vk/pk en disco, así que hay que soltar lo cacheado para no
/// seguir usando una llave anterior. En la práctica el setup es determinista y produce
/// la misma llave, pero depender de eso sería frágil.
pub fn invalidate_circuit(circuit_id: &str) {
    key_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(id, _), _| *id != circuit_id);
}

fn get_or_init<K, T, E>(
    cache: &'static Mutex<HashMap<K, AnyArc>>,
    key: K,
    build: impl FnOnce() -> Result<T, E>,
) -> Result<Arc<T>, E>
where
    K: std::hash::Hash + Eq,
    T: Send + Sync + 'static,
{
    // El lock se suelta antes de construir: `build` puede tardar segundos (leer el SRS)
    // y no queremos bloquear a otros hilos que piden una entrada distinta. El costo es
    // que dos hilos pueden construir la misma entrada a la vez; sale una de las dos y el
    // resultado es idéntico, así que solo se desperdicia trabajo, nunca se corrompe.
    if let Some(hit) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .and_then(|v| v.clone().downcast::<T>().ok())
    {
        return Ok(hit);
    }

    let value = Arc::new(build()?);
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, value.clone() as AnyArc);
    Ok(value)
}
