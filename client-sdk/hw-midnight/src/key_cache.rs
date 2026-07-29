//! In-memory cache for the heavy proving artifacts (SRS, pk, vk).
//!
//! Every `prove()`/`verify()` used to reload the Filecoin SRS and the keys from disk. In
//! `prove_all` that cost is paid three times and accounts for ~44% of the proof wall-clock.
//!
//! The cache is process-global (not per provider instance) because the calling code builds
//! a new provider on every call, e.g. `MidnightHwTrustProvider::new()` inside
//! `demo_runner`. A per-instance cache would never be reused.
//!
//! Values are kept behind a `OnceLock<Mutex<..>>`; keys are indexed by `circuit_id` and
//! the SRS by its `k`. Since the type of `MidnightPK<R>` depends on the relation, values
//! are stored type-erased (`Any`) and recovered with `downcast`. The `downcast` cannot
//! fail in practice — a given `circuit_id` always maps to the same relation — but if it
//! ever did, the value is recomputed instead of panicking.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Optimal `k` per relation, memoized.
///
/// `optimal_k` does not read from disk, but it is not cheap either: it tries `k` from 9 to
/// 25 and synthesizes the whole circuit through `cost_model` at every step. It was called
/// on every `prove()` and every `verify()`, even before consulting the SRS cache. For a
/// given relation the result is constant, so computing it once is enough.
///
/// The cache key is the relation's `TypeId`, which assumes `k` is a property of the type
/// and not of the instance. That holds for the three relations of the PoC, all of them
/// unit structs; a relation carrying fields that change the circuit size would need a
/// different key.
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

/// Returns the cached value for `k`, or builds it with `build` and stores it.
pub fn srs_or_init<T, E>(k: u32, build: impl FnOnce() -> Result<T, E>) -> Result<Arc<T>, E>
where
    T: Send + Sync + 'static,
{
    get_or_init(srs_cache(), k, build)
}

/// Same as [`srs_or_init`], but indexed by `(circuit_id, key kind)`.
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

/// Drops the cached keys of a circuit.
///
/// `setup_keys` rewrites vk/pk on disk, so the cached values have to be released to avoid
/// keeping a previous key in use. In practice the setup is deterministic and produces the
/// same key, but relying on that would be fragile.
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
    // The lock is released before building: `build` can take seconds (reading the SRS) and
    // we do not want to block other threads asking for a different entry. The cost is that
    // two threads may build the same entry at once; one of the two wins and the result is
    // identical, so the only downside is wasted work, never corruption.
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
