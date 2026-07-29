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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Cada test usa un `circuit_id` propio: el caché es global al proceso y los tests
    /// comparten proceso.
    #[test]
    fn la_segunda_llamada_no_reconstruye() {
        let calls = AtomicUsize::new(0);
        let build = || -> Result<String, ()> {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("valor".to_string())
        };

        let a = key_or_init("test-reuso", KeyKind::Proving, build).unwrap();
        let b = key_or_init("test-reuso", KeyKind::Proving, build).unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1, "se reconstruyó en vez de cachear");
        assert!(Arc::ptr_eq(&a, &b), "devolvió un Arc distinto");
    }

    #[test]
    fn proving_y_verifying_son_entradas_distintas() {
        let pk = key_or_init("test-kinds", KeyKind::Proving, || {
            Ok::<_, ()>("pk".to_string())
        })
        .unwrap();
        let vk = key_or_init("test-kinds", KeyKind::Verifying, || {
            Ok::<_, ()>("vk".to_string())
        })
        .unwrap();

        assert_eq!(*pk, "pk");
        assert_eq!(*vk, "vk", "la vk pisó a la pk: las claves colisionan");
    }

    #[test]
    fn circuitos_distintos_no_colisionan() {
        let a = key_or_init("test-circuito-a", KeyKind::Proving, || {
            Ok::<_, ()>("a".to_string())
        })
        .unwrap();
        let b = key_or_init("test-circuito-b", KeyKind::Proving, || {
            Ok::<_, ()>("b".to_string())
        })
        .unwrap();

        assert_eq!(*a, "a");
        assert_eq!(*b, "b");
    }

    #[test]
    fn invalidate_fuerza_reconstruccion() {
        let calls = AtomicUsize::new(0);
        let build = || -> Result<String, ()> {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("v{n}"))
        };

        let primera = key_or_init("test-invalidacion", KeyKind::Proving, build).unwrap();
        assert_eq!(*primera, "v0");

        // Esto es lo que hace `setup_keys` al reescribir las llaves en disco.
        invalidate_circuit("test-invalidacion");

        let segunda = key_or_init("test-invalidacion", KeyKind::Proving, build).unwrap();
        assert_eq!(*segunda, "v1", "siguió sirviendo la llave anterior tras invalidar");
    }

    #[test]
    fn invalidate_solo_afecta_a_su_circuito() {
        key_or_init("test-inv-objetivo", KeyKind::Proving, || {
            Ok::<_, ()>("objetivo".to_string())
        })
        .unwrap();
        let calls = AtomicUsize::new(0);
        let build_vecino = || -> Result<String, ()> {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("vecino".to_string())
        };
        key_or_init("test-inv-vecino", KeyKind::Proving, build_vecino).unwrap();

        invalidate_circuit("test-inv-objetivo");

        key_or_init("test-inv-vecino", KeyKind::Proving, build_vecino).unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "invalidar un circuito tiró también la entrada de otro"
        );
    }

    #[test]
    fn el_error_no_se_cachea() {
        let calls = AtomicUsize::new(0);
        let build_falla = || -> Result<String, &'static str> {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("falló la lectura")
        };

        assert!(key_or_init("test-error", KeyKind::Proving, build_falla).is_err());
        assert!(key_or_init("test-error", KeyKind::Proving, build_falla).is_err());

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "un fallo transitorio quedó cacheado como permanente"
        );
    }

    /// El lock se suelta mientras se construye, así que varios hilos pueden entrar a la
    /// vez. Se acepta que se duplique trabajo; lo que no se acepta es corromper nada ni
    /// que dos hilos se lleven valores distintos.
    #[test]
    fn acceso_concurrente_converge_a_un_solo_valor() {
        const HILOS: usize = 16;
        let valores: Vec<Arc<String>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..HILOS)
                .map(|_| {
                    s.spawn(|| {
                        key_or_init("test-concurrencia", KeyKind::Proving, || {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                            Ok::<_, ()>("compartido".to_string())
                        })
                        .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        for v in &valores {
            assert_eq!(**v, "compartido");
        }
        // Tras la carrera inicial el caché queda estabilizado en una única instancia.
        let posterior = key_or_init(
            "test-concurrencia",
            KeyKind::Proving,
            || -> Result<String, ()> { panic!("no debería reconstruir: el caché ya está poblado") },
        )
        .unwrap();
        assert_eq!(*posterior, "compartido");
    }

    #[test]
    fn el_srs_se_indexa_por_k() {
        let k16 = srs_or_init(16, || Ok::<_, ()>("srs-16".to_string())).unwrap();
        let k9 = srs_or_init(9, || Ok::<_, ()>("srs-9".to_string())).unwrap();

        assert_eq!(*k16, "srs-16");
        assert_eq!(*k9, "srs-9", "circuitos con distinto k compartieron SRS");

        let k16_otra_vez =
            srs_or_init(16, || -> Result<String, ()> { panic!("debería estar cacheado") }).unwrap();
        assert!(Arc::ptr_eq(&k16, &k16_otra_vez));
    }
}
