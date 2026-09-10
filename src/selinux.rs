//! Optional SELinux AVC reasoning.
//!
//! The public API is safe Rust. All libselinux/libsepol state is owned by the
//! C shim and represented here by one opaque handle. The analyzer is !Send and
//! !Sync because libsepol's service API uses process-global policydb/sidtab state.

use linux_audit_parser::{Body, MessageType, Value};
use crate::types::{Event, EventValues};

#[cfg(not(feature = "selinux"))]
pub struct Runtime;

#[cfg(not(feature = "selinux"))]
impl Runtime {
    pub fn new(enabled: bool) -> Self {
        if enabled {
            log::warn!(
                "SELinux WHY enrichment requested, but Laurel was built without the 'selinux' feature"
            );
        }
        Runtime
    }

    pub fn process(&mut self, _event: &mut Event<'_>) {}
}

#[cfg(feature = "selinux")]
mod enabled {
    #![deny(unsafe_op_in_unsafe_fn)]

    use std::ffi::CString;
    use std::marker::PhantomData;
    use std::os::raw::{c_char, c_int};
    use std::ptr::{self, NonNull};
    use std::rc::Rc;
    use std::slice;

    use indexmap::IndexMap;
    use thiserror::Error;

    use super::*;

    const CACHE_ENTRIES: usize = 1024;

    mod ffi {
        use super::{c_char, c_int};

        #[repr(C)]
        pub struct LaurelSelinux {
            _private: [u8; 0],
        }

        #[repr(C)]
        pub struct NativeResult {
            pub reason: c_int,
            pub detail: *const c_char,
            pub detail_len: usize,
        }

        pub const OK: c_int = 0;
        pub const DISABLED: c_int = 1;
        pub const BUSY: c_int = 2;
        pub const INVALID_ARGUMENT: c_int = 3;
        pub const NOMEM: c_int = 4;
        pub const POLICY_ERROR: c_int = 5;
        pub const BAD_SCON: c_int = 6;
        pub const BAD_TCON: c_int = 7;
        pub const BAD_CLASS: c_int = 8;
        pub const BAD_PERMISSION: c_int = 9;
        pub const COMPUTE_ERROR: c_int = 10;

        pub const ALLOW: c_int = 0;
        pub const DONTAUDIT: c_int = 1;
        pub const TERULE: c_int = 2;
        pub const BOOLEAN: c_int = 3;
        pub const CONSTRAINT: c_int = 4;
        pub const RBAC: c_int = 5;
        pub const BOUNDS: c_int = 6;

        extern "C" {
            pub fn laurel_selinux_open(out: *mut *mut LaurelSelinux) -> c_int;
            pub fn laurel_selinux_policy_changed(
                ctx: *mut LaurelSelinux,
                changed: *mut c_int,
            ) -> c_int;
            pub fn laurel_selinux_analyze(
                ctx: *mut LaurelSelinux,
                scontext: *const c_char,
                tcontext: *const c_char,
                tclass: *const c_char,
                permissions: *const *const c_char,
                permission_count: usize,
                out: *mut NativeResult,
            ) -> c_int;
            pub fn laurel_selinux_close(ctx: *mut LaurelSelinux);
        }
    }

    #[derive(Debug, Error)]
    enum SelinuxError {
        #[error("another SELinux analyzer is already active")]
        Busy,
        #[error("invalid argument passed to SELinux analyzer")]
        InvalidArgument,
        #[error("SELinux analyzer ran out of memory")]
        OutOfMemory,
        #[error("unable to load or inspect the active SELinux policy")]
        Policy,
        #[error("invalid SELinux source context")]
        BadSourceContext,
        #[error("invalid SELinux target context")]
        BadTargetContext,
        #[error("unknown SELinux object class")]
        BadClass,
        #[error("unknown SELinux permission")]
        BadPermission,
        #[error("SELinux access-vector computation failed")]
        Compute,
        #[error("SELinux field contains an interior NUL byte")]
        InteriorNul,
        #[error("SELinux shim returned an invalid result")]
        InvalidNativeResult,
        #[error("SELinux shim returned unknown status {0}")]
        UnknownStatus(i32),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WhyReason {
        Allow,
        DontAudit,
        TeRule,
        Boolean,
        Constraint,
        Rbac,
        Bounds,
    }

    impl WhyReason {
        fn from_native(value: c_int) -> Result<Self, SelinuxError> {
            match value {
                ffi::ALLOW => Ok(Self::Allow),
                ffi::DONTAUDIT => Ok(Self::DontAudit),
                ffi::TERULE => Ok(Self::TeRule),
                ffi::BOOLEAN => Ok(Self::Boolean),
                ffi::CONSTRAINT => Ok(Self::Constraint),
                ffi::RBAC => Ok(Self::Rbac),
                ffi::BOUNDS => Ok(Self::Bounds),
                _ => Err(SelinuxError::InvalidNativeResult),
            }
        }

        fn as_str(self) -> &'static str {
            match self {
                Self::Allow => "ALLOW",
                Self::DontAudit => "DONTAUDIT",
                Self::TeRule => "TERULE",
                Self::Boolean => "BOOLEAN",
                Self::Constraint => "CONSTRAINT",
                Self::Rbac => "RBAC",
                Self::Bounds => "BOUNDS",
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WhyResult {
        reason: WhyReason,
        detail: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    struct AvcQuery {
        scontext: Vec<u8>,
        tcontext: Vec<u8>,
        tclass: Vec<u8>,
        permissions: Vec<Vec<u8>>,
    }

    fn value_bytes(value: &Value<'_>) -> Option<Vec<u8>> {
        value.clone().try_into().ok()
    }

    fn extract_query(body: &Body<'_>) -> Option<AvcQuery> {
        let scontext = value_bytes(body.get("scontext")?)?;
        let tcontext = value_bytes(body.get("tcontext")?)?;
        let tclass = value_bytes(body.get("tclass")?)?;

        let denied = body.get("denied")?;
        let mut permissions = match denied {
            Value::List(values) => values.iter().filter_map(value_bytes).collect::<Vec<_>>(),
            value => vec![value_bytes(value)?],
        };

        permissions.retain(|p| !p.is_empty());
        permissions.sort();
        permissions.dedup();
        if permissions.is_empty() {
            return None;
        }

        Some(AvcQuery {
            scontext,
            tcontext,
            tclass,
            permissions,
        })
    }

    struct DecisionCache {
        entries: IndexMap<AvcQuery, WhyResult>,
    }

    impl DecisionCache {
        fn new() -> Self {
            Self { entries: IndexMap::new() }
        }

        fn get(&mut self, key: &AvcQuery) -> Option<WhyResult> {
            let idx = self.entries.get_index_of(key)?;
            let (key, value) = self.entries.shift_remove_index(idx)?;
            let result = value.clone();
            self.entries.insert(key, value);
            Some(result)
        }

        fn insert(&mut self, key: AvcQuery, value: WhyResult) {
            if let Some(idx) = self.entries.get_index_of(&key) {
                self.entries.shift_remove_index(idx);
            } else if self.entries.len() >= CACHE_ENTRIES {
                self.entries.shift_remove_index(0);
            }
            self.entries.insert(key, value);
        }
    }

    struct Analyzer {
        handle: NonNull<ffi::LaurelSelinux>,
        cache: DecisionCache,
        _not_send_sync: PhantomData<Rc<()>>,
    }

    impl Analyzer {
        fn open() -> Result<Option<Self>, SelinuxError> {
            let mut raw = ptr::null_mut();

            // SAFETY: `raw` is writable output storage; the shim does not retain
            // its address, and a successful handle is exclusively owned here.
            let status = unsafe { ffi::laurel_selinux_open(&mut raw) };
            if status == ffi::DISABLED {
                return Ok(None);
            }
            if status != ffi::OK {
                return Err(status_error(status));
            }

            let handle = NonNull::new(raw).ok_or(SelinuxError::InvalidNativeResult)?;
            Ok(Some(Self {
                handle,
                cache: DecisionCache::new(),
                _not_send_sync: PhantomData,
            }))
        }

        fn policy_changed(&mut self) -> Result<bool, SelinuxError> {
            let mut changed = -1;
            // SAFETY: handle is the unique live shim handle and `changed` is
            // writable for the duration of the call.
            let status = unsafe {
                ffi::laurel_selinux_policy_changed(self.handle.as_ptr(), &mut changed)
            };
            if status != ffi::OK {
                return Err(status_error(status));
            }
            match changed {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(SelinuxError::InvalidNativeResult),
            }
        }

        fn analyze(&mut self, query: &AvcQuery) -> Result<WhyResult, SelinuxError> {
            if let Some(result) = self.cache.get(query) {
                return Ok(result);
            }

            let scontext = CString::new(query.scontext.as_slice())
                .map_err(|_| SelinuxError::InteriorNul)?;
            let tcontext = CString::new(query.tcontext.as_slice())
                .map_err(|_| SelinuxError::InteriorNul)?;
            let tclass = CString::new(query.tclass.as_slice())
                .map_err(|_| SelinuxError::InteriorNul)?;
            let permissions = query.permissions.iter()
                .map(|p| CString::new(p.as_slice()).map_err(|_| SelinuxError::InteriorNul))
                .collect::<Result<Vec<_>, _>>()?;
            let permission_ptrs = permissions.iter().map(|p| p.as_ptr()).collect::<Vec<_>>();

            let mut native = ffi::NativeResult {
                reason: -1,
                detail: ptr::null(),
                detail_len: 0,
            };

            // SAFETY: all input CStrings and pointer arrays remain alive for the
            // call; the shim retains none of them. `native` is writable output.
            let status = unsafe {
                ffi::laurel_selinux_analyze(
                    self.handle.as_ptr(),
                    scontext.as_ptr(),
                    tcontext.as_ptr(),
                    tclass.as_ptr(),
                    permission_ptrs.as_ptr(),
                    permission_ptrs.len(),
                    &mut native,
                )
            };
            if status != ffi::OK {
                return Err(status_error(status));
            }

            let reason = WhyReason::from_native(native.reason)?;
            let detail = if native.detail_len == 0 {
                None
            } else {
                if native.detail.is_null() {
                    return Err(SelinuxError::InvalidNativeResult);
                }
                // SAFETY: on success the shim guarantees this many initialized
                // bytes until the next analyze/close call. Copy immediately.
                let bytes = unsafe {
                    slice::from_raw_parts(native.detail.cast::<u8>(), native.detail_len)
                };
                Some(bytes.to_vec())
            };

            let result = WhyResult { reason, detail };
            self.cache.insert(query.clone(), result.clone());
            Ok(result)
        }
    }

    impl Drop for Analyzer {
        fn drop(&mut self) {
            // SAFETY: this object exclusively owns the handle and closes it once.
            unsafe { ffi::laurel_selinux_close(self.handle.as_ptr()) };
        }
    }

    fn status_error(status: c_int) -> SelinuxError {
        match status {
            ffi::BUSY => SelinuxError::Busy,
            ffi::INVALID_ARGUMENT => SelinuxError::InvalidArgument,
            ffi::NOMEM => SelinuxError::OutOfMemory,
            ffi::POLICY_ERROR => SelinuxError::Policy,
            ffi::BAD_SCON => SelinuxError::BadSourceContext,
            ffi::BAD_TCON => SelinuxError::BadTargetContext,
            ffi::BAD_CLASS => SelinuxError::BadClass,
            ffi::BAD_PERMISSION => SelinuxError::BadPermission,
            ffi::COMPUTE_ERROR => SelinuxError::Compute,
            other => SelinuxError::UnknownStatus(other),
        }
    }

    fn attach_result(body: &mut Body<'_>, result: &WhyResult) {
        body.retain(|(key, _)| key != "SELINUX_WHY" && key != "SELINUX_WHY_DETAIL");
        body.push(("SELINUX_WHY".into(), result.reason.as_str().into()));
        if let Some(detail) = &result.detail {
            body.push((
                "SELINUX_WHY_DETAIL".into(),
                String::from_utf8_lossy(detail).into_owned().into(),
            ));
        }
    }

    fn enrich_values(analyzer: &mut Analyzer, values: &mut EventValues<'_>) {
        let bodies: &mut [Body<'_>] = match values {
            EventValues::Single(body) => std::slice::from_mut(body),
            EventValues::Multi(bodies) => bodies.as_mut_slice(),
        };

        for body in bodies {
            // AppArmor also emits type=AVC. Require SELinux-specific policy
            // fields before invoking libsepol.
            let Some(query) = extract_query(body) else { continue };
            match analyzer.analyze(&query) {
                Ok(result) => attach_result(body, &result),
                Err(error) => log::warn!("SELinux AVC reasoning failed: {error}"),
            }
        }
    }

    pub struct Runtime {
        requested: bool,
        analyzer: Option<Analyzer>,
    }

    impl Runtime {
        pub fn new(requested: bool) -> Self {
            let mut runtime = Self { requested, analyzer: None };
            if requested {
                runtime.reload();
            }
            runtime
        }

        fn reload(&mut self) {
            self.analyzer = None;
            match Analyzer::open() {
                Ok(Some(analyzer)) => {
                    log::info!("SELinux WHY analyzer initialized");
                    self.analyzer = Some(analyzer);
                }
                Ok(None) => log::warn!(
                    "SELinux WHY enrichment requested, but SELinux is not enabled; continuing without it"
                ),
                Err(error) => log::warn!(
                    "SELinux WHY analyzer unavailable ({error}); continuing normal Laurel processing"
                ),
            }
        }

        pub fn process(&mut self, event: &mut Event<'_>) {
            if !self.requested || event.is_filtered {
                return;
            }

            if !event.body.contains_key(&MessageType::AVC)
                && !event.body.contains_key(&MessageType::USER_AVC)
            {
                return;
            }

            let changed = match self.analyzer.as_mut() {
                Some(analyzer) => match analyzer.policy_changed() {
                    Ok(changed) => changed,
                    Err(error) => {
                        log::warn!("Unable to check SELinux policy generation ({error}); reloading analyzer");
                        true
                    }
                },
                None => false,
            };
            if changed {
                self.reload();
            }

            let Some(analyzer) = self.analyzer.as_mut() else { return };
            if let Some(values) = event.body.get_mut(&MessageType::AVC) {
                enrich_values(analyzer, values);
            }
            if let Some(values) = event.body.get_mut(&MessageType::USER_AVC) {
                enrich_values(analyzer, values);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn selinux_body() -> Body<'static> {
            let mut body = Body::default();
            body.push(("scontext".into(), "system_u:system_r:httpd_t:s0".into()));
            body.push(("tcontext".into(), "system_u:object_r:http_port_t:s0".into()));
            body.push(("tclass".into(), "tcp_socket".into()));
            body.push((
                "denied".into(),
                Value::List(vec!["name_connect".into(), "read".into()]),
            ));
            body
        }

        #[test]
        fn extracts_and_normalizes_selinux_avc() {
            let query = extract_query(&selinux_body()).expect("SELinux AVC");
            assert_eq!(query.tclass, b"tcp_socket");
            assert_eq!(
                query.permissions,
                vec![b"name_connect".to_vec(), b"read".to_vec()]
            );
        }

        #[test]
        fn rejects_apparmor_avc() {
            let mut body = Body::default();
            body.push(("apparmor".into(), "STATUS".into()));
            body.push(("operation".into(), "profile_replace".into()));
            assert!(extract_query(&body).is_none());
        }
    }
}

#[cfg(feature = "selinux")]
pub use enabled::Runtime;
