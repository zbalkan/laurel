//! Optional SELinux AVC reasoning.
//!
//! The public API is safe Rust. All libselinux/libsepol state is owned by the
//! C shim and represented here by one opaque handle. The analyzer is !Send and
//! !Sync because libsepol's service API uses process-global policydb/sidtab state.

use crate::types::Event;

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

    pub fn process(&mut self, _event: &mut Event<'_>, _prefix: Option<&str>) {}
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
    use linux_audit_parser::{Body, Key, MessageType, Value};
    use thiserror::Error;

    use crate::types::EventValues;

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
        pub const RELOAD_REQUIRED: c_int = 11;

        pub const ALLOW: c_int = 0;
        pub const DONTAUDIT: c_int = 1;
        pub const TERULE: c_int = 2;
        pub const BOOLEAN: c_int = 3;
        pub const CONSTRAINT: c_int = 4;
        pub const RBAC: c_int = 5;
        pub const BOUNDS: c_int = 6;

        extern "C" {
            pub fn laurel_selinux_open(out: *mut *mut LaurelSelinux) -> c_int;
            pub fn laurel_selinux_open_policy(
                out: *mut *mut LaurelSelinux,
                policy_path: *const c_char,
            ) -> c_int;
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
        #[error("SELinux analyzer must be reconstructed before further use")]
        ReloadRequired,
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

        #[cfg(test)]
        fn native_code(self) -> i32 {
            match self {
                Self::Allow => ffi::ALLOW,
                Self::DontAudit => ffi::DONTAUDIT,
                Self::TeRule => ffi::TERULE,
                Self::Boolean => ffi::BOOLEAN,
                Self::Constraint => ffi::CONSTRAINT,
                Self::Rbac => ffi::RBAC,
                Self::Bounds => ffi::BOUNDS,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct BooleanChange {
        name: Vec<u8>,
        value: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WhyResult {
        reason: WhyReason,
        detail: Option<Vec<u8>>,
        booleans: Vec<BooleanChange>,
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

    fn parse_boolean_detail(detail: &[u8]) -> Result<Vec<BooleanChange>, SelinuxError> {
        if detail.is_empty() {
            return Err(SelinuxError::InvalidNativeResult);
        }

        detail
            .split(|b| *b == b',')
            .map(|entry| {
                let Some(eq) = entry.iter().position(|b| *b == b'=') else {
                    return Err(SelinuxError::InvalidNativeResult);
                };
                let name = &entry[..eq];
                let value = &entry[eq + 1..];
                if name.is_empty() {
                    return Err(SelinuxError::InvalidNativeResult);
                }
                let value = match value {
                    b"0" => false,
                    b"1" => true,
                    _ => return Err(SelinuxError::InvalidNativeResult),
                };
                Ok(BooleanChange {
                    name: name.to_vec(),
                    value,
                })
            })
            .collect()
    }

    struct DecisionCache {
        entries: IndexMap<AvcQuery, WhyResult>,
    }

    impl DecisionCache {
        fn new() -> Self {
            Self {
                entries: IndexMap::new(),
            }
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
        fn from_open(status: c_int, raw: *mut ffi::LaurelSelinux) -> Result<Option<Self>, SelinuxError> {
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

        fn open() -> Result<Option<Self>, SelinuxError> {
            let mut raw = ptr::null_mut();

            // SAFETY: `raw` is writable output storage; the shim does not retain
            // its address, and a successful handle is exclusively owned here.
            let status = unsafe { ffi::laurel_selinux_open(&mut raw) };
            Self::from_open(status, raw)
        }

        #[cfg(test)]
        fn open_policy(path: &std::path::Path) -> Result<Self, SelinuxError> {
            use std::os::unix::ffi::OsStrExt;

            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| SelinuxError::InteriorNul)?;
            let mut raw = ptr::null_mut();

            // SAFETY: `raw` is writable output storage and `path` is a valid
            // NUL-terminated string that remains alive for the call. The shim
            // does not retain either pointer.
            let status = unsafe { ffi::laurel_selinux_open_policy(&mut raw, path.as_ptr()) };
            Self::from_open(status, raw)?.ok_or(SelinuxError::Policy)
        }

        fn policy_changed(&mut self) -> Result<bool, SelinuxError> {
            let mut changed = -1;
            // SAFETY: handle is the unique live shim handle and `changed` is
            // writable for the duration of the call.
            let status =
                unsafe { ffi::laurel_selinux_policy_changed(self.handle.as_ptr(), &mut changed) };
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
            let tclass =
                CString::new(query.tclass.as_slice()).map_err(|_| SelinuxError::InteriorNul)?;
            let permissions = query
                .permissions
                .iter()
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
            let native_detail = if native.detail_len == 0 {
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

            let (detail, booleans) = if reason == WhyReason::Boolean {
                let booleans = parse_boolean_detail(
                    native_detail
                        .as_deref()
                        .ok_or(SelinuxError::InvalidNativeResult)?,
                )?;
                (None, booleans)
            } else {
                (native_detail, Vec::new())
            };

            let result = WhyResult {
                reason,
                detail,
                booleans,
            };
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
            ffi::RELOAD_REQUIRED => SelinuxError::ReloadRequired,
            other => SelinuxError::UnknownStatus(other),
        }
    }

    fn enrichment_key(prefix: Option<&str>, suffix: &'static str, unprefixed: &'static str) -> Key {
        match prefix {
            Some(prefix) => format!("{prefix}{suffix}")
                .parse()
                .expect("audit field key parsing is infallible"),
            None => Key::Literal(unprefixed),
        }
    }

    fn attach_result(body: &mut Body<'_>, result: &WhyResult, prefix: Option<&str>) {
        let why_key = enrichment_key(prefix, "selinux_why", "SELINUX_WHY");
        let detail_key = enrichment_key(prefix, "selinux_why_detail", "SELINUX_WHY_DETAIL");
        let booleans_key =
            enrichment_key(prefix, "selinux_why_booleans", "SELINUX_WHY_BOOLEANS");

        body.retain(|(key, _)| key != &why_key && key != &detail_key && key != &booleans_key);
        body.push((why_key, result.reason.as_str().into()));

        if !result.booleans.is_empty() {
            let booleans = result
                .booleans
                .iter()
                .map(|change| {
                    Value::Map(vec![
                        (Key::Literal("name"), Value::from(change.name.clone())),
                        (
                            Key::Literal("value"),
                            Value::from(if change.value { 1_i64 } else { 0_i64 }),
                        ),
                    ])
                })
                .collect();
            body.push((booleans_key, Value::List(booleans)));
        }

        if let Some(detail) = &result.detail {
            body.push((detail_key, Value::from(detail.clone())));
        }
    }

    fn enrich_values(
        analyzer: &mut Analyzer,
        values: &mut EventValues<'_>,
        prefix: Option<&str>,
    ) -> bool {
        let bodies: &mut [Body<'_>] = match values {
            EventValues::Single(body) => std::slice::from_mut(body),
            EventValues::Multi(bodies) => bodies.as_mut_slice(),
        };

        for body in bodies {
            // AppArmor also emits type=AVC. Require SELinux-specific policy
            // fields before invoking libsepol.
            let Some(query) = extract_query(body) else {
                continue;
            };
            match analyzer.analyze(&query) {
                Ok(result) => attach_result(body, &result, prefix),
                Err(SelinuxError::ReloadRequired) => return true,
                Err(error) => log::warn!("SELinux AVC reasoning failed: {error}"),
            }
        }
        false
    }

    fn enrich_event(analyzer: &mut Analyzer, event: &mut Event<'_>, prefix: Option<&str>) -> bool {
        if let Some(values) = event.body.get_mut(&MessageType::AVC) {
            if enrich_values(analyzer, values, prefix) {
                return true;
            }
        }
        if let Some(values) = event.body.get_mut(&MessageType::USER_AVC) {
            if enrich_values(analyzer, values, prefix) {
                return true;
            }
        }
        false
    }

    pub struct Runtime {
        requested: bool,
        analyzer: Option<Analyzer>,
    }

    impl Runtime {
        pub fn new(requested: bool) -> Self {
            let mut runtime = Self {
                requested,
                analyzer: None,
            };
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

        pub fn process(&mut self, event: &mut Event<'_>, prefix: Option<&str>) {
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
                        log::warn!(
                            "Unable to check SELinux policy generation ({error}); reloading analyzer"
                        );
                        true
                    }
                },
                None => false,
            };
            if changed {
                self.reload();
            }

            let reload_required = match self.analyzer.as_mut() {
                Some(analyzer) => enrich_event(analyzer, event, prefix),
                None => return,
            };

            if !reload_required {
                return;
            }

            log::warn!(
                "SELinux analyzer state became uncertain during Boolean evaluation; rebuilding it"
            );
            self.reload();

            let reload_required = match self.analyzer.as_mut() {
                Some(analyzer) => enrich_event(analyzer, event, prefix),
                None => return,
            };
            if reload_required {
                log::error!(
                    "SELinux analyzer could not restore policy state after rebuild; disabling WHY enrichment"
                );
                self.analyzer = None;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;
        use std::process::Command;

        use serde_json::Value as JsonValue;

        use super::*;

        fn selinux_body() -> Body<'static> {
            let mut body = Body::default();
            body.push(("scontext".into(), "test_u:test_r:src_t:s0".into()));
            body.push(("tcontext".into(), "test_u:test_r:dst_t:s0".into()));
            body.push(("tclass".into(), "file".into()));
            body.push((
                "denied".into(),
                Value::List(vec!["write".into(), "read".into()]),
            ));
            body
        }

        fn query(scontext: &str, tcontext: &str, permission: &str) -> AvcQuery {
            AvcQuery {
                scontext: scontext.as_bytes().to_vec(),
                tcontext: tcontext.as_bytes().to_vec(),
                tclass: b"file".to_vec(),
                permissions: vec![permission.as_bytes().to_vec()],
            }
        }

        fn upstream_audit2why(policy: &Path, query: &AvcQuery) -> (i32, JsonValue) {
            const SCRIPT: &str = r#"
import json
import sys
from selinux import audit2why

policy, scon, tcon, tclass, *perms = sys.argv[1:]
if audit2why.init(policy) != 0:
    raise SystemExit("audit2why.init failed")
try:
    reason, detail = audit2why.analyze(scon, tcon, tclass, perms)
    print(json.dumps([reason, detail]))
finally:
    audit2why.finish()
"#;

            let mut command = Command::new("python3");
            command
                .arg("-c")
                .arg(SCRIPT)
                .arg(policy)
                .arg(String::from_utf8_lossy(&query.scontext).as_ref())
                .arg(String::from_utf8_lossy(&query.tcontext).as_ref())
                .arg(String::from_utf8_lossy(&query.tclass).as_ref());
            for permission in &query.permissions {
                command.arg(String::from_utf8_lossy(permission).as_ref());
            }

            let output = command.output().expect("run upstream audit2why");
            assert!(
                output.status.success(),
                "audit2why failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let parsed: JsonValue =
                serde_json::from_slice(&output.stdout).expect("audit2why JSON output");
            let pair = parsed.as_array().expect("audit2why result pair");
            let reason = pair[0].as_i64().expect("numeric audit2why reason") as i32;
            (reason, pair[1].clone())
        }

        #[test]
        fn extracts_and_normalizes_selinux_avc() {
            let query = extract_query(&selinux_body()).expect("SELinux AVC");
            assert_eq!(query.tclass, b"file");
            assert_eq!(
                query.permissions,
                vec![b"read".to_vec(), b"write".to_vec()]
            );
        }

        #[test]
        fn rejects_apparmor_avc() {
            let mut body = Body::default();
            body.push(("apparmor".into(), "STATUS".into()));
            body.push(("operation".into(), "profile_replace".into()));
            assert!(extract_query(&body).is_none());
        }

        #[test]
        fn parses_boolean_result_as_structured_values() {
            assert_eq!(
                parse_boolean_detail(b"allow_write=1,other_switch=0").unwrap(),
                vec![
                    BooleanChange {
                        name: b"allow_write".to_vec(),
                        value: true,
                    },
                    BooleanChange {
                        name: b"other_switch".to_vec(),
                        value: false,
                    },
                ]
            );
            assert!(parse_boolean_detail(b"broken").is_err());
        }

        #[test]
        fn enrichment_honors_prefix_and_keeps_booleans_structured() {
            let mut body = Body::default();
            let result = WhyResult {
                reason: WhyReason::Boolean,
                detail: None,
                booleans: vec![BooleanChange {
                    name: b"allow_write".to_vec(),
                    value: true,
                }],
            };

            attach_result(&mut body, &result, Some("enriched_"));
            assert!(body.get("enriched_selinux_why").is_some());
            assert!(body.get("enriched_selinux_why_booleans").is_some());
            assert!(body.get("SELINUX_WHY").is_none());
            assert!(body.get("SELINUX_WHY_DETAIL").is_none());
        }

        #[test]
        fn matches_upstream_audit2why_on_test_policy() {
            let Ok(policy) = std::env::var("LAUREL_SELINUX_TEST_POLICY") else {
                eprintln!("LAUREL_SELINUX_TEST_POLICY not set; skipping differential test");
                return;
            };
            let policy = Path::new(&policy);
            let mut analyzer = Analyzer::open_policy(policy).expect("open test policy");

            let cases = [
                (
                    "allow",
                    query("test_u:test_r:src_t:s0", "test_u:test_r:src_t:s0", "getattr"),
                ),
                (
                    "te-rule",
                    query("test_u:test_r:src_t:s0", "test_u:test_r:dst_t:s0", "getattr"),
                ),
                (
                    "boolean",
                    query("test_u:test_r:src_t:s0", "test_u:test_r:dst_t:s0", "write"),
                ),
                (
                    "dontaudit",
                    query("test_u:test_r:src_t:s0", "test_u:test_r:dst_t:s0", "execute"),
                ),
                (
                    "constraint",
                    query("test_u:test_r:src_t:s0", "test_u:test_r:dst_t:s0", "read"),
                ),
            ];

            for (name, query) in cases {
                let ours = analyzer.analyze(&query).unwrap_or_else(|error| {
                    panic!("{name}: Laurel analysis failed: {error}")
                });
                let (upstream_reason, upstream_detail) = upstream_audit2why(policy, &query);
                assert_eq!(
                    ours.reason.native_code(),
                    upstream_reason,
                    "{name}: reason differs from audit2why"
                );

                if ours.reason == WhyReason::Boolean {
                    let expected = upstream_detail.as_array().expect("Boolean list");
                    let ours = ours
                        .booleans
                        .iter()
                        .map(|change| {
                            (
                                String::from_utf8_lossy(&change.name).into_owned(),
                                if change.value { 1_i64 } else { 0_i64 },
                            )
                        })
                        .collect::<Vec<_>>();
                    let expected = expected
                        .iter()
                        .map(|item| {
                            let pair = item.as_array().expect("Boolean tuple");
                            (
                                pair[0].as_str().expect("Boolean name").to_string(),
                                pair[1].as_i64().expect("Boolean value"),
                            )
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(ours, expected, "{name}: Boolean detail differs");
                } else if ours.reason == WhyReason::Constraint {
                    assert_eq!(
                        ours.detail.as_deref().map(String::from_utf8_lossy),
                        upstream_detail.as_str().map(std::borrow::Cow::Borrowed),
                        "{name}: constraint detail differs"
                    );
                }
            }

            assert!(matches!(
                analyzer.analyze(&query(
                    "test_u:test_r:src_t:s0",
                    "test_u:test_r:dst_t:s0",
                    "does_not_exist"
                )),
                Err(SelinuxError::BadPermission)
            ));
        }
    }
}

#[cfg(feature = "selinux")]
pub use enabled::Runtime;
