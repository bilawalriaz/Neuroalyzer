//! Fault injection for tests. In debug builds, `SESSCRUB_TEST_FAULT=<name>`
//! makes `hit(name)` return true so a test can stop a run at a chosen step.
//! Release builds compile this to `false`.

pub fn hit(name: &str) -> bool {
    if cfg!(debug_assertions) {
        std::env::var("SESSCRUB_TEST_FAULT").is_ok_and(|v| v.split(',').any(|f| f == name))
    } else {
        let _ = name;
        false
    }
}
