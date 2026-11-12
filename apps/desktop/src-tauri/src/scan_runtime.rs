//! Low-priority Tokio runtime for CPU-heavy scan work.
//!
//! Tauri IPC remains on the default runtime; only scan futures run here.

use std::sync::{Arc, LazyLock};

use thread_priority::{set_current_thread_priority, ThreadPriority};
use tokio::runtime::{Builder, Runtime};

use crate::core::scanner::{self, ProgressFn, ScanError, ScanResult, ScanType};

/// Process-wide low-priority runtime for scan work.
static SCAN_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .thread_name("sitecmd-scan-worker")
        .on_thread_start(|| {
            // Best-effort priority drop keeps scan work behind foreground tasks.
            let _ = set_current_thread_priority(ThreadPriority::Min);
        })
        .build()
        .expect("scan runtime build")
});

/// Handle to the low-priority scan runtime. Use this to spawn scan work from
/// a different runtime (e.g. Tauri's default IPC runtime).
pub fn handle() -> tokio::runtime::Handle {
    SCAN_RUNTIME.handle().clone()
}

/// Owned, `'static + Send + Sync` cancel-check callback. Reference-counted so
/// it can be shared between the scan future and the spawning task.
pub type CancelFn = dyn Fn() -> bool + Send + Sync + 'static;

/// Run `scanner::run_scan` on the low-priority runtime with owned inputs.
pub async fn run_scan_low_priority(
    url: String,
    progress: Option<Arc<ProgressFn>>,
    enabled_categories: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    scan_type: ScanType,
    skip_origin_checks: bool,
    cancel_check: Option<Arc<CancelFn>>,
) -> Result<ScanResult, ScanError> {
    handle()
        .spawn(async move {
            scanner::run_scan::<CancelFn>(
                &url,
                progress.as_deref(),
                enabled_categories,
                timeout_secs,
                scan_type,
                skip_origin_checks,
                cancel_check.as_deref(),
            )
            .await
        })
        .await
        .map_err(|e| ScanError::ScanFailed(format!("scan task join: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_runtime_workers_run_at_reduced_priority() {
        let (name, priority_changed) = handle().block_on(async {
            tokio::task::spawn(async {
                let name = std::thread::current()
                    .name()
                    .unwrap_or_default()
                    .to_string();
                let _ = thread_priority::set_current_thread_priority(ThreadPriority::Min);
                let priority_changed = thread_priority::get_current_thread_priority().is_ok();
                (name, priority_changed)
            })
            .await
            .expect("scan worker task")
        });
        assert!(
            name.starts_with("sitecmd-scan-worker"),
            "expected scan-runtime thread name, got {:?}",
            name
        );
        assert!(
            priority_changed,
            "expected to be able to query thread priority on scan worker"
        );
    }
}
