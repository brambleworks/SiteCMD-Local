//! SIGINT handling for the standalone audit command.

use sitecmd_engine_host::Interrupt;
use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

/// Arm the audit interrupt and let the OS handle the next SIGINT by default.
pub fn install() -> std::io::Result<Interrupt> {
    // SAFETY: sigaction is initialized before registration, and the handler only stores to an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigint as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESETHAND;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(Interrupt::with_signal_flag(&INTERRUPTED))
}

pub fn reraise_sigint() {
    // SAFETY: The one-shot handler has already restored the default action.
    unsafe { libc::raise(libc::SIGINT) };
}
