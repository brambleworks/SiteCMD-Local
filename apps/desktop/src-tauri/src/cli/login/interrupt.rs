//! Signal custody and deterministic cancellation for credential transitions.

use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};
use tokio::sync::watch;

const SAVING: u8 = 1;
const SAVED: u8 = 2;

#[derive(Clone)]
pub(super) struct Interrupt(Arc<State>);
struct State {
    signal: watch::Sender<u8>,
    phase: AtomicU8,
    during_save: AtomicBool,
}

pub(super) struct SignalGuard(Option<tokio::task::JoinHandle<()>>);
impl Drop for SignalGuard {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

impl Interrupt {
    pub fn new() -> Self {
        Self(Arc::new(State {
            signal: watch::channel(0).0,
            phase: AtomicU8::new(0),
            during_save: AtomicBool::new(false),
        }))
    }
    pub fn trigger(&self) {
        if self.0.phase.load(Ordering::SeqCst) == SAVING {
            self.0.during_save.store(true, Ordering::SeqCst);
        }
        self.0
            .signal
            .send_modify(|count| *count = count.saturating_add(1));
    }
    pub fn triggered(&self) -> bool {
        *self.0.signal.borrow() > 0
    }
    pub fn begin_save(&self) {
        self.0.phase.store(SAVING, Ordering::SeqCst);
        if self.triggered() {
            self.0.during_save.store(true, Ordering::SeqCst);
        }
    }
    pub fn finish_save(&self) {
        self.0.phase.store(SAVED, Ordering::SeqCst);
    }
    pub fn during_save(&self) -> bool {
        self.0.during_save.load(Ordering::SeqCst)
    }
    pub async fn cancelled(&self) {
        let _ = self.0.signal.subscribe().wait_for(|count| *count > 0).await;
    }
    pub async fn forced(&self) {
        let _ = self
            .0
            .signal
            .subscribe()
            .wait_for(|count| *count >= 2)
            .await;
    }
    pub async fn listen(&self) -> Result<SignalGuard, String> {
        let mut signal = Box::pin(tokio::signal::ctrl_c());
        match futures_util::poll!(signal.as_mut()) {
            std::task::Poll::Ready(Ok(())) => {
                self.trigger();
                signal = Box::pin(tokio::signal::ctrl_c());
            }
            std::task::Poll::Ready(Err(_)) => {
                return Err("could not listen for sign-in interruption".into())
            }
            std::task::Poll::Pending => {}
        }
        let interrupt = self.clone();
        Ok(SignalGuard(Some(tokio::spawn(async move {
            loop {
                if signal.await.is_err() {
                    break;
                }
                interrupt.trigger();
                signal = Box::pin(tokio::signal::ctrl_c());
            }
        }))))
    }
}
