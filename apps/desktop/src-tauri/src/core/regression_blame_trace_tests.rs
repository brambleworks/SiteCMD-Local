//! Held-back findings remain observable when no blame is emitted.

use std::fmt::Write;
use std::sync::{Arc, Mutex};

use super::*;

struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    fn with_default<T>(self, f: impl FnOnce() -> T) -> T {
        // Keep two registered dispatchers alive so first use on another thread consults this subscriber.
        let _other_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new());
        tracing::subscriber::with_default(self, || {
            tracing::callsite::rebuild_interest_cache();
            f()
        })
    }
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        write!(self.0, "{}={value:?} ", field.name()).expect("write event field");
    }
}

impl tracing::Subscriber for Events {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = String::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().expect("events lock").push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[test]
fn withheld_findings_are_logged_without_a_blame_decision() {
    for has_commits in [true, false] {
        for duplicates in [1, 2] {
            let db = temp_db();
            let project_id = test_project(&db);
            let commits: &[(&str, &str)] = if has_commits {
                &[("unrelated change", "2026-06-09T10:00:00Z")]
            } else {
                &[]
            };
            let repo = make_repo("withheld", commits);
            stamp_fixture_runs(&db, project_id, &[42]);
            stamp_run_under_older_build(
                &db,
                project_id,
                41,
                &["security.headers.cross_origin"],
                &[],
            );
            let snapshot = snapshot_with(Some(previous_scan()), &[]);
            let issues = vec![issue("security.headers.cross_origin", "high"); duplicates];
            let path = repo.to_string_lossy().to_string();
            let events = Arc::new(Mutex::new(Vec::new()));
            let notice = Events(events.clone()).with_default(|| {
                emit_regression_blame(ctx(&db.db, project_id, &issues, Some(&path)), &snapshot)
            });
            assert!(notice.is_none());
            let captured = events.lock().expect("events lock");
            let notes: Vec<_> = captured
                .iter()
                .filter(|event| event.contains("findings withheld from deploy blame"))
                .collect();
            assert_eq!(notes.len(), 1, "{captured:?}");
            assert!(notes[0].contains("held_back=1"), "{:?}", notes[0]);
            assert!(db.get_regression_by_scan("web", 42).expect("get").is_none());
        }
    }
}

#[test]
fn capture_survives_first_use_on_another_thread() {
    fn emit() {
        tracing::info!(held_back = 1, "capture probe");
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    Events(events.clone()).with_default(|| {
        std::thread::spawn(|| tracing::dispatcher::with_default(&tracing::Dispatch::none(), emit))
            .join()
            .expect("first use on another thread");
        emit();
    });
    let captured = events.lock().expect("events lock");
    assert_eq!(captured.len(), 1, "{captured:?}");
    assert!(captured[0].contains("held_back=1"), "{captured:?}");
}

#[test]
fn capture_survives_first_use_under_an_uninterested_default() {
    fn emit() {
        tracing::info!(held_back = 1, "nested capture probe");
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    Events(events.clone()).with_default(|| {
        tracing::dispatcher::with_default(&tracing::Dispatch::none(), emit);
        emit();
    });
    let captured = events.lock().expect("events lock");
    assert_eq!(captured.len(), 1, "{captured:?}");
    assert!(captured[0].contains("held_back=1"), "{captured:?}");
}

#[test]
fn parallel_captures_keep_events_on_their_own_threads() {
    fn emit(probe: usize) {
        tracing::info!(probe, "parallel capture probe");
    }

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|probe| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let events = Arc::new(Mutex::new(Vec::new()));
                Events(events.clone()).with_default(|| {
                    barrier.wait();
                    emit(probe);
                });
                let captured = events.lock().expect("events lock");
                assert_eq!(captured.len(), 1, "{captured:?}");
                assert!(
                    captured[0].contains(&format!("probe={probe}")),
                    "{captured:?}"
                );
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("parallel capture");
    }
}
