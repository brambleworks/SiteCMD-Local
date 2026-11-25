use sitecmd_runtime::cli::audit::{self, AuditArgs, AuditOutcome};
use std::process::ExitCode;

pub(crate) fn dispatch_audit(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if audit::help_requested(&args) {
        eprint!("{}", audit::help());
        return ExitCode::SUCCESS;
    }

    match audit::parse_args(args) {
        Ok(audit_args) => run_audit(audit_args),
        Err(error) => {
            eprintln!("Error: {error}\nRun `sitecmd audit --help` for usage.");
            ExitCode::from(2)
        }
    }
}

#[cfg(unix)]
fn audit_until_interrupt(args: AuditArgs) -> (Result<AuditOutcome, String>, bool) {
    use sitecmd_runtime::cli::audit_interrupt;

    let interrupt = match audit_interrupt::install() {
        Ok(interrupt) => interrupt,
        Err(error) => {
            return (
                Err(format!("Could not install the interrupt handler: {error}")),
                false,
            )
        }
    };
    let outcome = audit::run_with_interrupt(&args, &interrupt);
    if interrupt.is_triggered() {
        audit_interrupt::reraise_sigint();
    }
    (outcome, interrupt.is_triggered())
}

#[cfg(not(unix))]
fn audit_until_interrupt(args: AuditArgs) -> (Result<AuditOutcome, String>, bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("could not start the audit runtime");
    let interrupt = sitecmd_runtime::cli::engine::Interrupt::new();
    let outcome = runtime.block_on(async {
        let mut signal = std::pin::pin!(tokio::signal::ctrl_c());
        let registered = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(signal.as_mut(), cx))
        })
        .await;
        if let std::task::Poll::Ready(result) = registered {
            return match result {
                Ok(()) => {
                    interrupt.trigger();
                    Err("Code scan cancelled.".into())
                }
                Err(error) => Err(format!("Could not install the interrupt handler: {error}")),
            };
        }
        let worker_interrupt = interrupt.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            audit::run_with_interrupt(&args, &worker_interrupt)
        });
        let outcome = tokio::select! {
            biased;
            signal_result = &mut signal => {
                interrupt.trigger();
                let outcome = worker.await;
                signal_result.map_err(|error| format!("Interrupt handler failed: {error}"))?;
                outcome
            }
            outcome = &mut worker => outcome,
        };
        outcome.map_err(|error| format!("Code Scan audit failed: {error}"))?
    });
    (outcome, interrupt.is_triggered())
}

fn run_audit(args: AuditArgs) -> ExitCode {
    let output_path = args.output.clone();
    let (outcome, interrupted) = audit_until_interrupt(args);
    if interrupted {
        return ExitCode::from(130);
    }
    match outcome {
        Ok(outcome) => {
            if let Some(path) = output_path {
                if let Err(error) = audit::write_report(&path, &outcome.rendered) {
                    eprintln!("Error: {error}");
                    return ExitCode::from(2);
                }
            } else {
                println!("{}", outcome.rendered);
            }
            if outcome.threshold_failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(2)
        }
    }
}
