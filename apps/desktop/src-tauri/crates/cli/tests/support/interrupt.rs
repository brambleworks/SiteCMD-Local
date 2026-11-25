use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub(super) fn send_interrupt(child: &Child) {
    assert!(Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
}

pub(super) fn assert_interrupted(mut child: Child) {
    let interrupt = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if interrupt.elapsed() >= Duration::from_secs(1) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("the audit did not exit within one second");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.signal(), Some(2));
}
