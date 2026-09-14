#[tokio::test(flavor = "current_thread")]
async fn blocking_work_leaves_the_calling_executor_responsive() {
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let work = super::run_blocking(move || {
        entered.send(()).expect("notify the calling executor");
        released.recv_timeout(std::time::Duration::from_secs(5))
    });
    let sibling = async move {
        observed.await.expect("blocking worker started");
        release.send(()).expect("worker still waiting");
    };
    let (result, ()) = tokio::join!(work, sibling);
    result
        .expect("worker joined")
        .expect("executor released the worker without waiting for its timeout");
}
