use super::*;

#[tokio::test]
async fn stylesheet_signals_and_fetches_run_on_the_first_page_alone() {
    // Follow-up pages must not refetch CSS or grade their inline styles as origin signals.
    let server = spawn_test_server(|_| {
        let page = format!(
            r#"<title>Example</title><link rel="stylesheet" href="/site.css">{}"#,
            r#"<i class="bg-gradient-to-r from-purple-500 bg-clip-text text-transparent"></i>"#
                .repeat(5)
        );
        HashMap::from([
            ("/".into(), TestResponse::ok("text/html", page.clone())),
            ("/inner".into(), TestResponse::ok("text/html", page)),
            (
                "/site.css".into(),
                TestResponse::ok("text/css", "body{color:red}"),
            ),
        ])
    })
    .await;
    let css_ids: Vec<_> = crate::checks::polish::POLISH_SIGNALS
        .iter()
        .filter(|s| s.reads_stylesheets)
        .map(|s| format!("polish.{}", s.id))
        .collect();
    for (path, skip) in [("/", false), ("/inner", true)] {
        let css_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = css_started.clone();
        let progress = move |p: &super::super::ScanProgress| {
            if p.check_id == "polish-css" && p.status == "running" {
                started.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        };
        let result = super::super::run_scan::<fn() -> bool>(
            &format!("{}{path}", server.base_url),
            Some(&progress),
            None,
            None,
            ScanType::Polish,
            skip,
            None,
        )
        .await
        .unwrap();
        let count = result
            .issues
            .iter()
            .filter(|row| css_ids.contains(&row.check_id))
            .count();
        assert_eq!(count, if skip { 0 } else { 6 });
        let gradient = result
            .issues
            .iter()
            .find(|row| row.check_id == "polish.gradient-text");
        if skip {
            assert!(gradient.is_none());
        } else {
            assert_eq!(gradient.unwrap().status, CheckStatus::Fail);
        }
        assert_eq!(
            css_started.load(std::sync::atomic::Ordering::Relaxed),
            !skip
        );
        assert!(result
            .issues
            .iter()
            .any(|row| row.check_id == "polish.default-page-title"));
    }
}
