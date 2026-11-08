use super::*;

#[tokio::test]
async fn http2_grades_on_the_first_page_alone() {
    // A synchronous origin check must not grade or claim coverage on follow-up pages.
    let server = spawn_test_server(|_| {
        HashMap::from([
            (
                "/".into(),
                TestResponse::ok("text/html", "<title>Home</title>"),
            ),
            (
                "/inner".into(),
                TestResponse::ok("text/html", "<title>Inner</title>"),
            ),
        ])
    })
    .await;
    for (path, skip) in [("/", false), ("/inner", true)] {
        let result = super::super::run_scan::<fn() -> bool>(
            &format!("{}{path}", server.base_url),
            None,
            Some(vec!["performance".into()]),
            None,
            ScanType::Health,
            skip,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            result
                .issues
                .iter()
                .filter(|r| r.check_id == "performance.http2")
                .count(),
            usize::from(!skip),
            "{path}"
        );
        assert!(result
            .issues
            .iter()
            .any(|r| r.check_id == "performance.dom_size"));
    }
}
