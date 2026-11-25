use crate::cli::export::labels::{stack_summary_string, verify_hint};
use crate::cli::impact;
use crate::core::scan_types::ScanResult;

pub(super) fn build_issues_md(result: &ScanResult) -> String {
    let stack_summary = stack_summary_string(result.detected_stack.as_ref());
    let ranked = impact::rank_issues(&result.issues, result.detected_stack.as_ref());

    let total_recoverable: u32 = result.fix_points.iter().sum();

    let mut out = String::with_capacity(2048);

    out.push_str(&format!(
        "# SiteCMD - {}\nScore: {}/100 | Stack: {} | Scanned: {}\nRescan: `sitecmd scan --diff`\n",
        result.url, result.overall_score, stack_summary, result.timestamp,
    ));

    out.push('\n');

    if ranked.is_empty() {
        out.push_str("## Fixes\n\nNo issues found.\n");
        return out;
    }

    out.push_str(&format!(
        "## Fixes ({} issues, {} points recoverable)\n\nPoints show score gains when fixes are applied in this order.\n",
        ranked.len(),
        total_recoverable,
    ));

    for ri in &ranked {
        let issue = ri.issue;

        let severity_label = format!("{:?}", issue.severity);

        out.push_str(&format!(
            "\n### {}. {} [+{} pts] {}\nID: {} | {}\n\n{}\n",
            ri.rank,
            issue.title,
            result
                .fix_points
                .get(ri.actionable_index)
                .copied()
                .unwrap_or_default(),
            ri.applicability.tag(),
            issue.check_id,
            severity_label,
            issue.description,
        ));

        if let Some(manual) = &issue.manual_fix {
            if !manual.is_empty() {
                out.push_str(manual);
                out.push('\n');
            }
        }

        let verify = verify_hint(&issue.check_id, &result.url);
        out.push_str(&format!("Verify: {}\n", verify));
    }

    out
}
