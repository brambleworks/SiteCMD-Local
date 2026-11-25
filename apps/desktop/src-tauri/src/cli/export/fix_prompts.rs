use crate::core::fixes::fix_text;
use crate::core::scan_types::{CheckStatus, ScanResult};
use sitecmd_protocol::engine_abi::FixTextTarget;

pub(super) fn enrich_with_fix_prompts(mut result: ScanResult) -> Result<ScanResult, String> {
    let issues: Vec<_> = result
        .issues
        .iter_mut()
        .filter(|issue| {
            issue.fix_prompt.is_none()
                && matches!(issue.status, CheckStatus::Fail | CheckStatus::Warn)
        })
        .collect();
    let targets = issues
        .iter()
        .map(|issue| FixTextTarget::Web {
            issue: Box::new((**issue).clone()),
            url: result.url.clone(),
            detected_stack: result.detected_stack.clone(),
        })
        .collect();
    for (issue, text) in issues.into_iter().zip(fix_text(targets)?) {
        issue.fix_prompt = Some(text);
    }
    Ok(result)
}
