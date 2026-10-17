import { formatCausalityBlock } from "./causal_graph.js";
import type { Issue } from "./db.js";
import { formatBoundedEntries } from "./output_budget.js";
import { quoteUntrustedText } from "./untrusted.js";

const MAX_ISSUE_LIST_CHARS = 16000;
const SUMMARY_DESCRIPTION_CHARS = 300;

export function issueLocation(issue: Issue): string {
  if (issue.relative_path) return `${issue.relative_path}${issue.line ? `:${issue.line}` : ""}`;
  return issue.page_url ?? "(site-wide)";
}

export function issueHeading(issue: Issue, level: "##" | "###"): string {
  const id = issue.id !== undefined ? ` (#${issue.id})` : "";
  return `${level} [${issue.severity.toUpperCase()}] ${quoteUntrustedText(issue.title, 500)}${id}`;
}

/** Source tells a dependency or integration finding apart from a scan finding. */
export function issueMeta(issue: Issue): string {
  return `**Check:** ${quoteUntrustedText(issue.check_id, 200)} | **Source:** ${quoteUntrustedText(issue.source ?? "unknown", 100)} | **Category:** ${issue.category} | **Confidence:** ${issue.confidence ?? "unknown"} | **Where:** ${quoteUntrustedText(issueLocation(issue), 500)}`;
}

/** Summaries retain routing and causal hints; get_issue supplies complete guidance. */
export function formatIssueSummaries(issues: Issue[], activeCheckIds: Set<string>) {
  return formatBoundedEntries(
    issues,
    (issue) => {
      const blocks = [
        issueHeading(issue, "###"),
        issueMeta(issue),
        quoteUntrustedText(issue.description, SUMMARY_DESCRIPTION_CHARS),
      ];
      const causal = formatCausalityBlock(issue.check_id, activeCheckIds);
      if (causal) blocks.push("", causal);
      return blocks.join("\n");
    },
    MAX_ISSUE_LIST_CHARS,
  );
}
