use super::*;

pub(super) fn collect_outbound_issues(issues: &mut Vec<CodeIssue>, ctx: &FileAnalysisContext<'_>) {
    let file = ctx.file;
    let content = ctx.content;
    let likely_public_endpoint = ctx.signals.likely_public_endpoint;
    let has_auth = ctx.signals.has_auth;
    let has_timeout = ctx.signals.has_timeout;
    let has_retry_guard = ctx.signals.has_retry_guard;
    let needs_outbound_guards = ctx.needs_outbound_guards;
    let uses_llm = ctx.signals.uses_llm;
    let scanned = outbound_view(content);
    // A route with no recognized auth gate is caller-facing whether or not its
    // name carries an abuse-sensitive word. A read-only GET that proxies an
    // upstream API needs a deadline just as much as a POST does, and pinning
    // that on a risk word made the verdict turn on wording in a third-party URL.
    let unguarded_outbound_route = likely_public_endpoint || !has_auth;
    if needs_outbound_guards && unguarded_outbound_route && !has_timeout {
        issues.push(build_issue(
            "external-call-timeout",
            "operations",
            Severity::High,
            "No recognized local deadline for an external call in a public route",
            "The scanned public-looking handler contains an outbound HTTP or third-party SDK call, but SiteCMD did not find a recognized local timeout or cancellation boundary. This file-local absence does not establish an unbounded runtime call because the client, SDK, wrapper, proxy, or platform may enforce a deadline. If no effective deadline exists, a stalled dependency can retain request and connection capacity until a lower-level timeout intervenes.",
            file,
            first_match_line(&scanned, &OUTBOUND_HTTP_PATTERNS),
            Some("Outbound HTTP or third-party SDK usage was detected in a public-looking handler, but no recognized local timeout, deadline, or abort pattern was found. Client defaults and infrastructure deadlines were not resolved.".into()),
            Some("Determine the effective end-to-end request budget, then configure a shorter per-attempt deadline through the client's supported cancellation mechanism and propagate cancellation where possible. Handle timeout distinctly, release resources, and coordinate any retry budget with idempotency and the caller's deadline.".into()),
            Some("Point the non-production client at a controlled slow/blackhole fixture. Measure that the call ends within the documented budget, resources are released, the public response is bounded and non-sensitive, and retries cannot extend work beyond the end-to-end deadline.".into()),
        ));
    }

    if needs_outbound_guards && unguarded_outbound_route && !has_retry_guard {
        issues.push(build_issue(
            "external-call-retry",
            "operations",
            Severity::Low,
            "No explicit retry policy for an external call in a public route",
            "The scanned public-looking handler contains an outbound call, but SiteCMD did not find a recognized local retry/backoff policy. This does not prove a reliability defect: a fail-fast policy with zero retries is often correct, and the client, SDK, queue, or gateway may already own retries. The review is to make the effective policy deliberate, bounded, deadline-aware, and safe for the operation's idempotency semantics.",
            file,
            first_match_line(&scanned, &OUTBOUND_HTTP_PATTERNS),
            Some("Outbound HTTP usage was detected without a recognized local max-attempt, backoff, or explicit no-retry pattern. Client/SDK defaults, queues, proxies, and operation idempotency were not resolved.".into()),
            Some("Document and configure the effective policy at the layer that owns the call. Zero retries is valid. If retries are justified, retry only eligible transient failures, cap attempts and total elapsed time, add jitter, honor server guidance where appropriate, and require an idempotency key or proven idempotence before retrying side effects.".into()),
            Some("Using a controlled failing dependency, test the chosen no-retry or bounded-retry policy for timeouts, connection failures, throttling, and permanent errors. Confirm attempts and total time stay within budget and no side effect is duplicated.".into()),
        ));
    }

    if uses_llm && !has_retry_guard {
        issues.push(build_issue(
            "ai-retry-bounds",
            "ai-safety",
            Severity::Low,
            "No explicit retry policy for an AI provider call",
            "The scanned file calls an AI provider, but SiteCMD did not find a recognized local retry/backoff policy. This does not prove unbounded retries or a reliability defect: zero retries may be correct, and the SDK, gateway, or job system may own a bounded policy. Because attempts can consume quota and cost, the effective policy should be deliberate, deadline-aware, observable, and safe for any surrounding side effects.",
            file,
            first_llm_usage_line(content),
            Some("Provider usage was detected, but no recognized local retry cap, explicit no-retry setting, or backoff flow was found. SDK, gateway, and queue defaults were not resolved.".into()),
            Some("Choose the policy at the owning layer and document it; zero retries is valid. If retrying, limit attempts and total elapsed time, add jitter, retry only eligible transient failures, honor the request deadline, and use a stable idempotency/deduplication key when an attempt can trigger external or persisted effects.".into()),
            Some("With a mocked provider, exercise the configured policy for timeout, throttling, transient server failure, invalid request, and cancellation. Confirm attempts and cost stay bounded, permanent failures are not retried, cancellation stops further work, and surrounding side effects occur at most once.".into()),
        ));
    }
}
