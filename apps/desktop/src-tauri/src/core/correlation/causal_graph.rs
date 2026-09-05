//! Directed causal graph over canonical check IDs.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_f32(self) -> f32 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.7,
            Self::Low => 0.3,
        }
    }

    pub fn from_f32(v: f32) -> Self {
        if v >= 0.9 {
            Self::High
        } else if v >= 0.5 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone)]
pub struct CausalLink {
    pub cause: &'static str,
    pub effect: &'static str,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct LikelyCause {
    pub check_id: String,
    pub confidence: Confidence,
}

pub const CAUSAL_LINKS: &[CausalLink] = &[
    // Performance chain
    CausalLink {
        cause: "performance.compression",
        effect: "performance.lcp",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "performance.compression",
        effect: "performance.page_weight",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "performance.cache_headers",
        effect: "performance.ttfb",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "performance.render_blocking",
        effect: "performance.lcp",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "performance.unused_javascript",
        effect: "performance.inp",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "performance.unused_css",
        effect: "performance.lcp",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "performance.modern_image_formats",
        effect: "performance.page_weight",
        confidence: Confidence::High,
    },
    // SEO chain
    CausalLink {
        cause: "seo.robots.blocked",
        effect: "seo.indexing.not-indexed",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "seo.canonical.missing",
        effect: "seo.canonical.mismatch",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "seo.mobile-viewport",
        effect: "accessibility.touch-target-size",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "seo.sitemap.missing",
        effect: "seo.indexing.not-indexed",
        confidence: Confidence::Medium,
    },
    // Security chain (uses canonical post-rename ids)
    CausalLink {
        cause: "security.https",
        effect: "security.hsts",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "security.https",
        effect: "security.mixed_content",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "security.exposed-env",
        effect: "security.csp",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "security.cors",
        effect: "security.csp",
        confidence: Confidence::Medium,
    },
    // Infrastructure chain
    CausalLink {
        cause: "infrastructure.ssl-expiring",
        effect: "infrastructure.uptime",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "infrastructure.ssl-mismatch",
        effect: "infrastructure.uptime",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "infrastructure.origin-error",
        effect: "infrastructure.server-errors",
        confidence: Confidence::High,
    },
    CausalLink {
        cause: "infrastructure.ci-failure",
        effect: "dependencies.vulnerability",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "infrastructure.server-errors",
        effect: "analytics.traffic-drop",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "infrastructure.uptime",
        effect: "analytics.traffic-drop",
        confidence: Confidence::High,
    },
    // Dependencies chain
    CausalLink {
        cause: "dependencies.vulnerability",
        effect: "security.csp",
        confidence: Confidence::Medium,
    },
    CausalLink {
        cause: "dependencies.outdated-major",
        effect: "performance.inp",
        confidence: Confidence::Medium,
    },
    // Analytics chain
    CausalLink {
        cause: "performance.lcp",
        effect: "analytics.conversion-drop",
        confidence: Confidence::Medium,
    },
];

static INVERTED_GRAPH: LazyLock<HashMap<&'static str, Vec<&'static CausalLink>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, Vec<&'static CausalLink>> = HashMap::new();
        for link in CAUSAL_LINKS {
            m.entry(link.effect).or_default().push(link);
        }
        m
    });

static FORWARD_GRAPH: LazyLock<HashMap<&'static str, Vec<&'static CausalLink>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, Vec<&'static CausalLink>> = HashMap::new();
        for link in CAUSAL_LINKS {
            m.entry(link.cause).or_default().push(link);
        }
        m
    });

#[tracing::instrument(skip(active_check_ids), fields(cause_check_id = %cause_check_id))]
pub fn resolve_downstream_effects(
    cause_check_id: &str,
    active_check_ids: &HashSet<String>,
) -> Vec<String> {
    FORWARD_GRAPH
        .get(cause_check_id)
        .map(|links| {
            links
                .iter()
                .filter(|l| active_check_ids.contains(l.effect))
                .map(|l| l.effect.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[tracing::instrument(skip(active_check_ids), fields(effect_check_id = %effect_check_id))]
pub fn resolve_likely_causes(
    effect_check_id: &str,
    active_check_ids: &HashSet<String>,
) -> Vec<LikelyCause> {
    CAUSAL_LINKS
        .iter()
        .filter(|l| l.effect == effect_check_id && active_check_ids.contains(l.cause))
        .map(|l| LikelyCause {
            check_id: l.cause.to_string(),
            confidence: l.confidence,
        })
        .collect()
}

pub fn resolve_transitive_causes(
    effect_check_id: &str,
    active_check_ids: &HashSet<String>,
    max_depth: u8,
) -> Vec<crate::core::types_work_items::TransitiveCause> {
    use crate::core::types_work_items::TransitiveCause;
    use std::collections::VecDeque;
    let mut out: Vec<TransitiveCause> = Vec::new();
    let mut queue: VecDeque<(String, Vec<String>, f32, u8)> = VecDeque::new();
    queue.push_back((
        effect_check_id.to_string(),
        vec![effect_check_id.to_string()],
        1.0,
        0,
    ));

    while let Some((node, path, conf, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let next_depth = depth + 1;
        let Some(links) = INVERTED_GRAPH.get(node.as_str()) else {
            continue;
        };
        for link in links {
            let next_conf = conf * link.confidence.as_f32() * 0.6;
            if next_conf < 0.2 {
                continue;
            }
            if path.iter().any(|p| p == link.cause) {
                continue;
            }
            if !active_check_ids.contains(link.cause) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(link.cause.to_string());
            out.push(TransitiveCause {
                check_id: link.cause.to_string(),
                path: next_path.clone(),
                confidence: Confidence::from_f32(next_conf),
                depth: next_depth,
            });
            queue.push_back((link.cause.to_string(), next_path, next_conf, next_depth));
        }
    }
    out.truncate(10);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn downstream_effects_returns_active_effects_only() {
        let active: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();
        let effects = resolve_downstream_effects("performance.compression", &active);
        assert!(
            effects.contains(&"performance.lcp".to_string()),
            "compression should surface lcp as an active downstream effect",
        );
    }

    #[test]
    fn downstream_effects_excludes_inactive() {
        let active: HashSet<String> = HashSet::new();
        let effects = resolve_downstream_effects("performance.compression", &active);
        assert!(
            effects.is_empty(),
            "no active downstream effects expected when active set is empty"
        );
    }

    #[test]
    fn causal_link_active_cause_is_returned() {
        let active: HashSet<String> = ["performance.compression", "performance.lcp"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let causes = resolve_likely_causes("performance.lcp", &active);
        assert!(
            causes
                .iter()
                .any(|c| c.check_id == "performance.compression"),
            "compression should be a likely cause of lcp when both active"
        );
    }

    #[test]
    fn inactive_cause_is_filtered_out() {
        let active: HashSet<String> = ["performance.lcp"].iter().map(|s| s.to_string()).collect();
        let causes = resolve_likely_causes("performance.lcp", &active);
        assert!(
            causes
                .iter()
                .all(|c| c.check_id != "performance.compression"),
            "we never speculate about causes that aren't observed"
        );
    }

    #[test]
    fn every_cause_and_effect_is_non_empty() {
        for link in CAUSAL_LINKS {
            assert!(!link.cause.is_empty(), "cause is empty");
            assert!(!link.effect.is_empty(), "effect is empty");
            assert_ne!(
                link.cause, link.effect,
                "self-loop in causal graph: {}",
                link.cause
            );
        }
    }

    #[test]
    fn no_duplicate_cause_effect_pairs() {
        let mut seen: HashSet<(&str, &str)> = HashSet::new();
        for link in CAUSAL_LINKS {
            assert!(
                seen.insert((link.cause, link.effect)),
                "duplicate pair: {} -> {}",
                link.cause,
                link.effect
            );
        }
    }

    #[derive(Serialize)]
    struct SerializedCausalLink {
        cause: &'static str,
        effect: &'static str,
        confidence: Confidence,
    }

    #[derive(Serialize)]
    struct CausalGraphFile {
        links: Vec<SerializedCausalLink>,
    }

    #[test]
    fn all_edges_reference_canonical_ids() {
        use crate::core::correlation::signal_mapping::CANONICAL_CHECK_IDS;
        let canonical: std::collections::HashSet<&str> =
            CANONICAL_CHECK_IDS.iter().copied().collect();
        for link in CAUSAL_LINKS {
            assert!(
                canonical.contains(link.cause),
                "CausalLink.cause `{}` is not in CANONICAL_CHECK_IDS",
                link.cause,
            );
            assert!(
                canonical.contains(link.effect),
                "CausalLink.effect `{}` is not in CANONICAL_CHECK_IDS",
                link.effect,
            );
        }
    }

    #[test]
    fn causal_graph_json_is_in_sync_with_mcp_copy() {
        let links: Vec<SerializedCausalLink> = CAUSAL_LINKS
            .iter()
            .map(|l| SerializedCausalLink {
                cause: l.cause,
                effect: l.effect,
                confidence: l.confidence,
            })
            .collect();
        let file = CausalGraphFile { links };
        let expected = serde_json::to_string_pretty(&file).expect("serialize graph") + "\n";

        // Path relative to the shared source root (apps/desktop/src-tauri). Go up to
        // apps/ and then into mcp-server/src/.
        let manifest_dir = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"));
        let json_path = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("apps root")
            .join("mcp-server")
            .join("src")
            .join("causal_graph.json");

        let actual = std::fs::read_to_string(&json_path).unwrap_or_default();
        if actual != expected {
            std::fs::write(&json_path, &expected).expect("write causal_graph.json");
            panic!(
                "apps/mcp-server/src/causal_graph.json was stale (rewrote it). \
                 Review the diff with `git diff apps/mcp-server/src/causal_graph.json` and commit."
            );
        }
    }

    #[test]
    fn confidence_roundtrip_thresholds() {
        assert_eq!(Confidence::from_f32(1.0), Confidence::High);
        assert_eq!(Confidence::from_f32(0.9), Confidence::High);
        assert_eq!(Confidence::from_f32(0.7), Confidence::Medium);
        assert_eq!(Confidence::from_f32(0.5), Confidence::Medium);
        assert_eq!(Confidence::from_f32(0.3), Confidence::Low);
        assert_eq!(Confidence::from_f32(0.0), Confidence::Low);
    }

    #[test]
    fn confidence_as_f32_distinct() {
        assert_eq!(Confidence::High.as_f32(), 1.0);
        assert_eq!(Confidence::Medium.as_f32(), 0.7);
        assert_eq!(Confidence::Low.as_f32(), 0.3);
    }

    #[test]
    fn transitive_two_hop_through_lcp() {
        let active: HashSet<String> = [
            "performance.compression",
            "performance.lcp",
            "analytics.conversion-drop",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let causes = resolve_transitive_causes("analytics.conversion-drop", &active, 4);
        assert!(
            causes
                .iter()
                .any(|c| c.check_id == "performance.compression" && c.depth == 2),
            "expected compression to surface as a 2-hop cause of conversion-drop via lcp; got: {:?}",
            causes,
        );
    }

    #[test]
    fn transitive_skips_inactive_intermediate() {
        let active: HashSet<String> = ["performance.compression", "analytics.conversion-drop"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let causes = resolve_transitive_causes("analytics.conversion-drop", &active, 4);
        assert!(
            !causes
                .iter()
                .any(|c| c.check_id == "performance.compression"),
            "compression should not reach conversion-drop when lcp is inactive; got: {:?}",
            causes,
        );
    }

    #[test]
    fn transitive_depth_capped() {
        let active: HashSet<String> = [
            "performance.compression",
            "performance.lcp",
            "analytics.conversion-drop",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let causes = resolve_transitive_causes("analytics.conversion-drop", &active, 1);
        assert!(
            causes.iter().all(|c| c.depth <= 1),
            "depth cap violated; got: {:?}",
            causes
        );
    }

    #[test]
    fn transitive_results_capped_at_10() {
        let active: HashSet<String> = CAUSAL_LINKS
            .iter()
            .map(|l| l.cause.to_string())
            .chain(CAUSAL_LINKS.iter().map(|l| l.effect.to_string()))
            .collect();
        let causes = resolve_transitive_causes("analytics.conversion-drop", &active, 4);
        assert!(
            causes.len() <= 10,
            "result cap violated: got {} entries",
            causes.len()
        );
    }
}
