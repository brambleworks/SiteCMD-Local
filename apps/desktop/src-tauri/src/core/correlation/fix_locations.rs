//! Candidate project files for fixing canonical issue groups.

use crate::core::types_work_items::FixLocation;

struct Candidate {
    label: &'static str,
    reason: &'static str,
    paths: &'static [&'static str],
}

fn security_candidates(check_id: &str) -> Vec<Candidate> {
    let id = check_id.to_lowercase();
    let mut candidates = Vec::new();

    if id.contains("csp") || id.contains("content-security-policy") {
        candidates.push(Candidate {
            label: "Header config",
            reason: "CSP and related headers are often set here for hosted builds.",
            paths: &[
                "_headers",
                "public/_headers",
                "vercel.json",
                "netlify.toml",
                "nginx.conf",
                "Caddyfile",
                ".htaccess",
            ],
        });
        candidates.push(Candidate {
            label: "App config",
            reason: "Framework-level security headers and rewrites often live here.",
            paths: &[
                "next.config.ts",
                "next.config.mjs",
                "next.config.js",
                "middleware.ts",
                "middleware.js",
                "src/middleware.ts",
                "src/middleware.js",
            ],
        });
    }

    if id.contains("hsts") || id.contains("strict-transport-security") {
        candidates.push(Candidate {
            label: "Server header config",
            reason: "HSTS is usually added at the hosting or reverse-proxy layer.",
            paths: &[
                "_headers",
                "public/_headers",
                "vercel.json",
                "netlify.toml",
                "nginx.conf",
                "Caddyfile",
                ".htaccess",
            ],
        });
    }

    if id.contains("https") || id.contains("mixed-content") || id.contains("mixed_content") {
        candidates.push(Candidate {
            label: "App config",
            reason: "HTTPS redirects and asset handling are often controlled here.",
            paths: &[
                "next.config.ts",
                "next.config.mjs",
                "next.config.js",
                "middleware.ts",
                "middleware.js",
                "src/middleware.ts",
                "src/middleware.js",
            ],
        });
        candidates.push(Candidate {
            label: "Server config",
            reason: "Mixed-content and redirect behavior can also be enforced at the edge.",
            paths: &[
                "vercel.json",
                "netlify.toml",
                "nginx.conf",
                "Caddyfile",
                ".htaccess",
            ],
        });
    }

    if id.contains("exposed-env")
        || id.contains("exposed")
        || id.contains(".env")
        || id.contains(".git")
    {
        candidates.push(Candidate {
            label: "Edge or server config",
            reason: "Static file exposure is usually blocked in hosting or rewrite config.",
            paths: &[
                "vercel.json",
                "netlify.toml",
                "nginx.conf",
                "Caddyfile",
                ".htaccess",
                "middleware.ts",
                "middleware.js",
                "src/middleware.ts",
                "src/middleware.js",
            ],
        });
    }

    candidates
}

fn seo_candidates(check_id: &str) -> Vec<Candidate> {
    let id = check_id.to_lowercase();
    let mut candidates = Vec::new();

    if id.contains("robots") {
        candidates.push(Candidate {
            label: "Robots config",
            reason: "Indexing directives usually live in a static robots file or generated route.",
            paths: &[
                "robots.txt",
                "public/robots.txt",
                "app/robots.ts",
                "src/app/robots.ts",
            ],
        });
    }

    if id.contains("sitemap") {
        candidates.push(Candidate {
            label: "Sitemap generation",
            reason: "Sitemap output usually comes from a static XML file or generated app route.",
            paths: &[
                "sitemap.xml",
                "public/sitemap.xml",
                "app/sitemap.ts",
                "src/app/sitemap.ts",
            ],
        });
    }

    if id.contains("canonical") {
        candidates.push(Candidate {
            label: "Metadata layout",
            reason: "Canonical URLs are often defined in shared metadata/layout config.",
            paths: &[
                "app/layout.tsx",
                "app/layout.ts",
                "src/app/layout.tsx",
                "src/app/layout.ts",
                "next-seo.config.ts",
                "next-seo.config.js",
            ],
        });
    }

    if id.contains("title") || id.contains("description") || id.contains("meta") {
        candidates.push(Candidate {
            label: "Metadata config",
            reason: "Title and description issues usually trace back to shared metadata or layout files.",
            paths: &["app/layout.tsx", "app/layout.ts", "src/app/layout.tsx", "src/app/layout.ts", "next-seo.config.ts", "next-seo.config.js"],
        });
    }

    candidates
}

#[tracing::instrument(skip(project_path), fields(check_id = %check_id, has_project_path = project_path.is_some_and(|value| !value.trim().is_empty())))]
pub fn resolve_fix_locations(check_id: &str, project_path: Option<&str>) -> Vec<FixLocation> {
    let Some(path) = project_path else {
        return Vec::new();
    };
    let base = std::path::Path::new(path);

    let candidates: Vec<Candidate> = if check_id.starts_with("security.") {
        security_candidates(check_id)
    } else if check_id.starts_with("seo.") {
        seo_candidates(check_id)
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for cand in candidates {
        for rel in cand.paths {
            let abs = base.join(rel);
            if abs.exists() {
                out.push(FixLocation {
                    label: cand.label.to_string(),
                    reason: cand.reason.to_string(),
                    relative_path: rel.to_string(),
                    absolute_path: abs.to_string_lossy().to_string(),
                });
                break;
            }
        }
    }
    out
}

/// Exported candidate shape used to generate fix_locations.json for the MCP server.
#[derive(serde::Serialize)]
pub struct FixLocationCandidateExport {
    pub label: String,
    pub reason: String,
    pub paths: Vec<String>,
}

/// Returns all fix-location candidates by check id for MCP export. Unlike the
/// desktop helpers, this does not filter paths by local file existence.
pub fn export_all_candidates() -> Vec<(&'static str, Vec<FixLocationCandidateExport>)> {
    let known_ids: &[&str] = &[
        "security.csp",
        "security.hsts",
        "security.https",
        "security.exposed-env",
        "seo.robots",
        "seo.sitemap.missing",
        "seo.canonical.missing",
        "seo.title",
        "seo.description",
        "seo.meta",
    ];

    let mut out = Vec::new();
    for &id in known_ids {
        let raw_candidates: Vec<Candidate> = if id.starts_with("security.") {
            security_candidates(id)
        } else if id.starts_with("seo.") {
            seo_candidates(id)
        } else {
            Vec::new()
        };

        if raw_candidates.is_empty() {
            continue;
        }

        let exported: Vec<FixLocationCandidateExport> = raw_candidates
            .into_iter()
            .map(|c| FixLocationCandidateExport {
                label: c.label.to_string(),
                reason: c.reason.to_string(),
                paths: c.paths.iter().map(|p| (*p).to_string()).collect(),
            })
            .collect();

        out.push((id, exported));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_without_project_path() {
        assert!(resolve_fix_locations("security.csp", None).is_empty());
    }

    #[test]
    fn returns_empty_when_no_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        let out = resolve_fix_locations("security.csp", Some(dir.path().to_str().unwrap()));
        assert!(out.is_empty());
    }

    #[test]
    fn resolves_next_config_for_csp() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("next.config.ts"), "export default {}").unwrap();
        let out = resolve_fix_locations("security.csp", Some(dir.path().to_str().unwrap()));
        assert!(out.iter().any(|l| l.relative_path == "next.config.ts"));
    }

    #[test]
    fn resolves_robots_txt_for_seo_robots() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("robots.txt"), "User-agent: *").unwrap();
        let out = resolve_fix_locations("seo.robots", Some(dir.path().to_str().unwrap()));
        assert!(out.iter().any(|l| l.relative_path == "robots.txt"));
    }

    #[test]
    fn export_all_candidates_covers_known_security_ids() {
        let exported = export_all_candidates();
        let ids: Vec<&str> = exported.iter().map(|(id, _)| *id).collect();
        for required in &[
            "security.csp",
            "security.hsts",
            "security.https",
            "security.exposed-env",
        ] {
            assert!(ids.contains(required), "export missing {}", required);
        }
    }

    #[test]
    fn export_all_candidates_covers_known_seo_ids() {
        let exported = export_all_candidates();
        let ids: Vec<&str> = exported.iter().map(|(id, _)| *id).collect();
        for required in &["seo.robots", "seo.sitemap.missing", "seo.canonical.missing"] {
            assert!(ids.contains(required), "export missing {}", required);
        }
    }

    /// Parity test: asserts `apps/mcp-server/src/fix_locations.json` matches the live
    /// Rust candidate table. Rewrites the file and panics when stale (same pattern as
    /// `causal_graph_json_is_in_sync_with_mcp_copy` in causal_graph.rs).
    #[test]
    fn fix_locations_json_is_in_sync_with_mcp_copy() {
        use std::collections::BTreeMap;

        // Build a BTreeMap so keys are sorted deterministically.
        let raw = export_all_candidates();
        let mut map: BTreeMap<&str, Vec<FixLocationCandidateExport>> = BTreeMap::new();
        for (id, candidates) in raw {
            map.insert(id, candidates);
        }

        let expected = serde_json::to_string_pretty(&map).expect("serialize fix_locations") + "\n";

        let manifest_dir = std::path::PathBuf::from(env!("SITECMD_SOURCE_ROOT"));
        let json_path = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("apps root")
            .join("mcp-server")
            .join("src")
            .join("fix_locations.json");

        let actual = std::fs::read_to_string(&json_path).unwrap_or_default();
        if actual != expected {
            std::fs::write(&json_path, &expected).expect("write fix_locations.json");
            panic!(
                "apps/mcp-server/src/fix_locations.json was stale (rewrote it). \
                 Review the diff with `git diff apps/mcp-server/src/fix_locations.json` and commit."
            );
        }
    }
}
