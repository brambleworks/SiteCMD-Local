//! OSV.dev batch vulnerability client.

use crate::{
    core::scan_types::Severity,
    updates::types::{Ecosystem, InstalledPackage},
};
use cvss::Cvss;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

/// A known vulnerability affecting an installed package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub package_name: String,
    pub ecosystem: Ecosystem,
    pub current_version: String,
    pub source: String,
    pub is_dev: bool,
    pub workspace_members: Vec<String>,
    pub advisory_id: String,
    pub severity: Severity,
    pub summary: String,
    pub advisory_url: Option<String>,
}

/// Map our ecosystem enum to OSV.dev ecosystem names
pub(crate) fn osv_ecosystem(eco: &Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::Composer => Some("Packagist"),
        Ecosystem::Python => Some("PyPI"),
        Ecosystem::Ruby => Some("RubyGems"),
        Ecosystem::Go => Some("Go"),
        Ecosystem::Rust => Some("crates.io"),
        // WordPress and Drupal aren't in OSV - handled by their own APIs
        Ecosystem::WordPress | Ecosystem::Drupal => None,
    }
}

/// Result of one OSV sweep over the installed packages.
pub struct OsvScan {
    pub vulns: Vec<VulnerabilityInfo>,
}

const OSV_API_BASE: &str = "https://api.osv.dev";

/// Query OSV.dev for known vulnerabilities affecting installed packages.
/// Uses the batch API to check all packages in a single request.
pub async fn check_vulnerabilities(packages: &[InstalledPackage]) -> OsvScan {
    check_vulnerabilities_at(packages, OSV_API_BASE).await
}

/// [`check_vulnerabilities`] with an injectable API base so tests can drive
/// the batch-failure path against a local server instead of api.osv.dev.
async fn check_vulnerabilities_at(packages: &[InstalledPackage], api_base: &str) -> OsvScan {
    // Filter to ecosystems OSV supports
    let queryable: Vec<&InstalledPackage> = packages
        .iter()
        .filter(|p| osv_ecosystem(&p.ecosystem).is_some())
        .collect();

    if queryable.is_empty() {
        return OsvScan { vulns: Vec::new() };
    }

    let client = crate::http_client::client().clone();

    // OSV batch API accepts up to 1000 queries per request
    let mut all_vulns = Vec::new();

    for chunk in queryable.chunks(crate::constants::OSV_BATCH_SIZE) {
        match query_batch(&client, chunk, api_base).await {
            Ok(vulns) => all_vulns.extend(vulns),
            Err(e) => tracing::warn!("OSV batch query failed: {}", e),
        }
    }

    OsvScan { vulns: all_vulns }
}

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Deserialize)]
struct OsvQueryResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
pub(crate) struct OsvVuln {
    pub(crate) id: String,
    pub(crate) summary: Option<String>,
    pub(crate) severity: Option<Vec<OsvSeverity>>,
    pub(crate) affected: Option<Vec<OsvAffected>>,
    pub(crate) references: Option<Vec<OsvReference>>,
}

#[derive(Deserialize)]
pub(crate) struct OsvSeverity {
    #[serde(rename = "type")]
    pub(crate) severity_type: Option<String>,
    pub(crate) score: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct OsvAffected {
    pub(crate) package: Option<OsvPackage>,
    pub(crate) severity: Option<Vec<OsvSeverity>>,
}

#[derive(Deserialize)]
pub(crate) struct OsvReference {
    #[serde(rename = "type")]
    pub(crate) ref_type: Option<String>,
    pub(crate) url: Option<String>,
}

async fn query_batch(
    client: &Client,
    packages: &[&InstalledPackage],
    api_base: &str,
) -> Result<Vec<VulnerabilityInfo>, String> {
    let queries: Vec<OsvQuery> = packages
        .iter()
        .filter_map(|p| {
            let eco = osv_ecosystem(&p.ecosystem)?;
            Some(OsvQuery {
                package: OsvPackage {
                    name: p.name.clone(),
                    ecosystem: eco.to_string(),
                },
                version: p.version.clone(),
            })
        })
        .collect();

    let body = OsvBatchRequest { queries };
    let resp = client
        .post(format!("{}/v1/querybatch", api_base))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("OSV request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("OSV returned status {}", resp.status()));
    }

    let batch: OsvBatchResponse = crate::http_client::read_json_limited(
        resp,
        crate::constants::OSV_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .map_err(|e| format!("OSV parse failed: {}", e))?;
    if batch.results.len() != packages.len() {
        return Err(format!(
            "OSV returned {} results for {} queries",
            batch.results.len(),
            packages.len()
        ));
    }

    // Batch results contain only IDs and modification times, so fetch each
    // unique advisory for severity and references.
    let ids: Vec<String> = batch
        .results
        .iter()
        .filter_map(|r| r.vulns.as_ref())
        .flatten()
        .map(|v| v.id.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let details = fetch_vuln_details(client, &ids, api_base).await;

    let mut results = build_vuln_infos(packages, &batch, &details);
    // Deduplicate: keep highest severity per package
    deduplicate_vulns(&mut results);

    Ok(results)
}

/// Fetch the full OSV record for each advisory ID via `GET /v1/vulns/{id}`.
/// A failed fetch is omitted; `build_vuln_infos` falls back to the
/// shallow querybatch vuln for that ID.
async fn fetch_vuln_details(
    client: &Client,
    ids: &[String],
    api_base: &str,
) -> HashMap<String, OsvVuln> {
    let mut map = HashMap::new();
    for id in ids {
        if let Some(detail) = fetch_vuln_detail(client, id, api_base).await {
            map.insert(id.clone(), detail);
        }
    }
    map
}

async fn fetch_vuln_detail(client: &Client, id: &str, api_base: &str) -> Option<OsvVuln> {
    let url = format!("{}/v1/vulns/{}", api_base, id);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    crate::http_client::read_json_limited::<OsvVuln>(
        resp,
        crate::constants::OSV_RESPONSE_MAX_BYTES,
        crate::constants::BODY_READ_TIMEOUT,
    )
    .await
    .ok()
}

/// Build the per-package vulnerability list from a querybatch response, using
/// the fetched full advisory records (`details`) and falling back to the
/// shallow querybatch vuln when a detail fetch failed. Pure; tested directly.
fn build_vuln_infos(
    packages: &[&InstalledPackage],
    batch: &OsvBatchResponse,
    details: &HashMap<String, OsvVuln>,
) -> Vec<VulnerabilityInfo> {
    let mut results = Vec::new();
    for (i, query_result) in batch.results.iter().enumerate() {
        let Some(pkg) = packages.get(i) else {
            continue;
        };
        let Some(vulns) = &query_result.vulns else {
            continue;
        };
        for shallow in vulns {
            let vuln = details.get(&shallow.id).unwrap_or(shallow);
            results.push(VulnerabilityInfo {
                package_name: pkg.name.clone(),
                ecosystem: pkg.ecosystem.clone(),
                current_version: pkg.version.clone(),
                source: pkg.source.clone(),
                is_dev: pkg.is_dev,
                workspace_members: pkg.workspace_members.clone(),
                advisory_id: vuln.id.clone(),
                severity: extract_severity(vuln, pkg),
                summary: vuln
                    .summary
                    .clone()
                    .unwrap_or_else(|| "Security vulnerability".to_string()),
                advisory_url: extract_advisory_url(vuln),
            });
        }
    }
    results
}

pub(crate) fn extract_severity(vuln: &OsvVuln, package: &InstalledPackage) -> Severity {
    let package_severities: Vec<&OsvSeverity> = vuln
        .affected
        .iter()
        .flatten()
        .filter(|affected| affected_matches_package(affected, package))
        .filter_map(|affected| affected.severity.as_deref())
        .flatten()
        .collect();
    if !package_severities.is_empty() {
        return highest_severity(package_severities.into_iter()).unwrap_or(Severity::High);
    }

    highest_severity(vuln.severity.iter().flatten()).unwrap_or(Severity::High)
}

pub(crate) fn parse_cvss_score(score_str: &str) -> Option<f64> {
    if let Ok(score) = score_str.parse::<f64>() {
        return (score.is_finite() && (0.0..=10.0).contains(&score)).then_some(score);
    }
    Cvss::from_str(score_str).ok().map(|vector| vector.score())
}

pub(crate) fn cvss_to_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn highest_severity<'a>(severities: impl Iterator<Item = &'a OsvSeverity>) -> Option<Severity> {
    severities
        .filter_map(severity_from_osv)
        .max_by_key(|severity| severity.impact_rank())
}

fn severity_from_osv(severity: &OsvSeverity) -> Option<Severity> {
    let score = severity.score.as_deref()?.trim();
    match score.to_ascii_lowercase().as_str() {
        "critical" => return Some(Severity::Critical),
        "high" => return Some(Severity::High),
        "moderate" | "medium" => return Some(Severity::Medium),
        "low" => return Some(Severity::Low),
        _ => {}
    }

    if severity
        .severity_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("CVSS_V2"))
    {
        return parse_cvss_v2_score(score).and_then(cvss_v2_to_severity);
    }
    parse_cvss_score(score).map(cvss_to_severity)
}

fn parse_cvss_v2_score(value: &str) -> Option<f64> {
    if let Ok(score) = value.parse::<f64>() {
        return (score.is_finite() && (0.0..=10.0).contains(&score)).then_some(score);
    }

    let vector = value.strip_prefix("CVSS:2.0/").unwrap_or(value);
    let mut metrics = CvssV2Metrics::default();
    for metric in vector.split('/') {
        let (name, value) = metric.split_once(':')?;
        match name {
            "AV" => set_metric(&mut metrics.access_vector, cvss_v2_access_vector(value)?)?,
            "AC" => set_metric(
                &mut metrics.access_complexity,
                cvss_v2_access_complexity(value)?,
            )?,
            "Au" => set_metric(&mut metrics.authentication, cvss_v2_authentication(value)?)?,
            "C" => set_metric(&mut metrics.confidentiality, cvss_v2_impact(value)?)?,
            "I" => set_metric(&mut metrics.integrity, cvss_v2_impact(value)?)?,
            "A" => set_metric(&mut metrics.availability, cvss_v2_impact(value)?)?,
            // These temporal and environmental metrics do not affect the base score.
            "E" | "RL" | "RC" | "CDP" | "TD" | "CR" | "IR" | "AR" => {}
            _ => return None,
        }
    }

    metrics.score()
}

#[derive(Default)]
struct CvssV2Metrics {
    access_vector: Option<f64>,
    access_complexity: Option<f64>,
    authentication: Option<f64>,
    confidentiality: Option<f64>,
    integrity: Option<f64>,
    availability: Option<f64>,
}

impl CvssV2Metrics {
    fn score(self) -> Option<f64> {
        let impact = 10.41
            * (1.0
                - (1.0 - self.confidentiality?)
                    * (1.0 - self.integrity?)
                    * (1.0 - self.availability?));
        if impact == 0.0 {
            return Some(0.0);
        }
        let exploitability =
            20.0 * self.access_vector? * self.access_complexity? * self.authentication?;
        let score = ((0.6 * impact + 0.4 * exploitability - 1.5) * 1.176).clamp(0.0, 10.0);
        Some((score * 10.0).round() / 10.0)
    }
}

fn set_metric(slot: &mut Option<f64>, value: f64) -> Option<()> {
    if slot.replace(value).is_some() {
        return None;
    }
    Some(())
}

fn cvss_v2_access_vector(value: &str) -> Option<f64> {
    match value {
        "L" => Some(0.395),
        "A" => Some(0.646),
        "N" => Some(1.0),
        _ => None,
    }
}

fn cvss_v2_access_complexity(value: &str) -> Option<f64> {
    match value {
        "H" => Some(0.35),
        "M" => Some(0.61),
        "L" => Some(0.71),
        _ => None,
    }
}

fn cvss_v2_authentication(value: &str) -> Option<f64> {
    match value {
        "M" => Some(0.45),
        "S" => Some(0.56),
        "N" => Some(0.704),
        _ => None,
    }
}

fn cvss_v2_impact(value: &str) -> Option<f64> {
    match value {
        "N" => Some(0.0),
        "P" => Some(0.275),
        "C" => Some(0.66),
        _ => None,
    }
}

fn cvss_v2_to_severity(score: f64) -> Option<Severity> {
    if !score.is_finite() || !(0.0..=10.0).contains(&score) {
        return None;
    }
    Some(if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    })
}

fn affected_matches_package(affected: &OsvAffected, package: &InstalledPackage) -> bool {
    let Some(osv_package) = &affected.package else {
        return false;
    };
    let Some(ecosystem) = osv_ecosystem(&package.ecosystem) else {
        return false;
    };
    osv_package.ecosystem.eq_ignore_ascii_case(ecosystem)
        && package_names_match(&package.ecosystem, &osv_package.name, &package.name)
}

fn package_names_match(ecosystem: &Ecosystem, left: &str, right: &str) -> bool {
    match ecosystem {
        Ecosystem::Python => {
            normalize_python_package_name(left) == normalize_python_package_name(right)
        }
        Ecosystem::Go => left == right,
        _ => left.eq_ignore_ascii_case(right),
    }
}

fn normalize_python_package_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
                separator = true;
            }
        } else {
            normalized.extend(character.to_lowercase());
            separator = false;
        }
    }
    normalized
}

pub(crate) fn extract_advisory_url(vuln: &OsvVuln) -> Option<String> {
    // Prefer ADVISORY type, then WEB, then any URL
    if let Some(refs) = &vuln.references {
        // Priority: ADVISORY > WEB > any
        for ref_type in &["ADVISORY", "WEB"] {
            if let Some(r) = refs
                .iter()
                .find(|r| r.ref_type.as_deref() == Some(ref_type))
            {
                return r.url.clone();
            }
        }
        // Fallback: first URL
        return refs.first().and_then(|r| r.url.clone());
    }
    // Generate OSV URL from ID
    Some(format!("https://osv.dev/vulnerability/{}", vuln.id))
}

/// Deduplicate: keep only the most severe vulnerability per package
pub(crate) fn deduplicate_vulns(vulns: &mut Vec<VulnerabilityInfo>) {
    let mut best: HashMap<String, usize> = HashMap::new();

    for (i, v) in vulns.iter().enumerate() {
        let key = format!("{}:{}", v.ecosystem.label(), v.package_name);
        if let Some(&existing_idx) = best.get(&key) {
            let existing_sev = vulns[existing_idx].severity.impact_rank();
            let new_sev = v.severity.impact_rank();
            if new_sev > existing_sev {
                best.insert(key, i);
            }
        } else {
            best.insert(key, i);
        }
    }

    let keep: std::collections::HashSet<usize> = best.values().cloned().collect();
    let mut i = 0;
    vulns.retain(|_| {
        let result = keep.contains(&i);
        i += 1;
        result
    });
}

#[cfg(test)]
#[path = "osv_tests.rs"]
mod tests;
