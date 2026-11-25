CREATE TABLE work_items_rebuild (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_url TEXT NOT NULL,
    source TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    detail_json TEXT,
    scan_ref INTEGER,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    resolved_at INTEGER,
    page_url TEXT,
    fix_prompt TEXT,
    manual_fix TEXT,
    why_it_matters TEXT,
    confidence TEXT,
    domain TEXT,
    relative_path TEXT,
    line INTEGER,
    check_status TEXT CHECK (check_status IS NULL OR check_status IN
        ('pass', 'fail', 'warn', 'skipped', 'not_applicable')),
    confidence_reason TEXT,
    producer_check_id TEXT,
    producer_fix_prompt TEXT,
    producer_category TEXT CHECK (producer_category IS NULL OR producer_category IN
        ('security', 'performance', 'seo', 'accessibility', 'compliance', 'config', 'polish')),
    first_seen_scan_ref INTEGER,
    resolved_scan_ref INTEGER
);

INSERT INTO work_items_rebuild (
    id, project_id, env_url, source, signal_id, check_id, category, severity,
    title, description, detail_json, scan_ref, first_seen_at, last_seen_at,
    resolved_at, page_url, fix_prompt, manual_fix, why_it_matters, confidence,
    domain, relative_path, line, check_status, confidence_reason, producer_check_id,
    producer_fix_prompt, producer_category, first_seen_scan_ref, resolved_scan_ref
)
SELECT id, project_id, env_url, source, signal_id, check_id, category, severity,
       title, description, detail_json, scan_ref, first_seen_at, last_seen_at,
       resolved_at, page_url, fix_prompt, manual_fix, why_it_matters, confidence,
       domain, relative_path, line, check_status, confidence_reason, producer_check_id,
       producer_fix_prompt, producer_category, first_seen_scan_ref, resolved_scan_ref
FROM work_items;

CREATE TABLE scan_findings_rebuild (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    occurrence_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('web_scan', 'code_scan')),
    canonical_check_id TEXT NOT NULL,
    producer_check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    producer_category TEXT NOT NULL,
    domain TEXT,
    verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'fail', 'warn', 'skipped', 'not_applicable')),
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    confidence TEXT NOT NULL CHECK(confidence IN ('confirmed', 'high', 'needs_review')),
    confidence_reason TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    fix_prompt TEXT,
    producer_fix_prompt TEXT,
    manual_fix TEXT,
    why_it_matters TEXT,
    verification_hint TEXT,
    raw_data TEXT,
    detail_json TEXT,
    location_kind TEXT NOT NULL CHECK(location_kind IN
        ('page', 'file', 'project', 'site', 'none')),
    page_url TEXT,
    relative_path TEXT,
    line INTEGER,
    UNIQUE(run_id, ordinal),
    UNIQUE(run_id, occurrence_id)
);

INSERT INTO scan_findings_rebuild (
    id, run_id, ordinal, occurrence_id, source, canonical_check_id, producer_check_id,
    category, producer_category, domain, verdict, severity, confidence, confidence_reason,
    title, description, fix_prompt, producer_fix_prompt, manual_fix, why_it_matters,
    verification_hint, raw_data, detail_json, location_kind, page_url, relative_path, line
)
SELECT id, run_id, ordinal, occurrence_id, source, canonical_check_id, producer_check_id,
       category, producer_category, domain, verdict, severity, confidence, confidence_reason,
       title, description, fix_prompt, producer_fix_prompt, manual_fix, why_it_matters,
       verification_hint, raw_data, detail_json, location_kind, page_url, relative_path, line
FROM scan_findings;

-- Copy sequence high-water marks so deleted IDs stay retired.
DELETE FROM sqlite_sequence WHERE name IN ('work_items_rebuild', 'scan_findings_rebuild');
INSERT INTO sqlite_sequence (name, seq)
SELECT name || '_rebuild', seq FROM sqlite_sequence WHERE name IN ('work_items', 'scan_findings');

-- Stage child rows so the work_items rebuild can run with foreign keys enabled.
CREATE TEMP TABLE historical_enrichments_backup AS
SELECT work_item_id, integration, payload, created_at FROM historical_enrichments;
DELETE FROM historical_enrichments;

DROP TABLE work_items;
ALTER TABLE work_items_rebuild RENAME TO work_items;

INSERT INTO historical_enrichments (work_item_id, integration, payload, created_at)
SELECT work_item_id, integration, payload, created_at FROM historical_enrichments_backup;
DROP TABLE historical_enrichments_backup;

DROP TABLE scan_findings;
ALTER TABLE scan_findings_rebuild RENAME TO scan_findings;

CREATE INDEX idx_work_items_active
    ON work_items(project_id, env_url, resolved_at);
CREATE INDEX idx_work_items_canonical_scan_ref
    ON work_items(source, scan_ref);
CREATE INDEX idx_work_items_check_id
    ON work_items(check_id);
CREATE INDEX idx_work_items_first_seen
    ON work_items(first_seen_at);
CREATE INDEX idx_work_items_page_url
    ON work_items(project_id, env_url, page_url)
    WHERE resolved_at IS NULL AND page_url IS NOT NULL;
CREATE INDEX idx_work_items_project_first_seen
    ON work_items(project_id, first_seen_at);
CREATE INDEX idx_work_items_resolved_scan_ref
    ON work_items(source, resolved_scan_ref)
    WHERE resolved_scan_ref IS NOT NULL;
CREATE INDEX idx_work_items_source_env_resolved
    ON work_items (source, env_url, resolved_at DESC)
    WHERE resolved_at IS NOT NULL;
CREATE INDEX idx_work_items_source_scan_ref
    ON work_items(source, scan_ref);
CREATE UNIQUE INDEX uq_work_items_active
    ON work_items(project_id, env_url, source, signal_id)
    WHERE resolved_at IS NULL;

CREATE INDEX idx_scan_findings_check
    ON scan_findings(canonical_check_id, run_id);
CREATE INDEX idx_scan_findings_occurrence
    ON scan_findings(occurrence_id, run_id);
CREATE INDEX idx_scan_findings_run
    ON scan_findings(run_id, ordinal);
