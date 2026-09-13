ALTER TABLE agent_requests ADD COLUMN target_relative_path TEXT
    CHECK (target_relative_path IS NULL OR (kind = 'start_fix' AND length(target_relative_path) > 0));

ALTER TABLE agent_requests ADD COLUMN target_line INTEGER
    CHECK (target_line IS NULL OR (
        target_relative_path IS NOT NULL AND typeof(target_line) = 'integer'
        AND target_line BETWEEN 1 AND 4294967295
    ));
