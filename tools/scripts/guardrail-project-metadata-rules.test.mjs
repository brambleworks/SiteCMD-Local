import { expect, it } from "vitest";

import { realRead, mustMutate } from "./guardrail-test-support.mjs";
import { projectMetadataReadFailures } from "./lib/guardrail-project-metadata-rules.mjs";

it("rejects project metadata reads that bypass the real bounded project reader", () => {
  const path = "apps/desktop/src-tauri/src/core/project_listing.rs";
  const failures = projectMetadataReadFailures((file) =>
    file === path
      ? mustMutate(
          realRead(file),
          "read_project_path(&self.dir, path, limit)",
          "read_unbounded(path)",
        )
      : realRead(file),
  );
  expect(failures).toContain(
    "Project detection must use shared bounded reads for repository-controlled metadata.",
  );
});
