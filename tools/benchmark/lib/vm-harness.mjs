import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { digest } from "./workflow-plan.mjs";
import { guestCommand } from "./vm-guest.mjs";

export function harnessFiles() {
  const directory = fileURLToPath(new URL("../guest/", import.meta.url));
  const files = {};
  for (const name of readdirSync(directory).filter((name) => /\.(mjs|py|apparmor)$/.test(name)))
    files[`guest/${name}`] = readFileSync(path.join(directory, name), "utf8");
  const require = createRequire(import.meta.url);
  files["vendor/typescript.cjs"] = readFileSync(require.resolve("typescript"), "utf8");
  files["guest/replacement-fmd-actions.js"] = readFileSync(
    new URL("../guest/replacement-fmd-actions.js", import.meta.url),
    "utf8",
  );
  for (const name of [
    "workflow-contract",
    "workflow-plan",
    "workflow-quota",
    "workflow-controller-amendment",
    "workflow-codex-quota",
    "workflow-claude-quota",
    "workflow-continuation",
    "workflow-usage",
    "workflow-trial-usage",
    "workflow-provider-transcript",
    "workflow-model-identity",
    "repository-snapshot",
    "repository-reference",
    "repository-confirmatory-registration",
    "repository-qualification-runtime",
    "repository-runtime",
    "repository-grader-identity",
    "repository-report-continuity",
    "repository-study-arguments",
    "trial-source",
    "trial-prompt",
    "trial-candidate",
    "trial-item",
    "workflow-results",
    "workflow-artifacts",
    "workflow-store",
    "workflow-pilot",
    "workflow-repository-study",
    "workflow-confirmatory-study",
    "workflow-supplemental-study",
    "workflow-study-validity",
    "workflow-runnable-study",
    "workflow-preflight",
    "trial-invocation",
    "repository-corpus",
    "repository-scanner-eligibility",
    "confirmatory-workflow",
  ])
    files[`lib/${name}.mjs`] = readFileSync(new URL(`./${name}.mjs`, import.meta.url), "utf8");
  files["pilot-policy.json"] = readFileSync(
    new URL("../pilot-policy.json", import.meta.url),
    "utf8",
  );
  files["repository-study-policy.json"] = readFileSync(
    new URL("../repository-study-policy.json", import.meta.url),
    "utf8",
  );
  files["confirmatory-study-policy.json"] = readFileSync(
    new URL("../confirmatory-study-policy.json", import.meta.url),
    "utf8",
  );
  files["confirmatory-v3-study-policy.json"] = readFileSync(
    new URL("../confirmatory-v3-study-policy.json", import.meta.url),
    "utf8",
  );
  files["supplemental-study-policy.json"] = readFileSync(
    new URL("../supplemental-study-policy.json", import.meta.url),
    "utf8",
  );
  files["invalidated-studies.json"] = readFileSync(
    new URL("../invalidated-studies.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-calibration.json"] = readFileSync(
    new URL("../cases/repository-calibration.json", import.meta.url),
    "utf8",
  );
  files["cases/linkding-calibration.json"] = readFileSync(
    new URL("../cases/linkding-calibration.json", import.meta.url),
    "utf8",
  );
  files["cases/linkding-runtime.json"] = readFileSync(
    new URL("../cases/linkding-runtime.json", import.meta.url),
    "utf8",
  );
  files["cases/whoogle-calibration.json"] = readFileSync(
    new URL("../cases/whoogle-calibration.json", import.meta.url),
    "utf8",
  );
  files["cases/whoogle-runtime.json"] = readFileSync(
    new URL("../cases/whoogle-runtime.json", import.meta.url),
    "utf8",
  );
  files["cases/flask-reuploaded-cases.json"] = readFileSync(
    new URL("../cases/flask-reuploaded-cases.json", import.meta.url),
    "utf8",
  );
  files["cases/flask-reuploaded-runtime.json"] = readFileSync(
    new URL("../cases/flask-reuploaded-runtime.json", import.meta.url),
    "utf8",
  );
  files["cases/onekey-runtime.json"] = readFileSync(
    new URL("../cases/onekey-runtime.json", import.meta.url),
    "utf8",
  );
  files["cases/fmd-runtime.json"] = readFileSync(
    new URL("../cases/fmd-runtime.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-held-out-v1.json"] = readFileSync(
    new URL("../cases/repository-held-out-v1.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-confirmatory-v2.json"] = readFileSync(
    new URL("../cases/repository-confirmatory-v2.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-confirmatory-registration.json"] = readFileSync(
    new URL("../cases/repository-confirmatory-registration.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-confirmatory-v3.json"] = readFileSync(
    new URL("../cases/repository-confirmatory-v3.json", import.meta.url),
    "utf8",
  );
  files["cases/repository-confirmatory-v3-registration.json"] = readFileSync(
    new URL("../cases/repository-confirmatory-v3-registration.json", import.meta.url),
    "utf8",
  );
  files["repository-corpus-policy.json"] = readFileSync(
    new URL("../repository-corpus-policy.json", import.meta.url),
    "utf8",
  );
  for (const name of [
    "run-next.mjs",
    "prepare-calibration.mjs",
    "qualify-repository.mjs",
    "selftest-repository.mjs",
    "prepare-repository-runtime.mjs",
    "prepare-repository-study.mjs",
    "prepare-confirmatory-study.mjs",
    "prepare-supplemental-study.mjs",
    "prepare-corpus-runtime.mjs",
    "qualify-corpus-repository.mjs",
  ])
    files[`host/${name}`] = readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
  files["host/vm-harness.mjs"] = readFileSync(new URL("./vm-harness.mjs", import.meta.url), "utf8");
  files["host/vm-trial-export.mjs"] = readFileSync(
    new URL("./vm-trial-export.mjs", import.meta.url),
    "utf8",
  );
  return files;
}

export function deployHarness() {
  const files = harnessFiles();
  const id = digest(files);
  const destination = `/srv/sitecmd-benchmark/controllers/${id}`;
  guestCommand(["sudo", "node", "--input-type=module", "-e", files["guest/install-harness.mjs"]], {
    input: JSON.stringify({ id, files }),
    capture: true,
  });
  return { id, directory: `${destination}/guest`, files };
}
