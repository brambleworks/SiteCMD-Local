import { scalar } from "./guardrail-workflow-yaml.mjs";

export const CI_WORKFLOW = ".github/workflows/ci.yml";
export const QUEUE_OR_DISPATCH =
  "github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch'";
export const PR_ONLY = "github.event_name == 'pull_request'";
export const DEPENDENCY_AUDIT =
  "needs.dependency-paths.outputs.dependencies == 'true' || github.event_name == 'workflow_dispatch'";
export const ENGINE_PIN_ONLY =
  "(github.event_name == 'merge_group' && needs.engine-pin-paths.outputs.engine == 'true') || github.event_name == 'workflow_dispatch'";
export const PUBLIC_TREE_PR = `${PR_ONLY} && github.repository == 'brambleworks/SiteCMD-Local'`;
export const PUBLIC_TREE_SKIP =
  "github.event_name != 'pull_request' || github.repository != 'brambleworks/SiteCMD-Local'";
export function requiredSkips(jobs) {
  return [...jobs]
    .filter(([id]) => id !== "CI")
    .flatMap(([id, job]) => {
      const value = scalar(job.get("if"));
      const condition =
        value?.startsWith("${{") && value.endsWith("}}") ? value.slice(3, -2).trim() : value;
      return condition ? [`\${{ !(${condition}) && '${id}' || '' }}`] : [];
    });
}
