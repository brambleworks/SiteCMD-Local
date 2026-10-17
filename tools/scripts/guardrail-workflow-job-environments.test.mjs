import { expect, it } from "vitest";
import { workflowJobEnvironments } from "./lib/guardrail-text-utils.mjs";

const job = "  publish:\n    environment: npm-publish\n";

it.each(["jobs:", "jobs:   ", "jobs: # every job", "jobs:\t#comment"])(
  "reads job environments after %j",
  (header) => {
    expect(workflowJobEnvironments(`${header}\n${job}`)).toEqual([
      { job: "publish", block: "environment: npm-publish\n" },
    ]);
  },
);

it.each(["jobs: x", "jobs:x", " jobs:", "jobs"])("finds no jobs block after %j", (header) => {
  expect(workflowJobEnvironments(`${header}\n${job}`)).toEqual([]);
});
