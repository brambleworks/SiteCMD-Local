#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

import { prTitleAndBodyFailures } from "./lib/commit-message-rules.mjs";

function main() {
  const { values } = parseArgs({
    options: {
      title: { type: "string" },
      "body-file": { type: "string" },
      author: { type: "string" },
    },
  });
  if (values.title === undefined || !values["body-file"] || !values.author) {
    throw new Error("Use --title <title> --body-file <file> --author <login>.");
  }
  if (values.author === "dependabot[bot]") return;

  const body = readFileSync(values["body-file"], "utf8");
  const failures = prTitleAndBodyFailures(values.title, body);
  if (failures.length > 0) {
    console.error(
      `Pull request title and body must be clear, concise, and written in plain English:\n- ${failures.join("\n- ")}`,
    );
    process.exitCode = 1;
  }
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 2;
}
