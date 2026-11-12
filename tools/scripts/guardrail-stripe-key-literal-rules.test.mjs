import { expect, it } from "vitest";

import { stripeKeyLiteralFailures } from "./lib/guardrail-stripe-key-literal-rules.mjs";

// Built from parts, as the rule requires, so this file holds no key literal.
const LIVE = ["sk", "live", "x".repeat(24)].join("_");
const RESTRICTED = ["rk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");

function failuresWith(files) {
  return stripeKeyLiteralFailures(
    (file) => files[file],
    (dir) => Object.keys(files).some((file) => file.startsWith(`${dir}/`)),
    (dir, predicate) =>
      Object.keys(files).filter((file) => file.startsWith(`${dir}/`) && predicate(file)),
  );
}

it("prevents a committed Stripe live key that GitHub's push protection refuses", () => {
  // Bug: a near-miss fixture held a placeholder live key, and GitHub refused the push.
  const file = "apps/desktop/src-tauri/crates/engine/tests/fixtures/bundles/near-misses.html";
  expect(failuresWith({ [file]: `<p>ok</p>\n<p>${LIVE}</p> <!-- gitleaks:allow -->` })).toEqual([
    `${file}:2 - holds a Stripe live key literal, which GitHub's push protection refuses; build it from parts with concat! or format!.`,
  ]);
  expect(
    failuresWith({ "tools/scripts/probe.test.mjs": `const key = "${RESTRICTED}";` }),
  ).toHaveLength(1);
});

it("lets keys built from parts and short stubs through", () => {
  expect(
    failuresWith({
      "apps/desktop/src-tauri/src/probe.rs":
        'let key = concat!("sk_live_", "1234567890abcdefghijklmn");',
      "apps/desktop/fixture.html": "<p>rk_live_abcdefghijklmnopqrs</p>",
    }),
  ).toEqual([]);
});
