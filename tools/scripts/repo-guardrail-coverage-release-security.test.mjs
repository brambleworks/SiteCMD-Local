import { it } from "vitest";
import {
  expectGuardrailFailure,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

const { releaseArtifactSafetyFailures, releaseWorkflowSafetyFailures } = rules;

it("fails when release-candidate notes are read from the signed tag body", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const scriptPath = ".github/scripts/release/build-candidate-manifest.sh";
      const script = readFixtureFile(fixtureRoot, scriptPath);
      writeFixtureFile(
        fixtureRoot,
        scriptPath,
        mustMutate(
          script,
          'NOTES=$(node ./tools/scripts/check-changelog-notes.mjs --release-notes "$VERSION")',
          "NOTES=$(git tag -l --format='%(contents:body)' \"$TAG_NAME\")",
        ),
      );
    },
    "read versioned changelog notes without exposing the signed-tag signature block",
  );
});

it("fails when the permanent updater key reaches a product build", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
          [
            '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
            "          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}",
          ].join("\n"),
        ),
      );
    },
    "release.yml CLI builds must require candidate approval, fetch the pinned engine before compiling",
  );
});

it("fails when production updater signing no longer depends on the approved build", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          "    needs: [prepare-candidate, build]",
          "    needs: prepare-candidate",
        ),
      );
    },
    "release.yml must expose the permanent updater key only inside the release-updater-signing environment",
  );
});

it("fails when protected tag trust can drift from the reviewed signer list", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflowPath = ".github/workflows/release.yml";
      const workflow = readFixtureFile(fixtureRoot, workflowPath);
      writeFixtureFile(
        fixtureRoot,
        workflowPath,
        mustMutate(
          workflow,
          'if ! cmp -s "$REVIEWED_SIGNERS_FILE" "$PROTECTED_SIGNERS_FILE"; then',
          'if ! cmp -s "$PROTECTED_SIGNERS_FILE" "$PROTECTED_SIGNERS_FILE"; then',
        ),
      );
    },
    "protected release-tag-trust signer list",
  );
});

it("fails when the credentialed publisher checks out product source", () => {
  expectGuardrailFailure(
    releaseWorkflowSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          "    steps:\n      - uses: actions/download-artifact@",
          [
            "    steps:",
            "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "      - uses: actions/download-artifact@",
          ].join("\n"),
        ),
      );
    },
    "release.yml must publish only after every secretless verification leg",
  );
});

it("fails when R2 credentials escape the isolated publisher", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
          [
            '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
            "          AWS_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}",
          ].join("\n"),
        ),
      );
    },
    "release.yml must keep R2 credentials and the releases-audience OIDC token request in the checkout-free publish-release job",
  );
});

it("fails when a job outside the publishers requests a releases-audience OIDC token", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
          [
            '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"',
            '          RELEASES_TOKEN_URL: "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://releases.sitecmd.com"',
          ].join("\n"),
        ),
      );
    },
    "release.yml must keep R2 credentials and the releases-audience OIDC token request in the checkout-free publish-release job",
  );
});

it("fails when the stored publish key returns to the release workflow", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          "      - name: Advance the production release manifest\n",
          [
            "      - name: Advance the production release manifest",
            "        env:",
            "          RELEASE_ADMIN_KEY: ${{ secrets.RELEASE_ADMIN_KEY }}",
            "",
          ].join("\n"),
        ),
      );
    },
    "RELEASE_ADMIN_KEY must not return to the release pipeline (found in .github/workflows/release.yml)",
  );
});

for (const [form, environment] of [
  ["the short form", "    environment: release-publish\n"],
  [
    "a url before the name",
    "    environment:\n      url: https://example.com\n      name: release-publish\n",
  ],
  ["the flow form", "    environment: { name: release-publish }\n"],
  ["a quoted name", '    environment:\n      name: "release-publish"\n'],
  ["an expression", "    environment: ${{ inputs.target }}\n"],
]) {
  it(`fails when another release job joins release-publish through ${form}`, () => {
    expectGuardrailFailure(
      releaseArtifactSafetyFailures,
      (fixtureRoot) => {
        const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
        writeFixtureFile(
          fixtureRoot,
          ".github/workflows/release.yml",
          mustMutate(
            workflow,
            "    environment:\n      name: release-updater-signing\n    steps:\n      - uses: actions/checkout@",
            `${environment}    steps:\n      - uses: actions/checkout@`,
          ),
        );
      },
      ".github/workflows/release.yml#validate-updater-key",
    );
  });
}

it("fails when publish-npm moves back into release-publish", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(workflow, "      name: npm-publish\n", "      name: release-publish\n"),
      );
    },
    "may use the release-publish environment (found: .github/workflows/release.yml#publish-npm,",
  );
});

it("fails when another job joins npm-publish", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/manual-npm.yml",
        [
          "name: Manual npm publish",
          "on:",
          "  workflow_dispatch:",
          "jobs:",
          "  publish:",
          "    runs-on: ubuntu-22.04",
          "    permissions:",
          "      id-token: write",
          "    environment: npm-publish",
          "    steps:",
          "      - run: npm publish",
          "",
        ].join("\n"),
      );
    },
    "(found: .github/workflows/manual-npm.yml#publish, .github/workflows/release.yml#publish-npm)",
  );
});

it("fails when a stored npm token returns to the npm publish", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          "          VERSION: ${{ needs.prepare-candidate.outputs.version }}\n        shell: bash\n        run: bash .github/scripts/release/publish-npm-packages.sh\n",
          "          VERSION: ${{ needs.prepare-candidate.outputs.version }}\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n        shell: bash\n        run: bash .github/scripts/release/publish-npm-packages.sh\n",
        ),
      );
    },
    "A stored npm token must not return to the release pipeline (found in .github/workflows/release.yml)",
  );
});

it("fails when the shipped CLI build drops the Connected service endpoint", () => {
  expectGuardrailFailure(
    releaseArtifactSafetyFailures,
    (fixtureRoot) => {
      const workflow = readFixtureFile(fixtureRoot, ".github/workflows/release.yml");
      writeFixtureFile(
        fixtureRoot,
        ".github/workflows/release.yml",
        mustMutate(
          workflow,
          '          SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"\n',
          "",
        ),
      );
    },
    "release.yml must bake SITECMD_CONNECTED_ENDPOINT",
  );
});
