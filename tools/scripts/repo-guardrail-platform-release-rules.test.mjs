import fs from "node:fs";
import { describe, expect, it } from "vitest";
import { expectGuardrailFailure, mustMutate, realRead, rules } from "./guardrail-test-support.mjs";

const cliReleaseWorkflow = ".github/workflows/release.yml";

const {
  ciCostSafetyFailures,

  releaseWorkflowSafetyFailures,
} = rules;

describe("release pipeline probe and CRLF rules", () => {
  const run = (mutate = (_file, source) => source) =>
    releaseWorkflowSafetyFailures((file) => mutate(file, realRead(file)));

  it("passes the real repository", () => {
    expect(run()).toEqual([]);
  });

  it("rejects a deleted nextest configuration while preflight selects ci", () => {
    const config = "apps/desktop/src-tauri/.config/nextest.toml";
    expectGuardrailFailure(
      releaseWorkflowSafetyFailures,
      (overlay) => overlay.set(config, rules.OVERLAY_DELETED),
      `release.yml uses nextest profile ci, but ${config} has no [profile.ci] table.`,
    );
  });

  it.each([
    [
      "conditional fetch",
      cliReleaseWorkflow,
      "- name: Fetch the pinned engine",
      "- name: Fetch the pinned engine\n        if: false",
    ],
    [
      "commented unset",
      ".github/scripts/release/build-cli.sh",
      "unset SITECMD_ENGINE_UNPINNED",
      "# unset SITECMD_ENGINE_UNPINNED",
    ],
  ])("rejects a release build with %s", (_scenario, changed, before, after) => {
    // A release build can bypass provisioning or inherit the unpinned flag.
    const failures = run((file, source) =>
      file === changed ? mustMutate(source, before, after) : source,
    );
    expect(failures.join("\n")).toContain("fetch the pinned engine before compiling");
  });

  it("rejects a fetch deferred until after the release build", () => {
    // The build can start before the pinned module exists.
    const fetch = "        run: pnpm engine:fetch";
    const build = "        run: bash .github/scripts/release/build-cli.sh";
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const start = source.indexOf("\n  build:");
      const job = mustMutate(source.slice(start), fetch, "        run: echo skipped");
      return source.slice(0, start) + mustMutate(job, build, `${build}\n      - ${fetch.trim()}`);
    });
    expect(failures.join("\n")).toContain("fetch the pinned engine before compiling");
  });

  it.each([
    ["engine lock", "            engine.lock\n"],
    ["public key", "            .github/actions/setup-sitecmd/updater-public-key.pub\n"],
  ])("rejects a verifier missing the %s in its checkout", (_scenario, removed) => {
    // Pin verification can bypass the approved lock or trust root.
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const start = source.indexOf("\n  verify-release:");
      return source.slice(0, start) + mustMutate(source.slice(start), removed, "");
    });
    expect(failures.join("\n")).toContain("must verify signed payloads and platform signatures");
  });

  it("rejects pin verification before Windows signature verification", () => {
    // Pin verification executes a Windows binary before checking its signature.
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const windows = source.indexOf("      - name: Verify Windows CLI and Authenticode signature");
      const pin = source.indexOf("      - name: Verify the embedded engine pin");
      const end = source.indexOf("\n  publish-release:");
      return (
        source.slice(0, windows) +
        source.slice(pin, end) +
        source.slice(windows, pin) +
        source.slice(end)
      );
    });
    expect(failures.join("\n")).toContain("must verify signed payloads and platform signatures");
  });

  it.each([
    [
      "target condition",
      "- name: Verify the embedded engine pin",
      "- name: Verify the embedded engine pin\n        if: matrix.target == 'linux-x86_64'",
    ],
    [
      "missing Intel check",
      "            node tools/scripts/verify-engine-pin.mjs cli-check/sitecmd-x86_64\n",
      "",
    ],
  ])("rejects release pin verification with %s", (_scenario, before, after) => {
    // The release Verifier can skip a platform or the Intel macOS slice.
    const failures = run((file, source) =>
      file === cliReleaseWorkflow ? mustMutate(source, before, after) : source,
    );
    expect(failures.join("\n")).toContain(
      "must verify the embedded pin on every target and the x86_64 macOS slice",
    );
  });

  it("catches a publisher that stopped uploading the signed checksum manifest", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("          add_upload payload/SHA256SUMS.minisig SHA256SUMS.minisig\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped checking the checksum manifest signature", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(
            '"$verifier" "$public_key" payload/SHA256SUMS checksum-signature.sig',
            "true",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped binding the CLI archive to the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace('verify_listed "$dir/$cli_archive"\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a verifier that stopped binding the engine lock to the candidate", () => {
    // A different engine lock can satisfy archive verification after candidate approval.
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace('test "$(sha256_file engine.lock)" =', ":")
        : source,
    );
    expect(failures.join("\n")).toContain("bind the checked-out engine lock");
  });

  it("catches a verify_listed whose body no longer reads the manifest", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(/verify_listed\(\) \{[\s\S]*?\n\}/, "verify_listed() {\n  :\n}")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  const advanceStepBlock = (source) => {
    const start = source.indexOf("      - name: Advance the production release manifest");
    const end = source.indexOf("\n      - ", start);
    return source.slice(start, end + 1);
  };

  it("is not fooled by a decoy comment when the manifest advance moves after the release", () => {
    const decoy = "      # Advance the production release manifest ran in the step above\n";
    const attestHeader = "      - name: Attest build provenance for the published artifacts\n";
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const step = advanceStepBlock(source);
      return source.replace(step, decoy).replace(attestHeader, `${step}${attestHeader}`);
    });
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("is not fooled by a decoy comment that literally names the releases-admin URL", () => {
    // Unlike the paraphrase above, this decoy quotes the exact needle
    // orderedBefore searches for, planted ahead of the real (now displaced)
    // step; a raw indexOf would find the comment and wrongly call this ordered.
    const decoy = "      # https://releases.sitecmd.com/api/releases-admin ran above already\n";
    const attestHeader = "      - name: Attest build provenance for the published artifacts\n";
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const step = advanceStepBlock(source);
      return source.replace(step, decoy).replace(attestHeader, `${step}${attestHeader}`);
    });
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a publisher that drops the upload-plan cross-check", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("          while read -r hash name; do\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches an upload-plan cross-check whose lookup is a no-op", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            'grep -Fq "$(printf \'\\tv%s/%s\\t%s\' "$VERSION" "$name" "$hash")" publication/upload-plan.tsv',
            "true",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("release-wide SHA256SUMS");
  });

  it("catches a publisher that leaves an existing Release unrepaired", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            '              gh release upload "$TAG_NAME" "payload/$asset" \\\n                --repo "$GITHUB_REPOSITORY" --clobber\n',
            "",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("must repair an existing Release");
  });

  it("catches a publisher that stopped failing on a draft Release", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            `if [ "$(jq -r '.isDraft' release-state.json)" = "true" ]; then`,
            "if false; then",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("must repair an existing Release");
  });

  it("catches a smoke test whose terminal failure exit is dropped", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow ? source.replace('          exit "$fail"\n', "") : source,
    );
    expect(failures.join("\n")).toContain("public smoke test");
  });

  it("catches a smoke-test curl that stops announcing the monitor User-Agent", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace('latest=$(curl -fsSL -A "$SMOKE_UA"', "latest=$(curl -fsSL")
        : source,
    );
    expect(failures.join("\n")).toContain('-A "$SMOKE_UA" on every curl request');
  });

  it("catches a smoke test whose User-Agent literal drifts", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace('SMOKE_UA="SiteCMD-Release-Smoke/1"', 'SMOKE_UA="curl/8"')
        : source,
    );
    expect(failures.join("\n")).toContain("SiteCMD-Release-Smoke/1");
  });

  it("catches a README that dropped the manifest-signature check the notes promise", () => {
    const failures = run((file, source) =>
      file === "README.md"
        ? source.replace("minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P ", "minisign -V # ")
        : source,
    );
    expect(failures.join("\n")).toContain("README.md#verify-your-download");
  });

  it("catches a README that dropped the downloaded-file checksum check", () => {
    const failures = run((file, source) =>
      file === "README.md"
        ? source.replace("shasum -a 256 -c --ignore-missing SHA256SUMS", "shasum -a 256 SHA256SUMS")
        : source,
    );
    expect(failures.join("\n")).toContain("README.md#verify-your-download");
  });

  it("catches provenance attestation moved out of the publisher", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow ? source.replace("      attestations: write\n", "") : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches a deleted attestation subject", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow ? source.replace("            payload/SHA256SUMS\n", "") : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches an attestation subject swapped for the unverified candidate manifest", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            "            payload/*/*.tar.gz\n",
            "            release-candidate/manifest.json\n",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("is not fooled by a decoy comment when the attest step moves ahead of the release", () => {
    const attestStep = [
      "      - name: Attest build provenance for the published artifacts",
      "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
      "        with:",
      "          subject-path: |",
      "            payload/*/*.tar.gz",
      "            payload/*/*.AppImage",
      "            payload/*/*-setup.exe",
      "            payload/*/*.zip",
      "            payload/*/*.dmg",
      "            payload/SHA256SUMS",
    ].join("\n");
    const publishHeader = "      - name: Publish the GitHub Release with notes and checksums";
    const decoy = "      # gh release create already ran; nothing left to publish\n";
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const withoutAttest = source.replace(`\n\n${attestStep}\n`, "\n");
      return withoutAttest.replace(
        `${publishHeader}\n`,
        `${decoy}\n${attestStep}\n\n${publishHeader}\n`,
      );
    });
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it('is not fooled by a decoy comment that literally names "gh release create"', () => {
    // Unlike the paraphrase above, this decoy quotes the exact needle
    // orderedBefore searches for, planted ahead of the attest step moved up
    // in front of it; a raw indexOf would find the comment and wrongly call
    // this ordered.
    const attestStep = [
      "      - name: Attest build provenance for the published artifacts",
      "        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
      "        with:",
      "          subject-path: |",
      "            payload/*/*.tar.gz",
      "            payload/*/*.AppImage",
      "            payload/*/*-setup.exe",
      "            payload/*/*.zip",
      "            payload/*/*.dmg",
      "            payload/SHA256SUMS",
    ].join("\n");
    const publishHeader = "      - name: Publish the GitHub Release with notes and checksums";
    const decoy = '      # gh release create "$TAG_NAME" already ran above\n';
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const withoutAttest = source.replace(`\n\n${attestStep}\n`, "\n");
      return withoutAttest.replace(
        `${publishHeader}\n`,
        `${decoy}\n${attestStep}\n\n${publishHeader}\n`,
      );
    });
    expect(failures.join("\n")).toContain("attest-build-provenance");
  });

  it("catches a removed updater-key probe job", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("\n  validate-updater-key:\n", "\n  validate-updater-key-detached:\n")
        : source,
    );
    expect(failures.join("\n")).toContain("validate-updater-key");
  });

  it("catches a removed publish-credential probe job", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("\n  validate-publish-key:\n", "\n  validate-publish-key-detached:\n")
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches release helpers omitted from an isolated sparse checkout", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("            .github/scripts/release\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain(
      "must include .github/scripts/release in its sparse checkout",
    );
  });

  it("is not satisfied by a probe that stopped checking the response code", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace('if [ "$status" != "400" ]; then', 'if [ "$status" = "999" ]; then')
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a probe that can no longer mint its OIDC token", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            "      # audience, minted in release-publish on a v* tag of this repository.\n      id-token: write\n",
            "      # audience, minted in release-publish on a v* tag of this repository.\n",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a probe that authenticates with anything but the OIDC token", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            "-w '%{http_code}' -X POST \\\n            -H \"Authorization: Bearer ${token}\"",
            "-w '%{http_code}' -X POST \\\n            -H \"Authorization: Bearer ${RELEASE_ADMIN_KEY}\"",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a manifest advance that stopped presenting the OIDC token", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            '-H "Authorization: Bearer ${token}" \\\n            -H "Content-Type: application/json" \\\n            --data-binary',
            '-H "Authorization: Bearer ${RELEASE_ADMIN_KEY}" \\\n            -H "Content-Type: application/json" \\\n            --data-binary',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("releases-audience OIDC token (id-token: write)");
  });

  it("catches a manifest advance that hides the worker's refusal reason", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("curl --fail-with-body -sS -X POST", "curl --fail -sS -X POST")
        : source,
    );
    expect(failures.join("\n")).toContain("curl --fail-with-body");
  });

  it("catches a token request that no longer fails on a token-service error", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replaceAll(
            'response=$(curl --fail-with-body -sS -H "Authorization: bearer',
            'response=$(curl -sS -H "Authorization: bearer',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a releases-audience token requested by a third step", () => {
    const tokenLine =
      '          response=$(curl --fail-with-body -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://releases.sitecmd.com")\n';
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? mustMutate(
            source,
            "      - name: Smoke test the public release surface\n",
            `      - name: Request a third token\n        run: |\n${tokenLine}      - name: Smoke test the public release surface\n`,
          )
        : source,
    );
    expect(failures.join("\n")).toContain("validate-publish-key");
  });

  it("catches a publish job missing the AWS region", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace("          AWS_DEFAULT_REGION: auto\n", "")
        : source,
    );
    expect(failures.join("\n")).toContain("AWS_DEFAULT_REGION");
  });

  it("catches a decode that stopped stripping carriage returns", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-signed-payload.sh")
        ? source.replace(
            "tr -d '\\r' < \"$dir/$cli_archive.sig\" | base64 --decode > cli-signature.sig",
            'base64 --decode < "$dir/$cli_archive.sig" > cli-signature.sig',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("carriage returns");
  });

  it("catches a macOS CLI whose native signature is no longer verified", () => {
    const failures = run((file, source) =>
      file.endsWith("verify-unix-artifacts.sh")
        ? source.replace(
            "  codesign --verify --strict cli-check/sitecmd",
            "  # codesign --verify --strict cli-check/sitecmd",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("extracted macOS CLI");
  });

  it("catches a Windows CLI whose Authenticode signature is no longer verified", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(
            "          $cliSignature = Get-AuthenticodeSignature $cli",
            "          # $cliSignature = Get-AuthenticodeSignature $cli",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("extracted Windows CLI");
  });

  it("catches a CLI archive that omits its license materials", () => {
    const failures = run((file, source) =>
      file.endsWith("build-cli.sh")
        ? source.replace('  "$GITHUB_WORKSPACE/THIRD_PARTY_DEPENDENCIES.json" \\\n', "")
        : source,
    );
    expect(failures.join("\n")).toContain(
      "CLI archive must include notices, a dependency inventory, upstream license texts",
    );
  });
});

describe("release audits are mirrored faithfully and run first", () => {
  const walk = (dir, filter) => {
    const out = [];
    const go = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = `${d}/${entry.name}`;
        if (entry.isDirectory()) go(full);
        else if (filter(full)) out.push(full);
      }
    };
    go(dir);
    return out;
  };
  const run = (mutate = (_file, source) => source) =>
    ciCostSafetyFailures((file) => mutate(file, realRead(file)), walk, { exported: true });

  it("passes the real repository", () => {
    expect(run()).toEqual([]);
  });

  it("pins every verify-push step name", () => {
    expect(run()).toEqual([]);
    const file = "tools/scripts/verify-push.mjs";
    const names = /\bname: "([^"]+)",/g;
    const steps = [...realRead(file).matchAll(names)].map((match) => match[1]);
    expect(steps).toContain("rust-nextest");
    const failures = run((path, source) =>
      path === file ? source.replace(names, 'name: "renamed",') : source,
    );
    for (const step of steps) {
      expect(failures).toContainEqual(expect.stringContaining(`must keep its "${step}" step`));
    }
  });

  it("catches local verification that drops the fresh-advisory flag", () => {
    const failures = run((file, source) =>
      file.includes("verify-push.mjs")
        ? source.replace(
            "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",
            "pnpm run audit:deps:rust",
          )
        : source,
    );
    expect(failures.join("\n")).toContain("SITECMD_RUST_AUDIT_FETCH=1");
  });

  it("is not satisfied by the flag appearing only in a comment", () => {
    const failures = run((file, source) =>
      file.includes("verify-push.mjs")
        ? source.replace(
            '      name: "audit:deps:rust",\n      cmd: "SITECMD_RUST_AUDIT_FETCH=1 pnpm run audit:deps:rust",',
            '      // Set SITECMD_RUST_AUDIT_FETCH=1 here to match CI.\n      name: "audit:deps:rust",\n      cmd: "pnpm run audit:deps:rust",',
          )
        : source,
    );
    expect(failures.join("\n")).toContain("SITECMD_RUST_AUDIT_FETCH=1");
  });

  it("catches audits moved back behind the test suites", () => {
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const audits = source.match(
        / {6}- name: JavaScript dependency audit[\s\S]*?run: pnpm run audit:deps:rust\n/,
      )[0];
      return source
        .replace(audits, "")
        .replace("      - name: Rust tests", `${audits}\n      - name: Rust tests`);
    });
    expect(failures.join("\n")).toContain("before `pnpm test`");
  });

  const diskStepBlock = (source) => {
    const start = source.indexOf("      - name: Free runner disk");
    const end = source.indexOf("\n      - ", start);
    return source.slice(start, end + 1);
  };

  it("catches a removed Free runner disk step", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow ? source.replace(diskStepBlock(source), "") : source,
    );
    expect(failures.join("\n")).toContain("Free runner disk");
  });

  it("is not satisfied by a comment naming the disk step", () => {
    const failures = run((file, source) =>
      file === cliReleaseWorkflow
        ? source.replace(diskStepBlock(source), "      # - name: Free runner disk\n")
        : source,
    );
    expect(failures.join("\n")).toContain("Free runner disk");
  });

  it("catches the disk step moved behind the Rust tests", () => {
    const failures = run((file, source) => {
      if (file !== cliReleaseWorkflow) return source;
      const step = diskStepBlock(source);
      return source
        .replace(step, "")
        .replace("      - name: Rust doctests", `${step}      - name: Rust doctests`);
    });
    expect(failures.join("\n")).toContain("before the Rust test steps");
  });
});
