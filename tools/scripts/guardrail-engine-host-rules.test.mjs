import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import {
  engineHostFailures,
  openCrateDependencyFailures,
} from "./lib/guardrail-engine-host-rules.mjs";

function openDependencyFixture(kind, source = "workspace") {
  const open = "path+file:///open#sitecmd-runtime@0.1.0";
  const internal = "path+file:///internal#fixture-internal@0.1.0";
  const external = "registry+https://example.invalid/#fixture-internal@0.1.0";
  const outside = {
    path: { id: "path+file:///checkout#fixture-internal@0.1.0", source: null },
    git: {
      id: "git+https://example.invalid/checkout#fixture-internal@0.1.0",
      source: "git+https://example.invalid/checkout#revision",
    },
  }[source];
  const dependency = outside ?? { id: internal, source: null };
  return {
    workspace_members: outside ? [open] : [open, internal],
    packages: [
      { id: open, name: "sitecmd-runtime", source: null },
      { ...dependency, name: "fixture-internal" },
      { id: external, name: "fixture-internal", source: "registry+https://example.invalid/" },
    ],
    resolve: {
      nodes: [
        {
          id: open,
          deps: [
            { name: "aliased_internal", pkg: dependency.id, dep_kinds: [{ kind, target: null }] },
            { name: "aliased_external", pkg: external, dep_kinds: [{ kind, target: null }] },
          ],
        },
        { id: dependency.id, deps: [] },
        { id: external, deps: [] },
      ],
    },
  };
}

it("an_open_crate_with_a_dev_dependency_outside_the_open_set_fails", () => {
  // An open crate that can't build without private source.
  expect(openCrateDependencyFailures(openDependencyFixture("dev"))).toEqual([
    "sitecmd-runtime has a disallowed dev dependency on workspace crate fixture-internal.",
  ]);
});

it("an_open_crate_with_a_build_dependency_outside_the_open_set_fails", () => {
  // An open crate that can't build without private source.
  expect(openCrateDependencyFailures(openDependencyFixture("build"))).toEqual([
    "sitecmd-runtime has a disallowed build dependency on workspace crate fixture-internal.",
  ]);
});

it("an_open_crate_with_a_normal_dependency_outside_the_open_set_fails", () => {
  // An aliased normal dependency can require private workspace source.
  expect(openCrateDependencyFailures(openDependencyFixture(null))).toEqual([
    "sitecmd-runtime has a disallowed normal dependency on workspace crate fixture-internal.",
  ]);
});

it("an_open_crate_with_a_nonmember_path_dependency_fails", () => {
  // An open crate can require a separate local checkout.
  expect(openCrateDependencyFailures(openDependencyFixture(null, "path"))).toEqual([
    "sitecmd-runtime has a disallowed normal dependency on non-member path crate fixture-internal.",
  ]);
});

it("an_open_crate_with_a_git_dependency_fails", () => {
  // A registry namesake can hide a dependency fetched from a private Git repository.
  expect(openCrateDependencyFailures(openDependencyFixture(null, "git"))).toEqual([
    "sitecmd-runtime has a disallowed normal dependency on git crate fixture-internal.",
  ]);
});

it("the_workspace_open_crates_pass", () => {
  // An open crate that can't build without private source.
  const cwd = fileURLToPath(new URL("../../apps/desktop/src-tauri/", import.meta.url));
  const metadata = JSON.parse(
    execFileSync(
      "cargo",
      ["metadata", "--format-version", "1", "--all-features", "--locked", "--offline"],
      {
        cwd,
        encoding: "utf8",
        maxBuffer: 32 * 1024 * 1024,
      },
    ),
  );
  expect(openCrateDependencyFailures(metadata)).toEqual([]);
}, 30_000);

function fixtureMetadata() {
  return JSON.parse(
    readFileSync(new URL("./testdata/engine-host-metadata.json", import.meta.url), "utf8"),
  );
}

function fixtureFailures(
  metadata,
  normalFeatures = ["runtime", "std", "once_cell", "wasmtime-jit-icache-coherence"],
) {
  return engineHostFailures(metadata, normalFeatures);
}

function hostDependency(metadata) {
  return metadata.packages
    .find((pkg) => pkg.name === "sitecmd-engine-host")
    .dependencies.find((dependency) => dependency.name === "wasmtime");
}

it("the_release_dependency_has_no_compiler", () => {
  // Bug: A normal Wasmtime dependency can ship a compiler in the release CLI.
  const metadata = fixtureMetadata();
  expect(fixtureFailures(metadata, ["runtime", "std", "cranelift"])).toContain(
    "sitecmd-engine-host must disable the Wasmtime feature cranelift.",
  );
});

it("build_and_dev_dependencies_can_use_cranelift", () => {
  // Bug: Cargo's combined features can make a compiler-free runtime fail the guardrail.
  const metadata = fixtureMetadata();
  expect(fixtureFailures(metadata)).toEqual([]);
  hostDependency(metadata).features.push("cranelift");
  expect(fixtureFailures(metadata)).toEqual([
    "sitecmd-engine-host must disable the Wasmtime feature cranelift.",
  ]);
});

it("only_the_host_crate_depends_on_wasmtime", () => {
  // Bug: A second workspace crate can instantiate Wasm outside the host boundary.
  const metadata = fixtureMetadata();
  expect(fixtureFailures(metadata)).toEqual([]);
  const cli = metadata.packages.find((pkg) => pkg.name === "sitecmd-cli");
  cli.dependencies.push({ ...hostDependency(metadata), rename: "another_runtime" });
  expect(fixtureFailures(metadata)).toEqual([
    "sitecmd-cli must depend on sitecmd-engine-host for Wasmtime.",
  ]);
});

it("wasmtime_features_exclude_cache_component_model_async_and_wat", () => {
  // Bug: Unneeded Wasmtime features can extend the host's runtime surface.
  const metadata = fixtureMetadata();
  expect(fixtureFailures(metadata)).toEqual([]);
  const dependency = hostDependency(metadata);
  for (const feature of ["cache", "component-model", "async", "wat"]) {
    dependency.features = [feature];
    expect(fixtureFailures(metadata)).toContain(
      `sitecmd-engine-host must disable the Wasmtime feature ${feature}.`,
    );
  }
  dependency.features = [];
  const host = metadata.packages.find((pkg) => pkg.name === "sitecmd-engine-host");
  host.features.internal = ["wasmtime?/component-model"];
  expect(fixtureFailures(metadata)).toContain(
    "sitecmd-engine-host must disable the Wasmtime feature component-model.",
  );
  dependency.uses_default_features = true;
  expect(fixtureFailures(metadata)).toContain(
    "sitecmd-engine-host must disable Wasmtime default features.",
  );
});

it.each(["cache", "component-model", "async", "wat"])(
  "rejects resolved Wasmtime feature %s",
  (feature) => {
    // Bug: A feature enabled in the resolved graph can escape manifest-only filtering.
    const metadata = fixtureMetadata();
    const wasmtime = metadata.resolve.nodes.find(({ id }) => id === "wasmtime");
    wasmtime.features.push(feature);
    expect(fixtureFailures(metadata)).toEqual([
      `sitecmd-engine-host must disable the Wasmtime feature ${feature}.`,
    ]);
  },
);

it.each(["third-party", "sitecmd-engine-host"])(
  "rejects a non-member named %s with its own Wasmtime dependency",
  (name) => {
    // Bug: Inspecting only workspace members misses a second path to Wasmtime.
    const metadata = fixtureMetadata();
    const id = `registry:${name}`;
    metadata.packages.push({
      id,
      name,
      dependencies: [{ ...hostDependency(metadata) }],
      features: {},
    });
    metadata.resolve.nodes
      .find(({ id }) => id === "sitecmd-cli")
      .deps.push({
        name: "third_party",
        pkg: id,
      });
    metadata.resolve.nodes.push({
      id,
      deps: [{ name: "wasmtime", pkg: "wasmtime" }],
      features: [],
    });
    expect(fixtureFailures(metadata)).toEqual([
      `${name} must depend on sitecmd-engine-host for Wasmtime.`,
    ]);
  },
);

it("requires a direct unconditional Wasmtime dependency in the host", () => {
  // Bug: The host can lose its normal dependency on Wasmtime.
  const metadata = fixtureMetadata();
  hostDependency(metadata).optional = true;
  expect(fixtureFailures(metadata)).toContain(
    "sitecmd-engine-host must directly depend on Wasmtime.",
  );
});
