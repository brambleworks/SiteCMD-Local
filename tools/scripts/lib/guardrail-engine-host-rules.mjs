const HOST = "sitecmd-engine-host";
const OPEN_CRATES = new Set([
  "sitecmd-protocol",
  HOST,
  "sitecmd-engine-standin",
  "sitecmd-runtime",
  "sitecmd-cli",
]);
const NORMAL_FEATURES = new Set(["runtime", "std"]);
const NORMAL_RESOLVED_FEATURES = new Set([
  ...NORMAL_FEATURES,
  "once_cell",
  "wasmtime-jit-icache-coherence",
]);
const RESOLVED_FEATURES = new Set([...NORMAL_RESOLVED_FEATURES, "cranelift", "all-arch", "pulley"]);

function allowsDeclaredFeature(kind, feature) {
  return (
    NORMAL_FEATURES.has(feature) ||
    (feature === "cranelift" && (kind === "build" || kind === "dev")) ||
    (feature === "all-arch" && kind === "build")
  );
}

export function openCrateDependencyFailures(metadata) {
  const members = new Set(metadata.workspace_members);
  const packages = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const failures = new Set();
  for (const { id, deps } of metadata.resolve.nodes) {
    const name = packages.get(id)?.name;
    if (!members.has(id) || !OPEN_CRATES.has(name)) continue;
    for (const { pkg, dep_kinds } of deps) {
      const dependency = packages.get(pkg);
      let disallowedSource;
      if (dependency.source?.startsWith("git+")) {
        disallowedSource = "git";
      } else if (members.has(pkg) && !OPEN_CRATES.has(dependency.name)) {
        disallowedSource = "workspace";
      } else if (!members.has(pkg) && dependency.source === null) {
        disallowedSource = "non-member path";
      } else {
        continue;
      }
      for (const { kind } of dep_kinds) {
        failures.add(
          `${name} has a disallowed ${kind ?? "normal"} dependency on ${disallowedSource} crate ${dependency.name}.`,
        );
      }
    }
  }
  return [...failures];
}

export function parseNormalWasmtimeFeatures(tree) {
  return tree
    .split("\n")
    .map((line) => line.split("\t"))
    .filter(([pkg]) => pkg.startsWith("wasmtime v"))
    .flatMap(([, features]) => features.split(",").filter(Boolean));
}

export function engineHostFailures(metadata, normalFeatures) {
  const failures = new Set();
  const members = new Set(metadata.workspace_members);
  const wasmtimeIds = new Set(
    metadata.packages.filter(({ name }) => name === "wasmtime").map(({ id }) => id),
  );
  const featureFailure = (feature) => `${HOST} must disable the Wasmtime feature ${feature}.`;
  let foundHostDependency = false;
  for (const pkg of metadata.packages) {
    for (const dependency of pkg.dependencies.filter(({ name }) => name === "wasmtime")) {
      if (pkg.name !== HOST || !members.has(pkg.id)) {
        failures.add(`${pkg.name} must depend on ${HOST} for Wasmtime.`);
        continue;
      }
      if (dependency.kind === null && !dependency.optional) foundHostDependency = true;
      if (dependency.uses_default_features) {
        failures.add(`${HOST} must disable Wasmtime default features.`);
      }
      for (const feature of dependency.features) {
        if (!allowsDeclaredFeature(dependency.kind, feature)) failures.add(featureFailure(feature));
      }
      const alias = dependency.rename ?? dependency.name;
      for (const [hostFeature, enabled] of Object.entries(pkg.features)) {
        for (const entry of enabled) {
          const [prefix, feature] = entry.split("/");
          if (!feature || (prefix !== alias && prefix !== `${alias}?`)) continue;
          if (hostFeature === "compile" && feature === "cranelift") continue;
          if (!NORMAL_FEATURES.has(feature)) failures.add(featureFailure(feature));
        }
      }
    }
  }
  if (!foundHostDependency) failures.add(`${HOST} must directly depend on Wasmtime.`);
  for (const node of metadata.resolve.nodes.filter(({ id }) => wasmtimeIds.has(id))) {
    for (const feature of node.features) {
      if (!RESOLVED_FEATURES.has(feature)) failures.add(featureFailure(feature));
    }
  }
  for (const feature of normalFeatures) {
    if (!NORMAL_RESOLVED_FEATURES.has(feature)) failures.add(featureFailure(feature));
  }
  return [...failures];
}
