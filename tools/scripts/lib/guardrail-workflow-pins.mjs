import {
  children,
  readJobs,
  scalar,
  sequence,
  workflowFields,
  workflowSteps,
} from "./guardrail-workflow-yaml.mjs";

export const RUNNER_IMAGES = {
  macos: "macos-26",
  windows: "windows-2025-vs2026",
};

const LATEST_LABEL = /-latest\b/i;
const LITERAL_LABEL = /^[\w.-]+$/;
const MATRIX_LABEL = /^\$\{\{\s*matrix(?:\.([\w-]+)|\['([\w-]+)'\])\s*\}\}$/;
const NODE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

export function isVersionedUbuntuRunner(label) {
  return (
    /^ubuntu-\d{2}\.\d{2}(?:-\w|$)/.test(label) &&
    LITERAL_LABEL.test(label) &&
    !LATEST_LABEL.test(label)
  );
}

function runnerLabels(field) {
  if (!field) return [];
  if (field.value.startsWith("[") || field.body[0]?.trimStart().startsWith("- ")) {
    return sequence(field);
  }
  if (field.value) return [scalar(field)];
  return runnerLabels(children(field).get("labels"));
}

function matrixLabels(label, strategy) {
  const match = MATRIX_LABEL.exec(label);
  if (!match || strategy?.value) return [label];
  const matrixField = children(strategy).get("matrix");
  if (!matrixField || matrixField.value) return [label];
  const matrix = children(matrixField);
  const key = match[1] ?? match[2];
  const includes = workflowSteps(matrix.get("include"));
  const values = [matrix.get(key), ...includes.map((row) => row.get(key))].flatMap(runnerLabels);
  return values.length ? values : [label];
}

function pinnedRunner(label) {
  const name = label.toLowerCase();
  if (name.startsWith("macos-") || name.startsWith("xcode-")) return RUNNER_IMAGES.macos;
  if (name.startsWith("windows-")) return RUNNER_IMAGES.windows;
}

function runnerFailures(job, context) {
  const labels = runnerLabels(job.get("runs-on"));
  const failures = new Set();
  for (const label of labels.flatMap((value) => matrixLabels(value, job.get("strategy")))) {
    if (LATEST_LABEL.test(label)) {
      failures.add(`${context}: no -latest runner labels.`);
    } else if (!LITERAL_LABEL.test(label)) {
      failures.add(`${context} must use literal runner labels or a literal runner matrix.`);
    } else if (label.toLowerCase().startsWith("ubuntu-") && !isVersionedUbuntuRunner(label)) {
      failures.add(`${context} must use a versioned Ubuntu runner label.`);
    } else {
      const expected = pinnedRunner(label);
      if (expected && label !== expected) failures.add(`${context} must run on ${expected}.`);
    }
  }
  return failures;
}

function pinnedImage(image) {
  if (typeof image !== "string") return false;
  const [reference, digest, extra] = image.split("@");
  const colon = reference.lastIndexOf(":");
  return (
    extra === undefined &&
    colon > Math.max(0, reference.lastIndexOf("/")) &&
    !/\s/.test(reference) &&
    /^\w[\w.-]*$/.test(reference.slice(colon + 1)) &&
    /^sha256:[a-f0-9]{64}$/.test(digest ?? "")
  );
}

function jobImages(job) {
  const services = job.get("services");
  const images = [...children(services?.value === "{}" ? undefined : services)].map(
    ([name, service]) => [`service ${name}`, scalar(children(service).get("image"))],
  );
  const container = job.get("container");
  if (container) {
    const image = container.value ? container : children(container).get("image");
    images.push(["container", scalar(image)]);
  }
  return images;
}

export function workflowPinFailures(read, listFiles) {
  const failures = [];
  if (!NODE_VERSION.test(read(".nvmrc").trim())) {
    failures.push(".nvmrc must pin X.Y.Z.");
  }
  for (const file of listFiles(".github/workflows", (name) => /\.ya?ml$/.test(name))) {
    for (const [id, job] of readJobs(workflowFields(read(file)))) {
      const context = `${file} job ${id}`;
      failures.push(...runnerFailures(job, context));
      for (const [name, image] of jobImages(job)) {
        if (!pinnedImage(image))
          failures.push(`${context} ${name} must pin an image tag and sha256 digest.`);
      }
    }
  }
  return failures;
}
