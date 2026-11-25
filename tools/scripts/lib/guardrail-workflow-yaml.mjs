const mappingKey = /^ *["']?([\w-]+)["']?\s*:/;

function uncomment(value) {
  return value.replace(/\s+#.*$/, "").trim();
}

// Read workflow mappings in the block layout used by the repository.
export function workflowFields(source) {
  const lines = source
    .split("\n")
    .filter((line) => line.trim() && !line.trimStart().startsWith("#"));
  const indent = lines[0]?.search(/\S/) ?? 0;
  const fields = new Map();
  let field;
  for (const line of lines) {
    if (line.search(/\S/) === indent) {
      const key = mappingKey.exec(line);
      if (!key || fields.has(key[1])) throw new Error(`Unsupported workflow mapping: ${line}`);
      const raw = line.slice(key[0].length);
      const comment = key[1] === "uses" ? /\s+#(.*)$/.exec(raw)?.[1].trim() : undefined;
      field = { value: uncomment(raw), body: [], comment };
      fields.set(key[1], field);
    } else {
      field.body.push(line);
    }
  }
  return fields;
}

export function children(field) {
  if (!field) return new Map();
  if (field.value) throw new Error(`Expected a workflow block, got ${field.value}`);
  return workflowFields(field.body.join("\n"));
}

export function scalar(field) {
  const value = field?.value;
  if (value === ">" || value === ">-") return field.body.map((line) => line.trim()).join(" ");
  return value?.replace(/^(['"])(.*)\1$/, "$2");
}

export function sequence(field) {
  if (!field) return [];
  if (field.value.startsWith("[")) {
    const value = [field.value, ...field.body.map(uncomment)].join(" ");
    if (!value.endsWith("]")) throw new Error(`Invalid workflow sequence: ${value}`);
    return value
      .slice(1, -1)
      .split(",")
      .map((entry) => scalar({ value: entry.trim() }))
      .filter(Boolean);
  }
  if (field.value) return [scalar(field)];
  return field.body.map((line) => {
    if (!line.trimStart().startsWith("- ")) throw new Error(`Invalid workflow sequence: ${line}`);
    return scalar({ value: uncomment(line.trimStart().slice(2)) });
  });
}

export function workflowSteps(field, anchors = new Map()) {
  if (!field) return [];
  if (field.value) throw new Error(`Expected a workflow steps block, got ${field.value}`);
  const indent = field.body[0]?.search(/\S/) ?? 0;
  const start = " ".repeat(indent) + "- ";
  const steps = [];
  for (const line of field.body) {
    if (line.startsWith(start)) {
      const raw = line.slice(start.length);
      const first = uncomment(raw);
      const reference = /^[&*]([\w-]+)$/.exec(first);
      if (!reference && !mappingKey.test(first))
        throw new Error(`Unsupported workflow step: ${line}`);
      steps.push({
        reference: reference && first,
        lines: reference ? [] : [" ".repeat(indent + 2) + raw],
      });
    } else {
      steps.at(-1).lines.push(line);
    }
  }
  return steps.map(({ reference, lines }) => {
    if (reference?.startsWith("*")) {
      const step = anchors.get(reference.slice(1));
      if (lines.length || !step) throw new Error(`Invalid workflow step alias ${reference}.`);
      return step;
    }
    const step = workflowFields(lines.join("\n"));
    if (reference) anchors.set(reference.slice(1), step);
    return step;
  });
}

export function workflowJobSteps(jobs) {
  const anchors = new Map();
  return new Map([...jobs].map(([id, job]) => [id, workflowSteps(job.get("steps"), anchors)]));
}

export function runCommand(step) {
  const run = step.get("run");
  if (run?.value === "|" || run?.value === "|-") {
    return run.body.map((line) => line.trimStart()).join("\n");
  }
  return scalar(run);
}

export function workflowEvents(field) {
  if (!field) throw new Error("Missing workflow on declaration.");
  if (field.value && !field.value.startsWith("[")) {
    if (!/^[\w_]+$/.test(scalar(field))) throw new Error("Unsupported workflow on declaration.");
  }
  if (field.value || field.body[0]?.trimStart().startsWith("- ")) {
    return new Map(sequence(field).map((event) => [event, new Map()]));
  }
  return new Map(
    [...children(field)].map(([event, filter]) => {
      if (["null", "~", "{}"].includes(filter.value)) return [event, new Map()];
      if (event === "schedule") return [event, new Map()];
      return [event, children(filter)];
    }),
  );
}

export function readJobs(fields) {
  return new Map([...children(fields.get("jobs"))].map(([id, job]) => [id, children(job)]));
}

export function readWorkflow(source) {
  const jobs = readJobs(workflowFields(source));
  return {
    jobs: Object.fromEntries(
      [...workflowJobSteps(jobs)].map(([id, steps]) => [
        id,
        { steps: steps.map((step) => ({ run: runCommand(step) })) },
      ]),
    ),
  };
}
