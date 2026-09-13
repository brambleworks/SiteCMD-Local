export function isValidFmdReferenceRun(run) {
  return (
    run?.exitCode === 0 &&
    run.error === null &&
    run.result?.passed === true &&
    run.result.setupError === null &&
    run.result.checks?.length === 82 &&
    run.result.observations?.length === 10 &&
    run.result.pendingActionSamples?.length === 10 &&
    run.result.pendingActionSamples.every(
      (record) => record.completed === true && record.samples.length >= 1,
    ) &&
    run.result.earlyRenderSamples?.length === 10 &&
    run.result.earlyRenderSamples.every(
      (record) => record.samples.length >= 3 && record.settleSamples.length >= 3,
    )
  );
}

export async function stabilizeFmdReferenceRuns(initialRuns, runOnce) {
  const runs = [...initialRuns];
  const retries = [];
  for (const [index, initial] of initialRuns.entries()) {
    if (isValidFmdReferenceRun(initial)) continue;
    const retry = await runOnce();
    runs[index] = retry;
    retries.push({ index, initial, retry });
    if (!isValidFmdReferenceRun(retry)) break;
  }
  return { runs, retries };
}
