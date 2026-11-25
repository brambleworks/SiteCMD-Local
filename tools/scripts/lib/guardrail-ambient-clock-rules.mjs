// Production checks use the caller's evaluation time so every runner agrees.
const AMBIENT_CLOCK = /\b(?:Utc|Local|SystemTime|Timestamp|Zoned)::now\s*\(|\bnow_utc\s*\(/;

export function ambientClockFailures(read, listFiles, roots) {
  const isNonTestSource = (file) =>
    file.endsWith(".rs") &&
    !/[/\\]tests[/\\]/.test(file) &&
    !/(_tests?\.rs|^tests\.rs)$/.test(file.split(/[/\\]/).pop());
  const offenders = roots
    .flatMap((root) => listFiles(root, isNonTestSource))
    .filter((file) => {
      const source = read(file);
      const cut = source.indexOf("#[cfg(test)]");
      const nonTest = cut === -1 ? source : source.slice(0, cut);
      return nonTest
        .split("\n")
        .some((line) => AMBIENT_CLOCK.test(line) && !line.includes("// allow-ambient-clock"));
    });
  if (offenders.length === 0) return [];
  return [
    `Checks and the engine crate must take their time basis from the injected evaluation_time (PageContext / caller argument), never an ambient clock (Timestamp::now/Zoned::now/SystemTime::now/now_utc; annotate a genuine exception with // allow-ambient-clock): ${offenders.join(", ")}`,
  ];
}
