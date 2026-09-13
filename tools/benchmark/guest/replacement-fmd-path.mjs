import path from "node:path";

const candidateRoots = [
  "/srv/sitecmd-benchmark/trials",
  "/srv/sitecmd-benchmark/replacement-qualification",
  "/srv/sitecmd-benchmark/confirmatory-qualification",
];

export function isApprovedFmdCandidatePath(candidate) {
  if (typeof candidate !== "string" || !path.isAbsolute(candidate)) return false;
  return candidateRoots.some((root) => {
    const relative = path.relative(root, candidate);
    return (
      relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative)
    );
  });
}
