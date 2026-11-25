import { copyFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { cargoRoot } from "./lib/wasm-build-settings.mjs";
import { buildWasmArtifact } from "./lib/build-wasm-artifact.mjs";

const { values } = parseArgs({ options: { out: { type: "string" } } });
const artifact = buildWasmArtifact({ packageName: "sitecmd-engine-standin" });
const output = path.resolve(values.out ?? path.join(cargoRoot, "target", "standin"));
const destination = path.join(output, path.basename(artifact));
mkdirSync(output, { recursive: true });
if (artifact !== destination) copyFileSync(artifact, destination);
console.log(destination);
