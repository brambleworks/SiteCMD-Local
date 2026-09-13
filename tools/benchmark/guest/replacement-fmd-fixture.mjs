import {
  createCipheriv,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
  randomInt,
} from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { inflateSync } from "node:zlib";
import { digest } from "../lib/workflow-plan.mjs";
import { fmdRuntimeManifest } from "./replacement-fmd-runtime.mjs";

function decodeRgbaPng(png) {
  if (!png.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex"))) {
    throw new Error("FMD marker asset is not a PNG");
  }
  let offset = 8;
  let width;
  let height;
  const compressed = [];
  while (offset < png.length) {
    const length = png.readUInt32BE(offset);
    const type = png.toString("ascii", offset + 4, offset + 8);
    const data = png.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      if (!data.subarray(8).equals(Buffer.from([8, 6, 0, 0, 0]))) {
        throw new Error("FMD marker asset uses an unsupported PNG format");
      }
    } else if (type === "IDAT") {
      compressed.push(data);
    } else if (type === "IEND") {
      break;
    }
    offset += 12 + length;
  }
  if (!Number.isInteger(width) || !Number.isInteger(height) || compressed.length === 0) {
    throw new Error("FMD marker asset is incomplete");
  }
  const filtered = inflateSync(Buffer.concat(compressed));
  const rowBytes = width * 4;
  if (filtered.length !== height * (rowBytes + 1)) {
    throw new Error("FMD marker asset has an invalid pixel payload");
  }
  const pixels = Buffer.alloc(width * height * 4);
  const paeth = (left, above, upperLeft) => {
    const estimate = left + above - upperLeft;
    const distances = [
      Math.abs(estimate - left),
      Math.abs(estimate - above),
      Math.abs(estimate - upperLeft),
    ];
    const minimum = Math.min(...distances);
    return [left, above, upperLeft][distances.indexOf(minimum)];
  };
  for (let y = 0; y < height; y += 1) {
    const filter = filtered[y * (rowBytes + 1)];
    for (let x = 0; x < rowBytes; x += 1) {
      const encoded = filtered[y * (rowBytes + 1) + 1 + x];
      const output = y * rowBytes + x;
      const left = x >= 4 ? pixels[output - 4] : 0;
      const above = y > 0 ? pixels[output - rowBytes] : 0;
      const upperLeft = y > 0 && x >= 4 ? pixels[output - rowBytes - 4] : 0;
      const predictor =
        filter === 0
          ? 0
          : filter === 1
            ? left
            : filter === 2
              ? above
              : filter === 3
                ? Math.floor((left + above) / 2)
                : filter === 4
                  ? paeth(left, above, upperLeft)
                  : null;
      if (predictor === null) throw new Error("FMD marker asset uses an unknown PNG filter");
      pixels[output] = (encoded + predictor) & 0xff;
    }
  }
  return { width, height, pixels };
}

export function createFmdFixture(baselineDirectory) {
  const manifest = fmdRuntimeManifest();
  const markerAsset = readFileSync(path.join(baselineDirectory, manifest.markerAsset));
  if (digest(markerAsset) !== manifest.markerAssetSha256) {
    throw new Error("FMD marker asset differs from its manifest");
  }
  const backend = readFileSync(path.join(baselineDirectory, "cmd/fmdserver.go"), "utf8");
  if (!backend.includes(`Set("Content-Security-Policy", "${manifest.csp}")`)) {
    throw new Error("FMD content security policy differs from its manifest");
  }
  const decoded = decodeRgbaPng(markerAsset);
  if (decoded.width !== 25 || decoded.height !== 41) {
    throw new Error("FMD marker asset dimensions changed");
  }
  const opaqueMask = Buffer.from(
    Array.from({ length: decoded.width * decoded.height }, (_value, index) => {
      const x = index % decoded.width;
      const y = Math.floor(index / decoded.width);
      return [-1, 0, 1].every((offsetY) =>
        [-1, 0, 1].every((offsetX) => {
          const sampleX = x + offsetX;
          const sampleY = y + offsetY;
          return (
            sampleX >= 0 &&
            sampleX < decoded.width &&
            sampleY >= 0 &&
            sampleY < decoded.height &&
            decoded.pixels[(sampleY * decoded.width + sampleX) * 4 + 3] === 255
          );
        }),
      )
        ? 1
        : 0;
    }),
  );
  if (opaqueMask.reduce((total, value) => total + value, 0) < 300) {
    throw new Error("FMD marker asset has insufficient opaque reference pixels");
  }
  const markerRgb = Buffer.from(
    Array.from({ length: decoded.width * decoded.height * 3 }, (_value, index) => {
      const pixel = Math.floor(index / 3);
      return decoded.pixels[pixel * 4 + (index % 3)];
    }),
  );
  const keys = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const semanticTokens = Array.from({ length: 4 }, () => randomBytes(16).toString("hex"));
  const providers = [
    "gps",
    `GPS <em data-sitecmd-probe="${semanticTokens[0]}">satellite-${semanticTokens[1]}</em> & Wi-Fi`,
    "cell &amp; Wi-Fi < 5 ☃",
    `<svg data-sitecmd-probe="${semanticTokens[2]}"><text>receiver-${semanticTokens[3]}</text></svg>`,
  ];
  const coordinates = [
    [51.501, -0.094],
    [51.506, -0.09],
    [51.503, -0.083],
    [51.51, -0.078],
  ];
  return {
    csp: manifest.csp,
    observationMode: "isolated",
    token: "qualification-owned-session",
    deviceId: "Q7b9M",
    detailsRenderBox: { left: 100, top: 1400, right: 1230, bottom: 1570 },
    mapRenderBox: { left: 8, top: 373, right: 1276, bottom: 1397 },
    mapHistogramDistanceLimit: 0.003,
    mapSpatialDistanceLimit: 0.004,
    mapPersistenceHistogramLimit: 0.00005,
    mapPersistenceSpatialLimit: 0.00005,
    mapSampleOffset: randomInt(1, 8),
    mapGridPhaseX: randomInt(1, 8),
    mapGridPhaseY: randomInt(1, 8),
    markerHitOffsetX: randomInt(-2, 3),
    markerHitOffsetY: randomInt(10, 13),
    markerMaterialDeltaThreshold: 16,
    markerMaterialPixelLimit: 4,
    markerTotalDifferenceLimit: 256,
    markerAssetSha256: digest(markerAsset),
    markerOpaqueMaskBase64: opaqueMask.toString("base64"),
    markerOpaqueMaskSha256: digest(opaqueMask),
    markerAssetRgbBase64: markerRgb.toString("base64"),
    markerAssetRgbSha256: digest(markerRgb),
    privateKey: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    samples: providers.map((provider, index) => {
      const location = {
        provider,
        bat: 67 - index * 11,
        time: `2024-05-${20 + index}T${12 + index}:34:56Z`,
        lat: coordinates[index][0],
        lon: coordinates[index][1],
      };
      const sessionKey = randomBytes(32);
      const iv = randomBytes(12);
      const encryptedKey = publicEncrypt({ key: keys.publicKey, oaepHash: "sha256" }, sessionKey);
      const cipher = createCipheriv("aes-256-gcm", sessionKey, iv);
      const data = Buffer.concat([
        cipher.update(JSON.stringify(location)),
        cipher.final(),
        cipher.getAuthTag(),
      ]);
      return {
        location,
        packet: Buffer.concat([encryptedKey, iv, data]).toString("base64"),
      };
    }),
  };
}
