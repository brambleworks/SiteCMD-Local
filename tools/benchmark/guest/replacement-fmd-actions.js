(() => {
  const expectedRoute = __SITECMD_EXPECTED_ROUTE__;
  const text = (id) => document.getElementById(id)?.textContent ?? null;
  const fields = {
    provider: document.getElementById("providerView"),
    battery: document.getElementById("batView"),
    deviceId: document.getElementById("idView"),
    date: document.getElementById("dateView"),
    time: document.getElementById("timeView"),
  };
  const provider = fields.provider;
  const hasVisibleAlpha = (value) => {
    const normalized = String(value ?? "")
      .trim()
      .toLowerCase();
    if (!normalized || normalized === "none" || normalized === "transparent") return false;
    const rgba = /^rgba\([^)]*,\s*([0-9.]+)\s*\)$/.exec(normalized);
    return !rgba || Number(rgba[1]) > 0;
  };
  const filterAllowsPaint = (value) => {
    const filter = String(value ?? "")
      .trim()
      .toLowerCase();
    if (!filter || filter === "none") return true;
    const opacity = /opacity\(\s*([0-9]*\.?[0-9]+)\s*(%)?\s*\)/g;
    for (const match of filter.matchAll(opacity)) {
      const alpha = Number(match[1]) / (match[2] ? 100 : 1);
      if (!Number.isFinite(alpha) || alpha <= 0) return false;
    }
    return true;
  };
  const stylesVisible = (element) => {
    if (!element) return false;
    if (getComputedStyle(element).visibility !== "visible") return false;
    for (let node = element; node instanceof Element; node = node.parentElement) {
      const css = getComputedStyle(node);
      if (
        css.display === "none" ||
        Number(css.opacity) <= 0 ||
        !filterAllowsPaint(css.filter || css.webkitFilter)
      )
        return false;
    }
    return true;
  };
  const textPainted = (element) => {
    const css = getComputedStyle(element);
    const fill = css.getPropertyValue("-webkit-text-fill-color") || css.color;
    return hasVisibleAlpha(fill);
  };
  const textRendered = (element) => {
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
    let found = false;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!node.data.length) continue;
      found = true;
      if (!stylesVisible(node.parentElement) || !textPainted(node.parentElement)) return false;
      const range = document.createRange();
      range.selectNodeContents(node);
      if (![...range.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0))
        return false;
    }
    return found;
  };
  const map = document.getElementById("map").getBoundingClientRect();
  const tiles = [...document.querySelectorAll("img.leaflet-tile")]
    .map((image) => {
      const match = /\/(\d+)\/(\d+)\/(\d+)\.png$/.exec(image.getAttribute("src") ?? "");
      return match
        ? {
            zoom: Number(match[1]),
            x: Number(match[2]),
            y: Number(match[3]),
            box: image.getBoundingClientRect(),
          }
        : null;
    })
    .filter((tile) => tile && tile.box.width > 0 && tile.box.height > 0);
  const tile = tiles.sort((left, right) => right.zoom - left.zoom)[0];
  const point = (left, top) => {
    if (!tile) return null;
    const scale = 2 ** tile.zoom;
    const x = (tile.x + (left - tile.box.left) / tile.box.width) / scale;
    const y = (tile.y + (top - tile.box.top) / tile.box.height) / scale;
    return {
      lat: (Math.atan(Math.sinh(Math.PI * (1 - 2 * y))) * 180) / Math.PI,
      lon: x * 360 - 180,
    };
  };
  const pixel = (location) => {
    if (!tile) return null;
    const scale = 2 ** tile.zoom;
    const x = ((location.lon + 180) / 360) * scale;
    const sine = Math.sin((location.lat * Math.PI) / 180);
    const y = (0.5 - Math.log((1 + sine) / (1 - sine)) / (4 * Math.PI)) * scale;
    return {
      x: tile.box.left + (x - tile.x) * tile.box.width,
      y: tile.box.top + (y - tile.y) * tile.box.height,
    };
  };
  const markerImages = [...document.querySelectorAll("img.leaflet-marker-icon")];
  const markerBoxes = markerImages.map((image) => image.getBoundingClientRect());
  const markerHitOffset = {
    x: __SITECMD_MARKER_HIT_X__,
    y: __SITECMD_MARKER_HIT_Y__,
  };
  const markerPixels = markerBoxes.map((box) => {
    return { x: box.left + box.width / 2, y: box.bottom };
  });
  const mapCenter = { x: map.left + map.width / 2, y: map.top + map.height / 2 };
  const activeMarkerIndex = markerPixels.reduce((nearest, marker, index) => {
    if (nearest === null) return index;
    const distance = Math.hypot(marker.x - mapCenter.x, marker.y - mapCenter.y);
    const nearestMarker = markerPixels[nearest];
    const nearestDistance = Math.hypot(
      nearestMarker.x - mapCenter.x,
      nearestMarker.y - mapCenter.y,
    );
    return distance < nearestDistance ? index : nearest;
  }, null);
  const activeMarkerBox =
    activeMarkerIndex === null
      ? null
      : {
          left: markerBoxes[activeMarkerIndex].left,
          top: markerBoxes[activeMarkerIndex].top,
          right: markerBoxes[activeMarkerIndex].right,
          bottom: markerBoxes[activeMarkerIndex].bottom,
        };
  const markerPainted = markerImages.map(
    (image, index) =>
      stylesVisible(image) && markerBoxes[index].width > 0 && markerBoxes[index].height > 0,
  );
  const markerUnobscured = markerImages.map((image, index) => {
    const box = markerBoxes[index];
    const x = box.left + box.width / 2 + markerHitOffset.x;
    const y = box.top + markerHitOffset.y;
    return document.elementsFromPoint(x, y)[0] === image;
  });
  const markerHitInMap = markerBoxes.map((box) => {
    const x = box.left + box.width / 2 + markerHitOffset.x;
    const y = box.top + markerHitOffset.y;
    return x >= map.left && x < map.right && y >= map.top && y < map.bottom;
  });
  const markerCropBoxes = markerBoxes
    .filter(
      (box) =>
        box.right > map.left &&
        box.left < map.right &&
        box.bottom > map.top &&
        box.top < map.bottom,
    )
    .map((box) => ({ left: box.left, top: box.top, right: box.right, bottom: box.bottom }));
  const markerPoints = markerPixels.map((marker) => point(marker.x, marker.y));
  const markerViewportDistances = markerPixels.map((marker) => {
    const dx = Math.max(map.left - marker.x, 0, marker.x - map.right);
    const dy = Math.max(map.top - marker.y, 0, marker.y - map.bottom);
    return Math.hypot(dx, dy);
  });
  const segmentDistance = (pointValue, start, end) => {
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const lengthSquared = dx * dx + dy * dy;
    const ratio =
      lengthSquared === 0
        ? 0
        : Math.max(
            0,
            Math.min(
              1,
              ((pointValue.x - start.x) * dx + (pointValue.y - start.y) * dy) / lengthSquared,
            ),
          );
    return Math.hypot(pointValue.x - (start.x + ratio * dx), pointValue.y - (start.y + ratio * dy));
  };
  const sampleSegment = ([start, end]) => {
    const length = Math.hypot(end.x - start.x, end.y - start.y);
    const count = Math.max(1, Math.ceil(length));
    return Array.from({ length: count + 1 }, (_value, index) => ({
      x: start.x + ((end.x - start.x) * index) / count,
      y: start.y + ((end.y - start.y) * index) / count,
    }));
  };
  const expectedPixels = expectedRoute.map(pixel).filter(Boolean);
  const expectedSegments = expectedPixels
    .slice(1)
    .map((end, index) => [expectedPixels[index], end]);
  const polylines = [...document.querySelectorAll("#map path.leaflet-interactive")];
  const polylinePainted = polylines.map((path) => {
    const css = getComputedStyle(path);
    return (
      stylesVisible(path) &&
      hasVisibleAlpha(css.stroke) &&
      Number(css.strokeOpacity) > 0 &&
      Number.parseFloat(css.strokeWidth) > 0
    );
  });
  const polylineLengths = polylines.map((path) => {
    try {
      return path.getTotalLength();
    } catch {
      return 0;
    }
  });
  const pathSamples = polylines.map((path, index) => {
    const matrix = path.getScreenCTM();
    if (!matrix) return [];
    const length = polylineLengths[index];
    const sampleCount = Math.min(4096, Math.max(1, Math.ceil(length)));
    return Array.from({ length: sampleCount + 1 }, (_value, sample) => {
      const local = path.getPointAtLength((length * sample) / sampleCount);
      return new DOMPoint(local.x, local.y).matrixTransform(matrix);
    });
  });
  const polylineMarkerDistances = pathSamples.map((samples) =>
    markerPixels.map((marker) => {
      if (!samples.length) return null;
      return Math.min(
        ...samples.map((sample) => Math.hypot(sample.x - marker.x, sample.y - marker.y)),
      );
    }),
  );
  const polylineRouteMaxDeviations = pathSamples.map((samples) => {
    if (!samples.length || !expectedSegments.length) return null;
    return Math.max(
      ...samples.map((sample) =>
        Math.min(...expectedSegments.map(([start, end]) => segmentDistance(sample, start, end))),
      ),
    );
  });
  const polylineExpectedRouteMaxDeviations = polylines.map((path, index) => {
    const samples = pathSamples[index];
    const bounds = path.ownerSVGElement?.getBoundingClientRect();
    if (!samples.length || !expectedSegments.length || !bounds) return null;
    const expectedSamples = expectedSegments
      .flatMap(sampleSegment)
      .filter(
        (sample) =>
          sample.x >= bounds.left &&
          sample.x <= bounds.right &&
          sample.y >= bounds.top &&
          sample.y <= bounds.bottom,
      );
    if (!expectedSamples.length) return null;
    const cellSize = 4;
    const buckets = new Map();
    for (const sample of samples) {
      const x = Math.floor(sample.x / cellSize);
      const y = Math.floor(sample.y / cellSize);
      const key = `${x},${y}`;
      if (!buckets.has(key)) buckets.set(key, []);
      buckets.get(key).push(sample);
    }
    const nearest = (expected) => {
      const originX = Math.floor(expected.x / cellSize);
      const originY = Math.floor(expected.y / cellSize);
      let distance = Infinity;
      for (let x = originX - 1; x <= originX + 1; x++) {
        for (let y = originY - 1; y <= originY + 1; y++) {
          for (const sample of buckets.get(`${x},${y}`) ?? []) {
            distance = Math.min(distance, Math.hypot(sample.x - expected.x, sample.y - expected.y));
          }
        }
      }
      return distance;
    };
    return Math.max(...expectedSamples.map(nearest));
  });
  const help = document.querySelector("#pushWarning a");
  return JSON.stringify({
    provider: text("providerView"),
    battery: text("batView"),
    deviceId: text("idView"),
    date: text("dateView"),
    time: text("timeView"),
    visibility: Object.fromEntries(
      Object.entries(fields).map(([name, element]) => [name, textRendered(element)]),
    ),
    interpretedElements: provider?.querySelectorAll("[data-sitecmd-probe]").length ?? -1,
    center: point(map.left + map.width / 2, map.top + map.height / 2),
    zoom: tile?.zoom ?? null,
    markerPoints,
    markerPainted,
    markerUnobscured,
    markerHitInMap,
    activeMarkerBox,
    markerCropBoxes,
    markerViewportDistances,
    polylines: polylines.length,
    polylinePainted,
    polylineLengths,
    polylineMarkerDistances,
    polylineRouteMaxDeviations,
    polylineExpectedRouteMaxDeviations,
    pageOverrideInstalled: document.documentElement.dataset.sitecmdOverride === "installed",
    help: { link: help?.getAttribute("href") ?? null, label: help?.textContent ?? null },
  });
})();
