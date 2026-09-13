import base64
import html
import json
import hashlib
import math
import mimetypes
import os
import pathlib
import re
import secrets
import ssl
import subprocess
import threading
import time
import uuid
import zlib
from datetime import datetime
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gdk, Gio, GLib, Gtk, WebKit2

fixture_bytes = pathlib.Path("/fixture.json").read_bytes()
fixture = json.loads(fixture_bytes)
render_mode = fixture.get("renderMode", "none")
expected_render_frames = fixture.get("expectedRenderFrames", [])
expected_details_frames = fixture.get("expectedDetailsFrames", [])
expected_transition_frames = fixture.get("expectedTransitionFrames", [])
expected_marker_body_pixels = fixture.get("expectedMarkerBodyPixels", {})
marker_opaque_mask_base64 = fixture.get("markerOpaqueMaskBase64")
marker_opaque_mask_sha256 = fixture.get("markerOpaqueMaskSha256")
marker_asset_rgb_base64 = fixture.get("markerAssetRgbBase64")
marker_asset_rgb_sha256 = fixture.get("markerAssetRgbSha256")
details_render_indexes = fixture.get("detailsRenderIndexes", [])
map_render_indexes = fixture.get("mapRenderIndexes", [])
for box_name in ("detailsRenderBox", "mapRenderBox"):
    box = fixture.get(box_name)
    coordinates = (box or {}).values() if isinstance(box, dict) else ()
    if (
        not isinstance(box, dict)
        or set(box) != {"left", "top", "right", "bottom"}
        or any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in coordinates)
        or any(not math.isfinite(value) for value in coordinates)
        or not 0 <= box["left"] < box["right"] <= 1280
        or not 0 <= box["top"] < box["bottom"] <= 1600
    ):
        raise ValueError(f"Invalid controller-owned {box_name}")
if render_mode == "compare" and len(expected_render_frames) != 10:
    raise ValueError("Expected ten controller-owned render frames")
if render_mode == "compare" and len(expected_details_frames) != 10:
    raise ValueError("Expected ten controller-owned details reference sets")
if (
    render_mode == "compare"
    and (
        len(expected_transition_frames) != 10
        or any(not isinstance(frames, list) or not frames for frames in expected_transition_frames)
    )
):
    raise ValueError("Expected ten controller-owned transition reference sets")
if render_mode == "compare" and details_render_indexes != list(range(10)):
    raise ValueError("Unexpected details checkpoint indexes")
if render_mode == "compare" and map_render_indexes != list(range(10)):
    raise ValueError("Unexpected map checkpoint indexes")
if (
    render_mode == "compare"
    and (
        not isinstance(expected_marker_body_pixels, dict)
        or not expected_marker_body_pixels
        or any(
            not re.fullmatch(r"[a-f0-9]{64}", key)
            or not isinstance(value, str)
            for key, value in expected_marker_body_pixels.items()
        )
    )
):
    raise ValueError("Expected marker body pixel pool is invalid")
if (
    isinstance(fixture.get("mapHistogramDistanceLimit"), bool)
    or not isinstance(fixture.get("mapHistogramDistanceLimit"), (int, float))
    or not 0 < fixture["mapHistogramDistanceLimit"] < 1
):
    raise ValueError("Invalid controller-owned map histogram distance limit")
if (
    isinstance(fixture.get("mapSpatialDistanceLimit"), bool)
    or not isinstance(fixture.get("mapSpatialDistanceLimit"), (int, float))
    or not 0 < fixture["mapSpatialDistanceLimit"] < 1
):
    raise ValueError("Invalid controller-owned map spatial distance limit")
for field in ("mapPersistenceHistogramLimit", "mapPersistenceSpatialLimit"):
    value = fixture.get(field)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value < 0.001
    ):
        raise ValueError(f"Invalid controller-owned {field}")
for field in ("mapSampleOffset", "mapGridPhaseX", "mapGridPhaseY"):
    value = fixture.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 8:
        raise ValueError(f"Invalid controller-owned {field}")
for field in (
    "markerMaterialDeltaThreshold",
    "markerMaterialPixelLimit",
    "markerTotalDifferenceLimit",
):
    value = fixture.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Invalid controller-owned {field}")
try:
    marker_opaque_mask = base64.b64decode(
        marker_opaque_mask_base64, validate=True
    )
except (TypeError, ValueError) as error:
    raise ValueError("Invalid controller-owned marker opaque mask") from error
if (
    len(marker_opaque_mask) != 25 * 41
    or any(value not in (0, 1) for value in marker_opaque_mask)
    or sum(marker_opaque_mask) < 300
    or not isinstance(marker_opaque_mask_sha256, str)
    or hashlib.sha256(marker_opaque_mask).hexdigest()
    != marker_opaque_mask_sha256
):
    raise ValueError("Invalid controller-owned marker opaque mask")
try:
    marker_asset_rgb = base64.b64decode(
        marker_asset_rgb_base64, validate=True
    )
except (TypeError, ValueError) as error:
    raise ValueError("Invalid controller-owned marker RGB data") from error
if (
    len(marker_asset_rgb) != 25 * 41 * 3
    or not isinstance(marker_asset_rgb_sha256, str)
    or hashlib.sha256(marker_asset_rgb).hexdigest() != marker_asset_rgb_sha256
):
    raise ValueError("Invalid controller-owned marker RGB data")
observer = pathlib.Path("/actions.js").read_text()
if observer.count("__SITECMD_EXPECTED_ROUTE__") != 1:
    raise ValueError("Observer route placeholder is invalid")
source = pathlib.Path("/work/web").resolve()
source_files_sha256 = {
    name: hashlib.sha256((source / name).read_bytes()).hexdigest()
    for name in (
        "logic.js",
        "style.css",
        "apiv1.js",
        "node_modules/hammerjs/changelog.js",
    )
}
isolated_world = "sitecmd-observer-" + uuid.uuid4().hex
observer_world = None if fixture["observationMode"] == "page-world-control" else isolated_world
paint_isolation_state = "sitecmd-paint-isolation-" + uuid.uuid4().hex
message_handler = "sitecmdMutation" + uuid.uuid4().hex
sink_message_handler = "sitecmdSink" + uuid.uuid4().hex
sink_bridge_token = secrets.token_hex(32)
mutation_waiters = {}
sink_reports, sink_ready_frames = [], []
requests, observations, checks, render_settles = [], [], [], []
early_render_samples, pending_action_samples = [], []
marker_body_pixels = {}
mode = "locations"
finished = started = False
expected_route = []
result = {"passed": False, "checks": checks, "observations": observations,
          "renderSettles": render_settles, "setupError": None,
          "earlyRenderSamples": early_render_samples,
          "pendingActionSamples": pending_action_samples,
          "markerBodyPixels": marker_body_pixels,
          "fixtureSha256": hashlib.sha256(fixture_bytes).hexdigest(),
          "sourceFilesSha256": source_files_sha256}
steps = [(3, "locate(-1)"), (2, "locateOlder()"), (1, "locateOlder()"),
         (0, "locateOlder()"), (1, "locateNewer()"), (2, "locateNewer()"), (3, "locate(-1)")]
visited = set()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, body, content_type="text/plain"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", fixture["csp"])
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlsplit(self.path).path
        requests.append({"method": "GET", "path": route})
        if route == "/api/v1/version":
            return self.respond(200, "v0.7.1")
        if route == "/__qualification/blank.html":
            return self.respond(200, "<!doctype html><html><body></body></html>", "text/html")
        target = (source / (unquote(route).lstrip("/") or "index.html")).resolve()
        if not target.is_relative_to(source) or not target.is_file():
            return self.respond(404, "Not found")
        self.respond(200, target.read_bytes(), mimetypes.guess_type(str(target))[0] or "application/octet-stream")

    def request_data(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 <= size <= 8192:
            raise ValueError("Unexpected request size")
        value = json.loads(self.rfile.read(size) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("Expected a request object")
        return value

    def do_POST(self):
        route, data = urlsplit(self.path).path, self.request_data()
        requests.append({"method": "POST", "path": route, "data": data})
        if route in ("/push", "/api/v1/push") and data.get("IDT") == fixture["token"]:
            return self.respond(200, "")
        self.respond(403, "Unexpected request")

    def do_PUT(self):
        route, data = urlsplit(self.path).path, self.request_data()
        requests.append({"method": "PUT", "path": route, "data": data})
        if data.get("IDT") != fixture["token"]:
            return self.respond(403, "Invalid fixture session")
        if route == "/api/v1/locationDataSize":
            count = 0 if mode == "empty" else len(fixture["samples"])
            return self.respond(200, json.dumps({"Data": str(count)}), "application/json")
        if route == "/api/v1/location" and mode != "empty":
            index = data.get("Data")
            if index not in [str(value) for value in range(len(fixture["samples"]))]:
                return self.respond(400, "Invalid location index")
            packet = fixture["samples"][int(index)]["packet"] if mode == "locations" else "invalid-packet"
            return self.respond(200, json.dumps({"Data": packet}), "application/json")
        self.respond(404, "Unexpected request")


def check(name, passed):
    checks.append({"name": name, "passed": bool(passed)})


def close(error=None):
    global finished
    if finished:
        return
    finished = True
    result["setupError"] = error
    result["requests"] = requests
    result["sinkMonitorSha256"] = hashlib.sha256(
        sink_monitor_script.encode()
    ).hexdigest()
    result["sinkMonitorBinding"] = {
        "messageHandler": sink_message_handler,
        "bridgeToken": sink_bridge_token,
    }
    result["sinkReadyFrames"] = sink_ready_frames
    expected_checks = 82 + 3 * len(details_render_indexes) if render_mode == "compare" else 82
    result["passed"] = error is None and len(checks) == expected_checks and all(item["passed"] for item in checks)
    result["runtime"] = {
        "webkit": f"{WebKit2.get_major_version()}.{WebKit2.get_minor_version()}.{WebKit2.get_micro_version()}",
        "gtk": f"{Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}",
        "network": "unshared namespace, owned loopback server only",
        "observationWorld": "page-world-control" if observer_world is None else isolated_world,
        "mutationChannel": "isolated observer, provider visibility sampler, and document-start sink bridges",
        "locale": "en-US", "timezone": "UTC",
        "scope": "Authenticated browser rendering; controller-owned expectations and DOM observations",
    }
    Gtk.main_quit()


arm_mutation_observer = """
(() => {
  const stateKey = __SITECMD_MUTATION_STATE_KEY__;
  const stopEvent = __SITECMD_MUTATION_STOP_EVENT__;
  const messageHandler = __SITECMD_MUTATION_MESSAGE_HANDLER__;
  const interpretedProviderTexts = new Set(__SITECMD_INTERPRETED_PROVIDER_TEXTS__);
  const initialProvider = document.getElementById('providerView');
  const state = {
    armed: 1,
    interpretedElements: 0,
    interpretedTextNodes: 0,
    interpretedAttributes: 0,
    interpretedShadowRoots: 0,
    recordBatches: 0,
    providerVisibilitySamples: 0,
    providerVisibleSamples: 0,
    providerHiddenAfterVisibleSamples: 0,
    providerWasVisible: false,
  };
  const seenShadowRoots = new WeakSet();
  const providerTextNodes = new WeakSet();
  const providerFor = node => {
    if (!(node instanceof Node) || node.nodeType === Node.DOCUMENT_NODE) return null;
    const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (
      initialProvider
      && (node === initialProvider || element === initialProvider || initialProvider.contains(node))
    ) return initialProvider;
    if (element?.id === 'providerView') return element;
    return element?.closest?.('#providerView') ?? null;
  };
  const textInterpreted = value => interpretedProviderTexts.has(String(value ?? ''));
  const filterAllowsPaint = value => {
    const filter = String(value ?? '').trim().toLowerCase();
    if (!filter || filter === 'none') return true;
    for (const match of filter.matchAll(/opacity\\(\\s*([0-9]*\\.?[0-9]+)\\s*(%)?\\s*\\)/g)) {
      const opacity = Number(match[1]) / (match[2] ? 100 : 1);
      if (!Number.isFinite(opacity) || opacity <= 0) return false;
    }
    return true;
  };
  const providerVisible = () => {
    const provider = document.getElementById('providerView');
    if (!provider) return false;
    for (let element = provider; element instanceof Element; element = element.parentElement) {
      const style = getComputedStyle(element);
      if (
        style.display === 'none'
        || style.visibility !== 'visible'
        || style.contentVisibility === 'hidden'
        || Number(style.opacity) <= 0
        || !filterAllowsPaint(style.filter || style.webkitFilter)
      ) return false;
    }
    return [...provider.getClientRects()].some(rect => rect.width > 0 && rect.height > 0);
  };
  const sampleProviderVisibility = () => {
    const visible = providerVisible();
    state.providerVisibilitySamples += 1;
    if (visible) {
      state.providerVisibleSamples += 1;
      state.providerWasVisible = true;
    } else if (state.providerWasVisible) {
      state.providerHiddenAfterVisibleSamples += 1;
    }
  };
  const countMarkerElements = root => {
    let count = root instanceof Element && root.matches('[data-sitecmd-probe]') ? 1 : 0;
    if (root instanceof Element || root instanceof DocumentFragment) {
      count += root.querySelectorAll('[data-sitecmd-probe]').length;
    }
    state.interpretedElements += count;
    return count;
  };
  const inspectTextNode = node => {
    providerTextNodes.add(node);
    if (!textInterpreted(node.data)) return 0;
    state.interpretedTextNodes += 1;
    return 1;
  };
  const inspectShadowRoot = root => {
    if (!(root instanceof ShadowRoot) || seenShadowRoots.has(root)) return 0;
    const markerCount = countMarkerElements(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let interpretedText = 0;
    for (let text = walker.nextNode(); text; text = walker.nextNode()) {
      interpretedText += inspectTextNode(text);
    }
    if (!markerCount && !interpretedText) return 0;
    seenShadowRoots.add(root);
    state.interpretedShadowRoots += 1;
    return 1;
  };
  const inspectShadowTree = root => {
    let found = 0;
    const elements = root instanceof Element
      ? [root, ...root.querySelectorAll('*')]
      : [...root.querySelectorAll('*')];
    for (const element of elements) {
      if (!element.shadowRoot) continue;
      found += inspectShadowRoot(element.shadowRoot);
      found += inspectShadowTree(element.shadowRoot);
    }
    return found;
  };
  const inspectProviderTree = (node, provider) => {
    let found = 0;
    if (node instanceof Text) {
      found += inspectTextNode(node);
    } else if (node instanceof Element || node instanceof DocumentFragment) {
      found += countMarkerElements(node);
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
      for (let text = walker.nextNode(); text; text = walker.nextNode()) {
        found += inspectTextNode(text);
      }
      found += inspectShadowTree(node);
    }
    return found;
  };
  const inspectAddedNode = (node, targetProvider) => {
    if (targetProvider) return inspectProviderTree(node, targetProvider);
    if (!(node instanceof Element)) return 0;
    const provider = node.id === 'providerView'
      ? node
      : node.querySelector('#providerView');
    return provider ? inspectProviderTree(provider, provider) : inspectShadowTree(node);
  };
  const scanShadowRoots = () => inspectShadowTree(document);
  const inspectRecords = records => {
    let found = 0;
    for (const record of records) {
      const provider = providerFor(record.target);
      if (
        record.type === 'attributes'
        && record.attributeName === 'data-sitecmd-probe'
        && record.oldValue !== null
      ) {
        state.interpretedAttributes += 1;
        found += 1;
      } else if (
        record.type === 'characterData'
        && (provider || providerTextNodes.has(record.target))
      ) {
        if (textInterpreted(record.oldValue)) {
          state.interpretedTextNodes += 1;
          found += 1;
        }
      } else if (record.type === 'childList') {
        for (const node of record.addedNodes) {
          found += inspectAddedNode(node, provider);
        }
      }
    }
    found += scanShadowRoots();
    if (found > 0) state.recordBatches += 1;
  };
  const observer = new MutationObserver(records => {
    inspectRecords(records);
  });
  observer.observe(document, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['data-sitecmd-probe'],
    attributeOldValue: true,
    characterData: true,
    characterDataOldValue: true,
  });
  sampleProviderVisibility();
  const shadowTimer = setInterval(() => {
    scanShadowRoots();
    sampleProviderVisibility();
  }, 10);
  document.addEventListener(stopEvent, () => {
    clearInterval(shadowTimer);
    inspectRecords(observer.takeRecords());
    observer.disconnect();
    scanShadowRoots();
    sampleProviderVisibility();
    window.webkit.messageHandlers[messageHandler].postMessage(JSON.stringify({
      stateKey,
      summary: {
        armed: state.armed,
        interpretedElements: state.interpretedElements,
        interpretedTextNodes: state.interpretedTextNodes,
        interpretedAttributes: state.interpretedAttributes,
        interpretedShadowRoots: state.interpretedShadowRoots,
        recordBatches: state.recordBatches,
        providerVisibilitySamples: state.providerVisibilitySamples,
        providerVisibleSamples: state.providerVisibleSamples,
        providerHiddenAfterVisibleSamples: state.providerHiddenAfterVisibleSamples,
      },
    }));
  }, { once: true });
  return true;
})()
"""


class ProviderSemanticParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.tags = set()
        self.text_fragments = []

    def handle_starttag(self, tag, _attrs):
        self.tags.add(tag.lower())
        self.depth += 1

    def handle_startendtag(self, tag, _attrs):
        self.tags.add(tag.lower())

    def handle_endtag(self, _tag):
        self.depth = max(0, self.depth - 1)

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_fragments.append(text)


def make_sink_monitor():
    provider_inputs = [sample["location"]["provider"] for sample in fixture["samples"]]
    decoded_inputs = [
        {"index": index, "text": decoded}
        for index, value in enumerate(provider_inputs)
        for decoded in (html.unescape(value),)
        if decoded != value
    ]
    marker_inputs = [
        {"index": index, "value": marker}
        for index, value in enumerate(provider_inputs)
        for marker in re.findall(r'data-sitecmd-probe="([^"]+)"', value)
    ]
    semantic_inputs = []
    for index, value in enumerate(provider_inputs):
        parser = ProviderSemanticParser()
        parser.feed(value)
        parser.close()
        if parser.tags and parser.text_fragments:
            semantic_inputs.append({
                "index": index,
                "tags": sorted(parser.tags),
                "textFragments": list(dict.fromkeys(parser.text_fragments)),
            })
    return """
(() => {
  const token = __SITECMD_SINK_BRIDGE_TOKEN__;
  const handler = __SITECMD_SINK_MESSAGE_HANDLER__;
  const providerInputs = __SITECMD_PROVIDER_INPUTS__;
  const decodedInputs = __SITECMD_DECODED_INPUTS__;
  const markerInputs = __SITECMD_MARKER_INPUTS__;
  const semanticInputs = __SITECMD_SEMANTIC_INPUTS__;
  const bridge = window.webkit.messageHandlers[handler];
  const post = bridge.postMessage.bind(bridge);
  const apply = Reflect.apply;
  const defineProperty = Object.defineProperty.bind(Object);
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor.bind(Object);
  const stringify = JSON.stringify.bind(JSON);
  const toText = String;
  const uncurryThis = Function.prototype.bind.bind(Function.prototype.call);
  const includes = uncurryThis(String.prototype.includes);
  const toLowerCase = uncurryThis(String.prototype.toLowerCase);
  const isPrototypeOf = uncurryThis(Object.prototype.isPrototypeOf);
  const SetConstructor = Set;
  const setHas = uncurryThis(Set.prototype.has);
  const setAdd = uncurryThis(Set.prototype.add);
  const iframePrototype = globalThis.HTMLIFrameElement?.prototype;
  const attrPrototype = globalThis.Attr?.prototype;
  const templatePrototype = globalThis.HTMLTemplateElement?.prototype;
  const getAttribute = uncurryThis(Element.prototype.getAttribute);
  const getElementById = uncurryThis(Document.prototype.getElementById);
  const querySelectorAll = uncurryThis(Element.prototype.querySelectorAll);
  const textContentGetter = getOwnPropertyDescriptor(Node.prototype, 'textContent')?.get;
  const localNameGetter = getOwnPropertyDescriptor(Element.prototype, 'localName')?.get;
  const templateContentGetter = templatePrototype
    ? getOwnPropertyDescriptor(templatePrototype, 'content')?.get
    : null;
  const sourceParserPrototype = globalThis.DOMParser?.prototype;
  const sourceParserMethod = sourceParserPrototype
    ? getOwnPropertyDescriptor(sourceParserPrototype, 'parseFromString')?.value
    : null;
  const sourceParser = globalThis.DOMParser ? new globalThis.DOMParser() : null;
  const inspectedSrcdocValues = new Set();
  const quote = value => stringify(toText(value));
  const toHtmlText = value => value === null ? '' : toText(value);
  const canBeInterpreted = value => includes(value, '<') || includes(value, '&');
  const matchingInput = text => {
    for (let index = 0; index < providerInputs.length; index += 1) {
      const input = providerInputs[index];
      if (
        canBeInterpreted(input)
        && (text === input || includes(text, input))
      ) return { index, length: text.length };
    }
    return null;
  };
  const postMatch = (sink, match) => {
    post(
      '{"token":' + quote(token)
      + ',"kind":"sink","sink":' + quote(sink)
      + ',"matchIndex":' + stringify(match.index)
      + ',"valueLength":' + stringify(match.length)
      + ',"frameUrl":' + quote(location.href) + '}'
    );
  };
  const report = (sink, text) => {
    const match = matchingInput(text);
    if (!match) return text;
    postMatch(sink, match);
    return text;
  };
  const reportSemanticSource = (sink, text) => {
    if (!sourceParser || typeof sourceParserMethod !== 'function') {
      report(sink, text);
      return text;
    }
    const parsed = apply(sourceParserMethod, sourceParser, [text, 'text/html']);
    inspectNode(parsed, new SetConstructor(), true);
    return text;
  };
  const reportDomInput = (sink, input, length, reportedInputs) => {
    if (setHas(reportedInputs, input.index)) return;
    setAdd(reportedInputs, input.index);
    postMatch(sink, { index: input.index, length });
  };
  const inspectText = (text, reportedInputs) => {
    for (let index = 0; index < decodedInputs.length; index += 1) {
      const input = decodedInputs[index];
      if (includes(text, input.text)) {
        reportDomInput('parsed DOM text', input, text.length, reportedInputs);
      }
    }
  };
  const inspectElement = (root, reportedInputs, allowSemantic) => {
    const elements = [root];
    const descendants = querySelectorAll(root, '*');
    for (let index = 0; index < descendants.length; index += 1) {
      elements.push(descendants[index]);
    }
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const marker = getAttribute(element, 'data-sitecmd-probe');
      if (marker !== null) {
        for (let inputIndex = 0; inputIndex < markerInputs.length; inputIndex += 1) {
          const input = markerInputs[inputIndex];
          if (toLowerCase(marker) === toLowerCase(input.value)) {
            reportDomInput(
              'parsed DOM marker', input, marker.length, reportedInputs
            );
          }
        }
      }
      if (iframePrototype && isPrototypeOf(iframePrototype, element)) {
        const srcdoc = getAttribute(element, 'srcdoc');
        if (srcdoc !== null && !setHas(inspectedSrcdocValues, srcdoc)) {
          setAdd(inspectedSrcdocValues, srcdoc);
          reportSemanticSource('HTMLIFrameElement parsed srcdoc', srcdoc);
        }
      }
      if (
        templatePrototype
        && templateContentGetter
        && isPrototypeOf(templatePrototype, element)
      ) {
        inspectNode(
          apply(templateContentGetter, element, []),
          reportedInputs,
          allowSemantic
        );
      }
    }
    if (textContentGetter) {
      const text = toText(apply(textContentGetter, root, []));
      if (allowSemantic) {
        const normalizedText = toLowerCase(text);
        const names = new SetConstructor();
        if (localNameGetter) {
          for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
            setAdd(
              names,
              toLowerCase(
                toText(apply(localNameGetter, elements[elementIndex], []))
              ),
            );
          }
        }
        for (let inputIndex = 0; inputIndex < semanticInputs.length; inputIndex += 1) {
          const input = semanticInputs[inputIndex];
          let tagMatches = true;
          for (let tagIndex = 0; tagIndex < input.tags.length; tagIndex += 1) {
            if (!setHas(names, input.tags[tagIndex])) tagMatches = false;
          }
          let textMatches = true;
          for (
            let fragmentIndex = 0;
            fragmentIndex < input.textFragments.length;
            fragmentIndex += 1
          ) {
            if (
              !includes(
                normalizedText,
                toLowerCase(input.textFragments[fragmentIndex]),
              )
            ) textMatches = false;
          }
          if (tagMatches && textMatches) {
            reportDomInput(
              'parsed DOM structure', input, text.length, reportedInputs
            );
          }
        }
      }
      inspectText(text, reportedInputs);
    }
  };
  const inspectNode = (
    node, reportedInputs = new SetConstructor(), allowSemantic = false
  ) => {
    if (!node) return;
    if (node.nodeType === 1) {
      inspectElement(node, reportedInputs, allowSemantic);
    }
    else if (node.nodeType === 3) inspectText(toText(node.data), reportedInputs);
    else if (node.nodeType === 9) {
      inspectNode(node.documentElement, reportedInputs, allowSemantic);
    }
    else if (node.nodeType === 11) {
      for (let child = node.firstChild; child; child = child.nextSibling) {
        inspectNode(child, reportedInputs, allowSemantic);
      }
    }
  };
  const wrapSetter = (
    prototype, name, sink = name, convert = toText,
    inspectResult = null, reportInput = true
  ) => {
    if (!prototype) return;
    const descriptor = getOwnPropertyDescriptor(prototype, name);
    if (!descriptor?.set) return;
    const original = descriptor.set;
    defineProperty(prototype, name, {
      ...descriptor,
      set(value) {
        const text = convert(value);
        if (reportInput === 'semantic') reportSemanticSource(sink, text);
        else if (reportInput) report(sink, text);
        const inspectionRoot = inspectResult === 'parent' ? this.parentNode : this;
        const result = apply(original, this, [text]);
        if (inspectResult) {
          inspectNode(inspectionRoot, new SetConstructor(), true);
        }
        return result;
      },
    });
  };
  const wrapMethod = (
    prototype, name, indexes = [0], sink = name,
    inspectResult = null, reportInput = true
  ) => {
    if (!prototype) return;
    const descriptor = getOwnPropertyDescriptor(prototype, name);
    if (typeof descriptor?.value !== 'function') return;
    const original = descriptor.value;
    defineProperty(prototype, name, {
      ...descriptor,
      value(...args) {
        const count = indexes === null ? args.length : indexes.length;
        for (let offset = 0; offset < count; offset += 1) {
          const index = indexes === null ? offset : indexes[offset];
          const text = toText(args[index]);
          args[index] = text;
          if (reportInput === 'semantic') reportSemanticSource(sink, text);
          else if (reportInput) report(sink, text);
        }
        const result = apply(original, this, args);
        if (inspectResult === 'return') {
          inspectNode(result, new SetConstructor(), true);
        } else if (inspectResult === 'parent') {
          inspectNode(this.parentNode || this, new SetConstructor(), true);
        } else if (inspectResult === 'self') {
          inspectNode(this, new SetConstructor(), true);
        }
        return result;
      },
    });
  };
  const wrapSrcdocAttribute = (name, nameIndex, valueIndex) => {
    const descriptor = getOwnPropertyDescriptor(Element.prototype, name);
    if (typeof descriptor?.value !== 'function') return;
    const original = descriptor.value;
    defineProperty(Element.prototype, name, {
      ...descriptor,
      value(...args) {
        const rawName = toText(args[nameIndex]);
        const attributeName = toLowerCase(rawName);
        const text = toText(args[valueIndex]);
        args[nameIndex] = rawName;
        args[valueIndex] = text;
        if (
          iframePrototype
          && isPrototypeOf(iframePrototype, this)
          && attributeName === 'srcdoc'
        ) reportSemanticSource('HTMLIFrameElement.' + name, text);
        return apply(original, this, args);
      },
    });
  };
  const wrapSrcdocAttributeNode = () => {
    for (const name of ['setAttributeNode', 'setAttributeNodeNS']) {
      const descriptor = getOwnPropertyDescriptor(Element.prototype, name);
      if (typeof descriptor?.value !== 'function') continue;
      const original = descriptor.value;
      defineProperty(Element.prototype, name, {
        ...descriptor,
        value(attribute) {
          if (
            iframePrototype
            && isPrototypeOf(iframePrototype, this)
            && toLowerCase(toText(attribute?.name)) === 'srcdoc'
          ) reportSemanticSource(
            'HTMLIFrameElement.' + name, toText(attribute.value)
          );
          return apply(original, this, [attribute]);
        },
      });
    }
  };
  const wrapSrcdocAttrSetter = name => {
    const descriptor = getOwnPropertyDescriptor(Attr.prototype, name);
    if (!descriptor?.set) return;
    const original = descriptor.set;
    defineProperty(Attr.prototype, name, {
      ...descriptor,
      set(value) {
        const text = toText(value);
        if (
          iframePrototype
          && isPrototypeOf(iframePrototype, this.ownerElement)
          && toLowerCase(toText(this.name)) === 'srcdoc'
        ) reportSemanticSource('HTMLIFrameElement.srcdoc Attr.' + name, text);
        return apply(original, this, [text]);
      },
    });
  };
  const wrapSrcdocNodeSetter = name => {
    const descriptor = getOwnPropertyDescriptor(Node.prototype, name);
    if (!descriptor?.set) return;
    const original = descriptor.set;
    defineProperty(Node.prototype, name, {
      ...descriptor,
      set(value) {
        if (
          attrPrototype
          && isPrototypeOf(attrPrototype, this)
          && iframePrototype
          && isPrototypeOf(iframePrototype, this.ownerElement)
          && toLowerCase(toText(this.name)) === 'srcdoc'
        ) reportSemanticSource(
          'HTMLIFrameElement.srcdoc Attr.' + name, toText(value)
        );
        return apply(original, this, [value]);
      },
    });
  };
  const wrapSrcdocNamedItem = name => {
    const descriptor = getOwnPropertyDescriptor(NamedNodeMap.prototype, name);
    if (typeof descriptor?.value !== 'function') return;
    const original = descriptor.value;
    defineProperty(NamedNodeMap.prototype, name, {
      ...descriptor,
      value(attribute) {
        const replaced = apply(original, this, [attribute]);
        if (
          iframePrototype
          && isPrototypeOf(iframePrototype, attribute?.ownerElement)
          && toLowerCase(toText(attribute?.name)) === 'srcdoc'
        ) reportSemanticSource(
          'HTMLIFrameElement.attributes.' + name, toText(attribute.value)
        );
        return replaced;
      },
    });
  };
  const wrapDomParser = () => {
    const prototype = globalThis.DOMParser?.prototype;
    const descriptor = prototype
      ? getOwnPropertyDescriptor(prototype, 'parseFromString')
      : null;
    if (typeof descriptor?.value !== 'function') return;
    const original = descriptor.value;
    defineProperty(prototype, 'parseFromString', {
      ...descriptor,
      value(source, mimeType) {
        const text = toText(source);
        const type = toText(mimeType);
        if (toLowerCase(type) === 'text/html') {
          reportSemanticSource('parseFromString', text);
        }
        const result = apply(original, this, [text, type]);
        inspectNode(result, new SetConstructor(), true);
        return result;
      },
    });
  };
  const parserObserver = new MutationObserver(records => {
    for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
      const record = records[recordIndex];
      if (record.type === 'characterData') inspectNode(record.target);
      else {
        for (let nodeIndex = 0; nodeIndex < record.addedNodes.length; nodeIndex += 1) {
          inspectNode(record.addedNodes[nodeIndex]);
        }
      }
    }
  });
  const observeProviderRoot = () => {
    const providerRoot = getElementById(document, 'providerView');
    if (!providerRoot) return;
    parserObserver.observe(
      providerRoot, { childList: true, subtree: true, characterData: true }
    );
    inspectNode(providerRoot);
  };
  const wrapAttachShadow = () => {
    const descriptor = getOwnPropertyDescriptor(Element.prototype, 'attachShadow');
    if (typeof descriptor?.value !== 'function') return;
    const original = descriptor.value;
    defineProperty(Element.prototype, 'attachShadow', {
      ...descriptor,
      value(...args) {
        const root = apply(original, this, args);
        parserObserver.observe(root, { childList: true, subtree: true, characterData: true });
        inspectNode(root);
        return root;
      },
    });
  };
  wrapSetter(
    Element.prototype, 'innerHTML', 'innerHTML', toHtmlText, 'self', false
  );
  wrapSetter(
    Element.prototype, 'outerHTML', 'outerHTML', toHtmlText, 'parent', false
  );
  wrapSetter(
    globalThis.ShadowRoot?.prototype,
    'innerHTML',
    'ShadowRoot.innerHTML',
    toHtmlText,
    'self',
    false
  );
  wrapSetter(
    globalThis.HTMLIFrameElement?.prototype,
    'srcdoc',
    'HTMLIFrameElement.srcdoc',
    toText,
    null,
    'semantic'
  );
  wrapSrcdocAttribute('setAttribute', 0, 1);
  wrapSrcdocAttribute('setAttributeNS', 1, 2);
  wrapSrcdocAttributeNode();
  wrapSrcdocAttrSetter('value');
  wrapSrcdocNodeSetter('nodeValue');
  wrapSrcdocNodeSetter('textContent');
  wrapSrcdocNamedItem('setNamedItem');
  wrapSrcdocNamedItem('setNamedItemNS');
  wrapMethod(
    Element.prototype, 'insertAdjacentHTML', [1],
    'insertAdjacentHTML', 'parent', false
  );
  wrapMethod(Document.prototype, 'write', null, 'write', 'self', false);
  wrapMethod(Document.prototype, 'writeln', null, 'writeln', 'self', false);
  wrapDomParser();
  wrapMethod(
    globalThis.Range?.prototype,
    'createContextualFragment',
    [0],
    'createContextualFragment',
    'return',
    false
  );
  wrapMethod(
    Element.prototype,
    'setHTMLUnsafe',
    [0],
    'setHTMLUnsafe',
    'self',
    'semantic'
  );
  wrapMethod(
    globalThis.ShadowRoot?.prototype,
    'setHTMLUnsafe',
    [0],
    'ShadowRoot.setHTMLUnsafe',
    'self',
    'semantic'
  );
  wrapMethod(
    globalThis.Document,
    'parseHTMLUnsafe',
    [0],
    'Document.parseHTMLUnsafe',
    'return',
    'semantic'
  );
  wrapAttachShadow();
  observeProviderRoot();
  document.addEventListener('DOMContentLoaded', observeProviderRoot, { once: true });
  post(
    '{"token":' + quote(token)
    + ',"kind":"ready","frameUrl":' + quote(location.href) + '}'
  );
})()
""".replace(
        "__SITECMD_SINK_BRIDGE_TOKEN__", json.dumps(sink_bridge_token)
    ).replace(
        "__SITECMD_SINK_MESSAGE_HANDLER__", json.dumps(sink_message_handler)
    ).replace(
        "__SITECMD_PROVIDER_INPUTS__", json.dumps(provider_inputs)
    ).replace(
        "__SITECMD_DECODED_INPUTS__", json.dumps(decoded_inputs)
    ).replace(
        "__SITECMD_MARKER_INPUTS__", json.dumps(marker_inputs)
    ).replace(
        "__SITECMD_SEMANTIC_INPUTS__", json.dumps(semantic_inputs)
    )


sink_monitor_script = make_sink_monitor()


def sink_message_received(_manager, message):
    if finished:
        return
    try:
        value = message.get_js_value() if hasattr(message, "get_js_value") else message
        payload = json.loads(value.to_string())
        if not isinstance(payload, dict) or payload.get("token") != sink_bridge_token:
            raise ValueError("Invalid sink bridge payload")
        kind = payload.get("kind")
        if kind == "ready" and set(payload) == {"token", "kind", "frameUrl"}:
            sink_ready_frames.append(payload["frameUrl"])
            return
        if kind != "sink" or set(payload) != {
            "token", "kind", "sink", "matchIndex", "valueLength", "frameUrl"
        }:
            raise ValueError("Invalid sink bridge report")
        if (
            not isinstance(payload["sink"], str)
            or isinstance(payload["matchIndex"], bool)
            or not isinstance(payload["matchIndex"], int)
            or not 0 <= payload["matchIndex"] < len(fixture["samples"])
            or isinstance(payload["valueLength"], bool)
            or not isinstance(payload["valueLength"], int)
            or payload["valueLength"] < 0
            or not isinstance(payload["frameUrl"], str)
        ):
            raise ValueError("Invalid sink bridge fields")
        if len(sink_reports) >= 2048:
            raise ValueError("Too many sink bridge reports")
        sink_reports.append({key: payload[key] for key in (
            "sink", "matchIndex", "valueLength", "frameUrl"
        )})
    except Exception as error:
        close(str(error))


def mutation_message_received(_manager, message):
    if finished:
        return
    try:
        value = message.get_js_value() if hasattr(message, "get_js_value") else message
        payload = json.loads(value.to_string())
        if not isinstance(payload, dict) or set(payload) != {"stateKey", "summary"}:
            raise ValueError("Invalid mutation bridge payload")
        finalize = mutation_waiters.pop(payload["stateKey"], None)
        if finalize is None:
            raise ValueError("Unknown mutation bridge state")
        if not isinstance(payload["summary"], dict):
            raise ValueError("Invalid mutation bridge summary")
        finalize(payload["summary"])
    except Exception as error:
        close(str(error))


def drive(body, continuation, allowed_provider_texts):
    state_key = "sitecmd-observer-state-" + secrets.token_hex(16)
    stop_event = "sitecmd-mutation-stop-" + secrets.token_hex(16)
    sink_report_start = len(sink_reports)
    pending = {
        "position": len(observations),
        "completed": False,
        "delaysMs": [],
        "samples": [],
        "preActionFrame": None,
        "samplingLimitReached": False,
    }
    pending_action_samples.append(pending)
    action_clock = {"startedAt": None}
    sampling_state = {
        "actionCompleted": False,
        "captureInFlight": False,
        "completionStarted": False,
    }

    def continue_with_mutation(row):
        bridge = {"stopAcknowledged": False, "summary": None}

        def finalize(transient):
            if finished:
                return
            try:
                if transient["armed"] < 1:
                    raise ValueError(
                        "Transient mutation observer did not report readiness"
                    )
                if not sink_ready_frames:
                    raise ValueError("Document-start sink monitor did not report readiness")
                action_sink_reports = sink_reports[sink_report_start:]
                transient["interpretedHtmlSinks"] = len(action_sink_reports)
                transient["htmlSinkReports"] = action_sink_reports
                transient["stateTokenSha256"] = hashlib.sha256(
                    state_key.encode()
                ).hexdigest()
                transient["stopTokenSha256"] = hashlib.sha256(
                    stop_event.encode()
                ).hexdigest()
                transient["messageHandlerSha256"] = hashlib.sha256(
                    message_handler.encode()
                ).hexdigest()
                transient["sinkMessageHandlerSha256"] = hashlib.sha256(
                    sink_message_handler.encode()
                ).hexdigest()
                transient["sinkBridgeTokenSha256"] = hashlib.sha256(
                    sink_bridge_token.encode()
                ).hexdigest()
                row["transientMutation"] = transient
                check(
                    f"transient markup frame {len(observations) - 1}",
                    all(
                        transient[key] == 0
                        for key in (
                            "interpretedElements",
                            "interpretedTextNodes",
                            "interpretedAttributes",
                            "interpretedShadowRoots",
                            "interpretedHtmlSinks",
                        )
                    )
                    and transient["providerVisibilitySamples"] >= 1
                    and transient["providerVisibleSamples"]
                    <= transient["providerVisibilitySamples"]
                    and transient["providerHiddenAfterVisibleSamples"] == 0,
                )
                if render_mode == "compare":
                    check(
                        f"pending action frames {len(observations) - 1}",
                        pending["completed"]
                        and len(pending["samples"]) >= 1
                        and not pending["samplingLimitReached"]
                        and all(
                            sample.get("accepted") is True
                            for sample in pending["samples"]
                        )
                        and not has_persistent_nonreference_map(
                            pending["samples"]
                        )
                        and not has_nonreference_sibling_paint(
                            pending["samples"]
                        ),
                    )
                continuation(row)
            except Exception as error:
                close(str(error))

        def received(transient):
            bridge["summary"] = transient
            if bridge["stopAcknowledged"]:
                finalize(transient)

        def stopped(view, task, *_args):
            if finished:
                return
            try:
                if not view.evaluate_javascript_finish(task).to_boolean():
                    raise ValueError("Transient mutation observer did not stop")
                bridge["stopAcknowledged"] = True
                if bridge["summary"] is not None:
                    finalize(bridge["summary"])
            except Exception as error:
                close(str(error))

        mutation_waiters[state_key] = received
        stop_script = (
            "(() => { document.dispatchEvent(new Event("
            + json.dumps(stop_event)
            + ")); return true; })()"
        )
        webview.evaluate_javascript(
            stop_script, -1, observer_world, None, None, stopped
        )

    def armed(view, task, *_args):
        if finished:
            return
        try:
            if not view.evaluate_javascript_finish(task).to_boolean():
                raise ValueError("Mutation observer did not start")

            def start_action(frame):
                pending["preActionFrame"] = frame
                action_clock["startedAt"] = time.monotonic()
                webview.call_async_javascript_function(
                    body + "; return true;", -1, None, None, None, None,
                    completed,
                )
                schedule_pending_render(
                    pending, sampling_state, action_clock["startedAt"]
                )

            capture_marker_bound_frame(start_action)
        except Exception as error:
            close(str(error))

    def capture_completion_when_idle():
        if finished or sampling_state["completionStarted"]:
            return False
        if sampling_state["captureInFlight"]:
            GLib.timeout_add(10, capture_completion_when_idle)
            return False
        sampling_state["completionStarted"] = True

        def captured(_frame):
            pending["completed"] = True
            sample = {
                "position": len(observations),
                "delaysMs": [],
                "samples": [],
                "settleSamples": [],
                "preActionFrame": pending["preActionFrame"],
            }
            early_render_samples.append(sample)
            schedule_early_render(
                continue_with_mutation, sample, time.monotonic()
            )

        capture_transition_frame(
            pending,
            action_clock["startedAt"],
            "completion",
            captured,
        )
        return False

    def completed(view, task, *_args):
        if finished:
            return
        try:
            if not view.call_async_javascript_function_finish(task).to_boolean():
                raise ValueError("Application action did not complete")
            sampling_state["actionCompleted"] = True
            GLib.idle_add(capture_completion_when_idle)
        except Exception as error:
            close(str(error))

    interpreted_provider_texts = list(dict.fromkeys(
        decoded
        for value in allowed_provider_texts
        for decoded in (html.unescape(value),)
        if decoded != value
    ))
    arm_script = arm_mutation_observer.replace(
        "__SITECMD_MUTATION_STATE_KEY__", json.dumps(state_key)
    ).replace(
        "__SITECMD_MUTATION_STOP_EVENT__", json.dumps(stop_event)
    ).replace(
        "__SITECMD_MUTATION_MESSAGE_HANDLER__", json.dumps(message_handler)
    ).replace(
        "__SITECMD_INTERPRETED_PROVIDER_TEXTS__",
        json.dumps(interpreted_provider_texts),
    )
    webview.evaluate_javascript(arm_script, -1, observer_world, None, None, armed)


def normalized_box(value, width, height, margin=0):
    left = max(0, math.floor(value["left"]) - margin)
    top = max(0, math.floor(value["top"]) - margin)
    right = min(width, math.ceil(value["right"]) + margin)
    bottom = min(height, math.ceil(value["bottom"]) + margin)
    if right <= left or bottom <= top:
        raise ValueError("Invalid rendered crop box")
    return {"left": left, "top": top, "right": right, "bottom": bottom}


def capture_webview():
    allocation = webview.get_allocation()
    surface = webview.get_window()
    pixbuf = Gdk.pixbuf_get_from_window(
        surface, allocation.x, allocation.y, allocation.width, allocation.height
    )
    if pixbuf is None:
        raise ValueError("Could not capture the rendered webview")
    width = pixbuf.get_width()
    height = pixbuf.get_height()
    channels = pixbuf.get_n_channels()
    stride = pixbuf.get_rowstride()
    pixels = bytes(pixbuf.get_pixels())
    packed = b"".join(
        pixels[offset:offset + width * channels]
        for offset in range(0, stride * height, stride)
    )
    return width, height, channels, packed


def crop_pixels(packed, width, channels, box):
    return b"".join(
        packed[y * width * channels + box["left"] * channels:
               y * width * channels + box["right"] * channels]
        for y in range(box["top"], box["bottom"])
    )


def capture_marker_crop(packed, width, channels, box):
    pixels = crop_pixels(packed, width, channels, box)
    return {
        "box": box,
        "sha256": hashlib.sha256(pixels).hexdigest(),
        "pixelsBase64": base64.b64encode(pixels).decode("ascii"),
    }


def capture_marker_body_crop(packed, width, channels, box):
    pixels = crop_pixels(packed, width, channels, box)
    sha256 = hashlib.sha256(pixels).hexdigest()
    marker_body_pixels.setdefault(
        sha256,
        base64.b64encode(zlib.compress(pixels, level=9)).decode("ascii"),
    )
    return {
        "box": box,
        "sha256": sha256,
    }


def marker_body_crop_pixels(crop):
    try:
        sha256 = crop["sha256"]
        encoded = marker_body_pixels.get(
            sha256, expected_marker_body_pixels.get(sha256)
        )
        pixels = zlib.decompress(base64.b64decode(encoded, validate=True))
    except (KeyError, TypeError, ValueError, zlib.error) as error:
        raise ValueError("Marker body crop pixels are invalid") from error
    if hashlib.sha256(pixels).hexdigest() != sha256:
        raise ValueError("Marker body pixel digest changed")
    box = crop.get("box")
    if not isinstance(box, dict):
        raise ValueError("Marker body crop box is invalid")
    expected_length = (
        (box["right"] - box["left"])
        * (box["bottom"] - box["top"])
        * 3
    )
    if len(pixels) != expected_length:
        raise ValueError("Marker body crop pixels are invalid")
    return pixels


def marker_paint_isolation_comparison(
    frame, isolated_crops, isolated_geometries
):
    observed_crops = frame["markerBodyCrops"]
    geometries = frame["markerBodyMaskGeometry"]
    if not (
        len(observed_crops)
        == len(isolated_crops)
        == len(geometries)
        == len(isolated_geometries)
    ):
        raise ValueError("Marker paint-isolation crops are inconsistent")
    changed_pixels = 0
    material_pixels = 0
    total_difference = 0
    compared_pixels = 0
    skipped_crops = 0
    observed_asset_material_pixels = 0
    observed_asset_total_difference = 0
    isolated_asset_material_pixels = 0
    isolated_asset_total_difference = 0
    material_signature = []
    for crop_index, (
        observed, isolated, geometry, isolated_geometry
    ) in enumerate(zip(
        observed_crops,
        isolated_crops,
        geometries,
        isolated_geometries,
        strict=True,
    )):
        if isolated is None or isolated_geometry is None:
            skipped_crops += 1
            continue
        observed_pixels = marker_body_crop_pixels(observed)
        isolated_pixels = marker_body_crop_pixels(isolated)
        observed_box = observed["box"]
        isolated_box = isolated["box"]
        observed_width = observed_box["right"] - observed_box["left"]
        observed_height = observed_box["bottom"] - observed_box["top"]
        isolated_width = isolated_box["right"] - isolated_box["left"]
        isolated_height = isolated_box["bottom"] - isolated_box["top"]
        sampled_pairs = set()
        for source_y in range(41):
            for source_x in range(25):
                if not marker_opaque_mask[source_y * 25 + source_x]:
                    continue
                observed_x = math.floor(
                    geometry["left"]
                    + (source_x + 0.5) * geometry["width"] / 25
                )
                observed_y = math.floor(
                    geometry["top"]
                    + (source_y + 0.5) * geometry["height"] / 41
                )
                isolated_x = math.floor(
                    isolated_geometry["left"]
                    + (source_x + 0.5)
                    * isolated_geometry["width"] / 25
                )
                isolated_y = math.floor(
                    isolated_geometry["top"]
                    + (source_y + 0.5)
                    * isolated_geometry["height"] / 41
                )
                if not (
                    0 <= observed_x < observed_width
                    and 0 <= observed_y < observed_height
                    and 0 <= isolated_x < isolated_width
                    and 0 <= isolated_y < isolated_height
                ):
                    continue
                pair = (observed_x, observed_y, isolated_x, isolated_y)
                if pair in sampled_pairs:
                    continue
                sampled_pairs.add(pair)
                observed_offset = (
                    observed_y * observed_width + observed_x
                ) * 3
                isolated_offset = (
                    isolated_y * isolated_width + isolated_x
                ) * 3
                differences = [
                    abs(observed_pixels[observed_offset + channel]
                        - isolated_pixels[isolated_offset + channel])
                    for channel in range(3)
                ]
                compared_pixels += 1
                if max(differences) > 0:
                    changed_pixels += 1
                if max(differences) >= fixture["markerMaterialDeltaThreshold"]:
                    material_pixels += 1
                    material_signature.append([
                        crop_index, source_x, source_y
                    ])
                total_difference += sum(differences)
                expected_offset = (source_y * 25 + source_x) * 3
                observed_asset_differences = [
                    abs(observed_pixels[observed_offset + channel]
                        - marker_asset_rgb[expected_offset + channel])
                    for channel in range(3)
                ]
                isolated_asset_differences = [
                    abs(isolated_pixels[isolated_offset + channel]
                        - marker_asset_rgb[expected_offset + channel])
                    for channel in range(3)
                ]
                if max(observed_asset_differences) >= fixture[
                    "markerMaterialDeltaThreshold"
                ]:
                    observed_asset_material_pixels += 1
                if max(isolated_asset_differences) >= fixture[
                    "markerMaterialDeltaThreshold"
                ]:
                    isolated_asset_material_pixels += 1
                observed_asset_total_difference += sum(
                    observed_asset_differences
                )
                isolated_asset_total_difference += sum(
                    isolated_asset_differences
                )
    required = compared_pixels > 0
    accepted = not required or (
        material_pixels <= fixture["markerMaterialPixelLimit"]
        and total_difference <= fixture["markerTotalDifferenceLimit"]
    )
    return {
        "cropCount": len(observed_crops),
        "skippedCropCount": skipped_crops,
        "comparedOpaquePixelCount": compared_pixels,
        "changedPixelCount": changed_pixels,
        "materialPixelCount": material_pixels,
        "totalAbsoluteDifference": total_difference,
        "materialDifferenceSignatureSha256": (
            hashlib.sha256(json.dumps(
                material_signature,
                separators=(",", ":"),
            ).encode()).hexdigest()
            if material_signature else None
        ),
        "observedAssetMaterialPixelCount": observed_asset_material_pixels,
        "observedAssetTotalAbsoluteDifference": (
            observed_asset_total_difference
        ),
        "isolatedAssetMaterialPixelCount": isolated_asset_material_pixels,
        "isolatedAssetTotalAbsoluteDifference": (
            isolated_asset_total_difference
        ),
        "materialDeltaThreshold": fixture["markerMaterialDeltaThreshold"],
        "materialPixelLimit": fixture["markerMaterialPixelLimit"],
        "totalDifferenceLimit": fixture["markerTotalDifferenceLimit"],
        "required": required,
        "accepted": accepted,
    }


def settle_render(
    continuation, transition_record, started_at,
    previous_hash, stable_count, attempt, history
):
    if finished:
        return False

    def captured(frame):
        try:
            frame["elapsedMs"] = int((time.monotonic() - started_at) * 1000)
            frame["phase"] = "settle"
            if render_mode == "compare":
                compare_transition_frame(
                    frame,
                    transition_record["position"],
                    transition_record["preActionFrame"],
                )
            transition_record["settleSamples"].append(frame)
            map_hash = frame["mapSha256"]
            next_count = stable_count + 1 if map_hash == previous_hash else 1
            next_attempt = attempt + 1
            next_history = history + [map_hash]
            if next_count >= 3:
                render_settles.append({
                    "attempts": next_attempt,
                    "consecutiveFrames": next_count,
                    "mapSha256": map_hash,
                    "mapBox": frame["mapBox"],
                    "sampleHashes": next_history,
                })
                GLib.idle_add(observe, continuation)
            elif next_attempt >= 12:
                close("Native map did not settle: " + json.dumps(next_history))
            else:
                GLib.timeout_add(
                    250,
                    settle_render,
                    continuation,
                    transition_record,
                    started_at,
                    map_hash,
                    next_count,
                    next_attempt,
                    next_history,
                )
        except Exception as error:
            close(str(error))

    capture_marker_bound_frame(captured)
    return False


NO_MARKER_CROP = object()
NO_MARKER_CROPS = object()
NO_MARKER_VISIBILITY = object()


def capture_render_frame(
    marker_box=NO_MARKER_CROP,
    marker_boxes=NO_MARKER_CROPS,
    include_visible_marker_crops=False,
    marker_head_unobscured=NO_MARKER_VISIBILITY,
    marker_body_unobscured=NO_MARKER_VISIBILITY,
):
    width, height, channels, packed = capture_webview()
    details_box = normalized_box(fixture["detailsRenderBox"], width, height)
    map_box = normalized_box(fixture["mapRenderBox"], width, height)

    details_pixels = crop_pixels(packed, width, channels, details_box)
    map_pixels = crop_pixels(packed, width, channels, map_box)
    map_histogram = [0] * 64
    map_sample_count = 0
    for phase in range(8):
        linear_phase = (fixture["mapSampleOffset"] + phase) % 8
        for offset in range(
            linear_phase * channels,
            len(map_pixels) - channels + 1,
            channels * 8,
        ):
            red, green, blue = map_pixels[offset:offset + 3]
            bucket = (red >> 6) * 16 + (green >> 6) * 4 + (blue >> 6)
            map_histogram[bucket] += 1
            map_sample_count += 1

    map_grid_sums = [[0, 0, 0, 0] for _ in range(64)]
    map_width = map_box["right"] - map_box["left"]
    map_height = map_box["bottom"] - map_box["top"]
    for y in range(fixture["mapGridPhaseY"], map_height, 8):
        grid_y = min(7, y * 8 // map_height)
        for x in range(fixture["mapGridPhaseX"], map_width, 8):
            grid_x = min(7, x * 8 // map_width)
            offset = (y * map_width + x) * channels
            red, green, blue = map_pixels[offset:offset + 3]
            cell = map_grid_sums[grid_y * 8 + grid_x]
            cell[0] += red
            cell[1] += green
            cell[2] += blue
            cell[3] += 1
    map_spatial_grid = bytes(
        (cell[channel] + cell[3] // 2) // cell[3]
        for cell in map_grid_sums
        for channel in range(3)
    )
    frame = {
        "width": width,
        "height": height,
        "channels": channels,
        "sha256": hashlib.sha256(packed).hexdigest(),
        "detailsBox": details_box,
        "detailsPixelsSha256": hashlib.sha256(details_pixels).hexdigest(),
        "mapBox": map_box,
        "mapSha256": hashlib.sha256(map_pixels).hexdigest(),
        "mapVisual": {
            "histogram": map_histogram,
            "sampleCount": map_sample_count,
            "occupiedBuckets": sum(count > 0 for count in map_histogram),
            "dominantFraction": max(map_histogram) / map_sample_count,
            "spatialGridBase64": base64.b64encode(map_spatial_grid).decode("ascii"),
        },
    }
    if marker_box is not NO_MARKER_CROP:
        if marker_box is None:
            frame["activeMarkerCrop"] = None
        else:
            active_marker_box = normalized_box(marker_box, width, height)
            if (
                active_marker_box["left"] < map_box["left"]
                or active_marker_box["top"] < map_box["top"]
                or active_marker_box["right"] > map_box["right"]
                or active_marker_box["bottom"] > map_box["bottom"]
            ):
                raise ValueError("Active marker crop is outside the map")
            frame["activeMarkerCrop"] = capture_marker_crop(
                packed, width, channels, active_marker_box
            )
    if marker_boxes is not NO_MARKER_CROPS:
        if not isinstance(marker_boxes, list):
            raise ValueError("Visible marker crop boxes are invalid")
        marker_box_observations = []
        for value in marker_boxes:
            if (
                not isinstance(value, dict)
                or set(value) != {"left", "top", "right", "bottom"}
                or any(
                    isinstance(coordinate, bool)
                    or not isinstance(coordinate, (int, float))
                    or not math.isfinite(coordinate)
                    for coordinate in value.values()
                )
                or value["right"] <= value["left"]
                or value["bottom"] <= value["top"]
            ):
                raise ValueError("Visible marker crop box is invalid")
            marker_box_observations.append({
                key: value[key]
                for key in ("left", "top", "right", "bottom")
            })
        marker_box_observations.sort(
            key=lambda box: (
                box["top"], box["left"], box["bottom"], box["right"]
            )
        )
        frame["markerBoxObservations"] = marker_box_observations
        marker_body_boxes = []
        marker_body_mask_geometry = []
        marker_head_boxes = []
        visible_marker_boxes = []
        for value in marker_box_observations:
            marker_crop_box = normalized_box(value, width, height)
            clipped_box = {
                "left": max(marker_crop_box["left"], map_box["left"]),
                "top": max(marker_crop_box["top"], map_box["top"]),
                "right": min(marker_crop_box["right"], map_box["right"]),
                "bottom": min(marker_crop_box["bottom"], map_box["bottom"]),
            }
            if (
                clipped_box["right"] <= clipped_box["left"]
                or clipped_box["bottom"] <= clipped_box["top"]
            ):
                raise ValueError("Visible marker crop does not intersect the map")
            visible_marker_boxes.append(clipped_box)
            hit_x = math.floor(
                value["left"]
                + (value["right"] - value["left"]) / 2
                + fixture["markerHitOffsetX"]
            )
            hit_y = math.floor(value["top"] + fixture["markerHitOffsetY"])
            head_box = {
                "left": hit_x - 1,
                "top": hit_y - 1,
                "right": hit_x + 2,
                "bottom": hit_y + 2,
            }
            if (
                head_box["left"] >= map_box["left"]
                and head_box["top"] >= map_box["top"]
                and head_box["right"] <= map_box["right"]
                and head_box["bottom"] <= map_box["bottom"]
            ):
                marker_width = value["right"] - value["left"]
                marker_height = value["bottom"] - value["top"]
                if (
                    abs(marker_width - 25) > 0.01
                    or abs(marker_height - 41) > 0.01
                ):
                    raise ValueError("Marker body dimensions changed")
                marker_body_boxes.append(clipped_box)
                marker_body_mask_geometry.append({
                    "left": value["left"] - clipped_box["left"],
                    "top": value["top"] - clipped_box["top"],
                    "width": marker_width,
                    "height": marker_height,
                })
                marker_head_boxes.append(head_box)
        frame["markerBodyCrops"] = [
            capture_marker_body_crop(packed, width, channels, box)
            for box in marker_body_boxes
        ]
        frame["markerBodyMaskGeometry"] = marker_body_mask_geometry
        frame["markerHeadCrops"] = [
            capture_marker_crop(packed, width, channels, box)
            for box in marker_head_boxes
        ]
        if marker_head_unobscured is not NO_MARKER_VISIBILITY:
            if (
                not isinstance(marker_head_unobscured, list)
                or len(marker_head_unobscured) != len(marker_head_boxes)
                or any(not isinstance(value, bool) for value in marker_head_unobscured)
            ):
                raise ValueError("Marker paint-stack observations are invalid")
            frame["markerHeadUnobscured"] = marker_head_unobscured
        if marker_body_unobscured is not NO_MARKER_VISIBILITY:
            if (
                not isinstance(marker_body_unobscured, list)
                or len(marker_body_unobscured) != len(marker_body_boxes)
                or any(not isinstance(value, bool) for value in marker_body_unobscured)
            ):
                raise ValueError("Marker body paint-stack observations are invalid")
            frame["markerBodyUnobscured"] = marker_body_unobscured
        if include_visible_marker_crops:
            visible_marker_boxes.sort(
                key=lambda box: (
                    box["top"], box["left"], box["bottom"], box["right"]
                )
            )
            frame["visibleMarkerCrops"] = [
                capture_marker_crop(packed, width, channels, box)
                for box in visible_marker_boxes
            ]
    return frame


def capture_isolated_marker_crops(
    packed, width, height, channels, marker_boxes
):
    crops = []
    geometries = []
    for value in marker_boxes:
        if (
            not isinstance(value, dict)
            or set(value) != {"left", "top", "right", "bottom"}
            or any(
                isinstance(coordinate, bool)
                or not isinstance(coordinate, (int, float))
                or not math.isfinite(coordinate)
                for coordinate in value.values()
            )
        ):
            raise ValueError("Isolated marker box is invalid")
        if (
            value["right"] <= value["left"]
            or value["bottom"] <= value["top"]
            or value["right"] <= 0
            or value["bottom"] <= 0
            or value["left"] >= width
            or value["top"] >= height
        ):
            crops.append(None)
            geometries.append(None)
            continue
        marker_width = value["right"] - value["left"]
        marker_height = value["bottom"] - value["top"]
        if (
            abs(marker_width - 25) > 0.01
            or abs(marker_height - 41) > 0.01
        ):
            raise ValueError("Isolated marker body dimensions changed")
        crop_box = normalized_box(value, width, height)
        crops.append(capture_marker_body_crop(
            packed, width, channels, crop_box
        ))
        geometries.append({
            "left": value["left"] - crop_box["left"],
            "top": value["top"] - crop_box["top"],
            "width": marker_width,
            "height": marker_height,
        })
    return crops, geometries


marker_box_observer = """
(() => {
  const map = __SITECMD_MAP_RENDER_BOX__;
  const hitOffset = {
    x: __SITECMD_MARKER_HIT_X__,
    y: __SITECMD_MARKER_HIT_Y__,
  };
  const allElements = [];
  const roots = [document];
  while (roots.length > 0) {
    const root = roots.pop();
    for (const element of root.querySelectorAll('*')) {
      allElements.push(element);
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
  }
  const generatedContentSelectors = [];
  const splitSelectorList = selectorText => {
    const selectors = [];
    let start = 0;
    let quote = null;
    let escaped = false;
    let brackets = 0;
    let parentheses = 0;
    for (let index = 0; index < selectorText.length; index += 1) {
      const character = selectorText[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\\\') {
        escaped = true;
        continue;
      }
      if (quote) {
        if (character === quote) quote = null;
        continue;
      }
      if (character === '\"' || character === "'") {
        quote = character;
      } else if (character === '[') {
        brackets += 1;
      } else if (character === ']') {
        brackets = Math.max(0, brackets - 1);
      } else if (character === '(') {
        parentheses += 1;
      } else if (character === ')') {
        parentheses = Math.max(0, parentheses - 1);
      } else if (character === ',' && brackets === 0 && parentheses === 0) {
        selectors.push(selectorText.slice(start, index));
        start = index + 1;
      }
    }
    selectors.push(selectorText.slice(start));
    return selectors;
  };
  const generatedContentOwner = selector => {
    let quote = null;
    let escaped = false;
    let brackets = 0;
    let parentheses = 0;
    for (let index = 0; index < selector.length; index += 1) {
      const character = selector[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\\\') {
        escaped = true;
        continue;
      }
      if (quote) {
        if (character === quote) quote = null;
        continue;
      }
      if (character === '\"' || character === "'") {
        quote = character;
      } else if (character === '[') {
        brackets += 1;
      } else if (character === ']') {
        brackets = Math.max(0, brackets - 1);
      } else if (character === '(') {
        parentheses += 1;
      } else if (character === ')') {
        parentheses = Math.max(0, parentheses - 1);
      } else if (brackets === 0 && parentheses === 0) {
        const pseudo = selector.slice(index).match(/^:{1,2}(?:before|after)\\b/);
        if (pseudo) return selector.slice(0, index).trim();
      }
    }
    return null;
  };
  const nestedRulesApply = rule => {
    if (typeof CSSMediaRule !== 'undefined' && rule instanceof CSSMediaRule) {
      return matchMedia(rule.conditionText).matches;
    }
    if (typeof CSSSupportsRule !== 'undefined' && rule instanceof CSSSupportsRule) {
      return CSS.supports(rule.conditionText);
    }
    return true;
  };
  const collectGeneratedContentSelectors = rules => {
    for (const rule of rules) {
      if (typeof rule.selectorText === 'string' && rule.style) {
        const content = rule.style.getPropertyValue('content').trim();
        if (content && !['none', 'normal'].includes(content)) {
          for (const selector of splitSelectorList(rule.selectorText)) {
            const owner = generatedContentOwner(selector.trim());
            if (owner) generatedContentSelectors.push(owner);
          }
        }
      }
      if (rule.cssRules && nestedRulesApply(rule)) {
        collectGeneratedContentSelectors(rule.cssRules);
      }
    }
  };
  for (const sheet of [
    ...document.styleSheets,
    ...(document.adoptedStyleSheets ?? []),
  ]) {
    try {
      collectGeneratedContentSelectors(sheet.cssRules);
    } catch {}
  }
  for (const style of document.querySelectorAll('style')) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(style.textContent);
      collectGeneratedContentSelectors(sheet.cssRules);
    } catch {}
  }
  const transparent = color =>
    color === 'transparent'
    || /^rgba\\([^)]*(?:,|\\/)\\s*0(?:\\.0+)?\\s*\\)$/.test(color);
  const solidPointerTransparentElements = allElements.flatMap(element => {
    const style = getComputedStyle(element);
    if (
      style.pointerEvents !== 'none'
      || style.display === 'none'
      || style.visibility !== 'visible'
      || Number(style.opacity) === 0
      || transparent(style.backgroundColor)
    ) return [];
    const box = element.getBoundingClientRect();
    return box.right > box.left && box.bottom > box.top
      ? [{ element, box }]
      : [];
  });
  const markerAncestryPaintIsExpected = marker => {
    try {
      const source = new URL(marker.currentSrc, document.baseURI);
      if (!source.pathname.endsWith('/marker-icon.png')) return false;
    } catch {
      return false;
    }
    for (let owner = marker; owner && owner.id !== 'map'; owner = owner.parentElement) {
      if (generatedContentSelectors.some(selector => {
        try {
          return owner.matches(selector);
        } catch {
          return false;
        }
      })) return false;
      const style = getComputedStyle(owner);
      if (
        style.display === 'none'
        || style.visibility !== 'visible'
        || Number(style.opacity) !== 1
        || !['none', 'opacity(1)'].includes(style.filter)
        || !['none', ''].includes(style.clipPath ?? '')
        || !['none', ''].includes(style.webkitClipPath ?? '')
        || !['none', ''].includes(style.webkitMaskImage ?? '')
        || style.boxShadow !== 'none'
        || style.textShadow !== 'none'
        || style.backgroundImage !== 'none'
        || !transparent(style.backgroundColor)
        || style.mixBlendMode !== 'normal'
      ) return false;
    }
    return true;
  };
  const intersection = (left, right) => {
    const overlap = {
      left: Math.max(left.left, right.left),
      top: Math.max(left.top, right.top),
      right: Math.min(left.right, right.right),
      bottom: Math.min(left.bottom, right.bottom),
    };
    return overlap.right > overlap.left && overlap.bottom > overlap.top
      ? overlap
      : null;
  };
  const markerPointsUnobscured = (marker, points, markerBox = null) => {
    if (!markerAncestryPaintIsExpected(marker)) return false;
    if (!points.every(({ x, y }) => {
      const top = document.elementsFromPoint(x, y)[0];
      return top === marker || marker.contains(top);
    })) return false;
    for (const { element, box } of solidPointerTransparentElements) {
      if (
        element === marker
        || element.contains(marker)
        || marker.contains(element)
      ) continue;
      const overlap = markerBox ? intersection(box, markerBox) : null;
      const covered = overlap
        ? [
            { x: (overlap.left + overlap.right) / 2,
              y: (overlap.top + overlap.bottom) / 2 },
            { x: overlap.left + 0.25, y: overlap.top + 0.25 },
            { x: overlap.right - 0.25, y: overlap.bottom - 0.25 },
          ]
        : points.filter(({ x, y }) =>
            x >= box.left && x < box.right && y >= box.top && y < box.bottom
          );
      if (covered.length === 0) continue;
      const inlineValue = element.style.getPropertyValue('pointer-events');
      const inlinePriority = element.style.getPropertyPriority('pointer-events');
      let obscures = false;
      try {
        element.style.setProperty('pointer-events', 'auto', 'important');
        obscures = covered.some(({ x, y }) => {
          const pointerTop = document.elementsFromPoint(x, y)[0];
          return pointerTop === element || element.contains(pointerTop);
        });
      } finally {
        if (inlineValue) {
          element.style.setProperty(
            'pointer-events', inlineValue, inlinePriority
          );
        } else {
          element.style.removeProperty('pointer-events');
        }
      }
      if (obscures) return false;
    }
    return true;
  };
  const markerHeadUnobscured = (marker, x, y) =>
    markerPointsUnobscured(marker, [{ x, y }]);
  const modulo = (value, divisor) => ((value % divisor) + divisor) % divisor;
  const markerBodyUnobscured = (marker, box) => {
    const left = Math.max(box.left, map.left);
    const top = Math.max(box.top, map.top);
    const right = Math.min(box.right, map.right);
    const bottom = Math.min(box.bottom, map.bottom);
    const points = [];
    for (
      let y = top + 0.5 + modulo(hitOffset.y, 5);
      y + 1 <= bottom;
      y += 5
    ) {
      for (
        let x = left + 0.5 + modulo(hitOffset.x, 5);
        x + 1 <= right;
        x += 5
      ) {
        points.push({ x, y });
      }
    }
    return points.length > 0 && markerPointsUnobscured(marker, points, {
      left,
      top,
      right,
      bottom,
    });
  };
  const markers = [...document.querySelectorAll('img.leaflet-marker-icon')]
    .map(image => ({ image, box: image.getBoundingClientRect() }))
    .filter(({ box }) =>
      box.right > map.left && box.left < map.right
      && box.bottom > map.top && box.top < map.bottom
    )
    .sort((left, right) =>
      left.box.top - right.box.top
      || left.box.left - right.box.left
      || left.box.bottom - right.box.bottom
      || left.box.right - right.box.right
    );
  const markerBoxes = markers.map(({ box }) => ({
    left: box.left,
    top: box.top,
    right: box.right,
    bottom: box.bottom,
  }));
  const headMarkers = markers.filter(({ box }) => {
    const x = Math.floor(box.left + box.width / 2 + hitOffset.x);
    const y = Math.floor(box.top + hitOffset.y);
    return x - 1 >= map.left && x + 2 <= map.right
      && y - 1 >= map.top && y + 2 <= map.bottom;
  });
  const elementCanCoverMarker = (element, box) => {
    const overlaps = markers.flatMap(({ box: markerBox }) => {
      const overlap = intersection(box, markerBox);
      return overlap ? [overlap] : [];
    });
    if (overlaps.length === 0) return false;
    const inlineValue = element.style.getPropertyValue('pointer-events');
    const inlinePriority = element.style.getPropertyPriority('pointer-events');
    try {
      element.style.setProperty('pointer-events', 'auto', 'important');
      return overlaps.some(overlap => [
        { x: (overlap.left + overlap.right) / 2,
          y: (overlap.top + overlap.bottom) / 2 },
        { x: overlap.left + 0.25, y: overlap.top + 0.25 },
        { x: overlap.right - 0.25, y: overlap.bottom - 0.25 },
      ].some(({ x, y }) => {
        const top = document.elementsFromPoint(x, y)[0];
        return top === element || element.contains(top);
      }));
    } finally {
      if (inlineValue) {
        element.style.setProperty(
          'pointer-events', inlineValue, inlinePriority
        );
      } else {
        element.style.removeProperty('pointer-events');
      }
    }
  };
  const paintIsolationElements = allElements.filter(element => {
    const style = getComputedStyle(element);
    const box = element.getBoundingClientRect();
    const hasGeneratedPaint = generatedContentSelectors.some(selector => {
      try {
        return element.matches(selector);
      } catch {
        return false;
      }
    });
    const needsRenderedPaintCheck = style.pointerEvents === 'none'
      || style.boxShadow !== 'none'
      || style.outlineStyle !== 'none'
      || hasGeneratedPaint;
    return style.display !== 'none'
      && style.visibility === 'visible'
      && Number(style.opacity) !== 0
      && needsRenderedPaintCheck
      && !markers.some(({ image }) =>
        element === image
        || element.contains(image)
        || image.contains(element)
      )
      && elementCanCoverMarker(element, box);
  });
  const hiddenRouteCount = [
    ...document.querySelectorAll('#map path.leaflet-interactive'),
  ].filter(route => {
    for (let element = route; element; element = element.parentElement) {
      const style = getComputedStyle(element);
      if (
        style.display === 'none'
        || style.visibility !== 'visible'
        || Number(style.opacity) === 0
      ) return true;
      if (element.id === 'map') break;
    }
    return false;
  }).length;
  globalThis[__SITECMD_PAINT_ISOLATION_STATE__] = {
    elements: paintIsolationElements,
    markers: headMarkers.map(({ image }) => image),
    records: [],
    hidden: false,
  };
  return JSON.stringify({
    markerBoxes,
    markerHeadUnobscured: headMarkers.map(({ image, box }) =>
      markerHeadUnobscured(
        image,
        box.left + box.width / 2 + hitOffset.x,
        box.top + hitOffset.y,
      )
    ),
    markerBodyUnobscured: headMarkers.map(({ image, box }) =>
      markerBodyUnobscured(image, box)
    ),
    hiddenRouteCount,
    paintIsolationElementCount: paintIsolationElements.length,
  });
})()
"""


def capture_marker_bound_frame(
    continuation,
    marker_box=NO_MARKER_CROP,
    include_visible_marker_crops=False,
):
    def completed(view, task, *_args):
        if finished:
            return
        try:
            observation = json.loads(
                view.evaluate_javascript_finish(task).to_string()
            )
            if not isinstance(observation, dict) or set(observation) != {
                "markerBoxes", "markerHeadUnobscured", "markerBodyUnobscured",
                "hiddenRouteCount", "paintIsolationElementCount",
            }:
                raise ValueError("Marker-bound observation is invalid")
            if (
                isinstance(observation["paintIsolationElementCount"], bool)
                or not isinstance(observation["paintIsolationElementCount"], int)
                or observation["paintIsolationElementCount"] < 0
            ):
                raise ValueError("Marker paint-isolation inventory is invalid")
            if (
                isinstance(observation["hiddenRouteCount"], bool)
                or not isinstance(observation["hiddenRouteCount"], int)
                or observation["hiddenRouteCount"] < 0
            ):
                raise ValueError("Route visibility inventory is invalid")
            frame = capture_render_frame(
                marker_box,
                observation["markerBoxes"],
                include_visible_marker_crops,
                observation["markerHeadUnobscured"],
                observation["markerBodyUnobscured"],
            )
            frame["paintIsolationElementCount"] = observation[
                "paintIsolationElementCount"
            ]
            frame["hiddenRouteCount"] = observation["hiddenRouteCount"]
            if (
                not frame["markerBodyCrops"]
                or observation["paintIsolationElementCount"] == 0
            ):
                isolated_crops = list(frame["markerBodyCrops"])
                frame["markerBodyWithoutSiblingPaintCrops"] = isolated_crops
                frame["markerBodyWithoutSiblingPaintGeometry"] = list(
                    frame["markerBodyMaskGeometry"]
                )
                frame["markerGeometryStable"] = True
                frame["markerSiblingPaintComparison"] = (
                    marker_paint_isolation_comparison(
                        frame,
                        isolated_crops,
                        frame["markerBodyMaskGeometry"],
                    )
                )
                continuation(frame)
                return

            def restored(restored_view, restored_task, *_restored_args):
                if finished:
                    return
                try:
                    if not restored_view.evaluate_javascript_finish(
                        restored_task
                    ).to_boolean():
                        raise ValueError("Marker paint isolation did not restore")
                    continuation(frame)
                except Exception as error:
                    close(str(error))

            def isolated_measured(
                measured_view, measured_task, *_measured_args
            ):
                if finished:
                    return
                try:
                    isolated_boxes = json.loads(
                        measured_view.evaluate_javascript_finish(
                            measured_task
                        ).to_string()
                    )
                    if (
                        not isinstance(isolated_boxes, list)
                        or len(isolated_boxes) != len(frame["markerBodyCrops"])
                    ):
                        raise ValueError(
                            "Marker paint-isolation boxes are invalid"
                        )
                    width, height, channels, packed = capture_webview()
                    if (
                        width != frame["width"]
                        or height != frame["height"]
                        or channels != frame["channels"]
                    ):
                        raise ValueError("Marker paint-isolation frame changed size")
                    isolated_crops, isolated_geometries = (
                        capture_isolated_marker_crops(
                            packed,
                            width,
                            height,
                            channels,
                            isolated_boxes,
                        )
                    )
                    frame["markerBodyWithoutSiblingPaintCrops"] = isolated_crops
                    frame["markerBodyWithoutSiblingPaintGeometry"] = (
                        isolated_geometries
                    )
                    frame["markerGeometryStable"] = all(
                        isolated_crop is not None
                        and observed_crop["box"] == isolated_crop["box"]
                        and observed_geometry == isolated_geometry
                        for (
                            observed_crop,
                            isolated_crop,
                            observed_geometry,
                            isolated_geometry,
                        ) in zip(
                            frame["markerBodyCrops"],
                            isolated_crops,
                            frame["markerBodyMaskGeometry"],
                            isolated_geometries,
                            strict=True,
                        )
                    )
                    frame["markerSiblingPaintComparison"] = (
                        marker_paint_isolation_comparison(
                            frame, isolated_crops, isolated_geometries
                        )
                    )
                    restore_script = """
(() => {
  const state = globalThis[__SITECMD_PAINT_ISOLATION_STATE__];
  if (!state || !state.hidden) return false;
  for (const record of [...state.records].reverse()) {
    if (record.value) {
      record.element.style.setProperty(
        'visibility', record.value, record.priority
      );
    } else {
      record.element.style.removeProperty('visibility');
    }
  }
  state.records = [];
  state.hidden = false;
  return true;
})()
""".replace(
                        "__SITECMD_PAINT_ISOLATION_STATE__",
                        json.dumps(paint_isolation_state),
                    )
                    webview.evaluate_javascript(
                        restore_script,
                        -1,
                        observer_world,
                        None,
                        None,
                        restored,
                    )
                except Exception as error:
                    close(str(error))

            def measure_isolated():
                if finished:
                    return False
                measure_script = """
(() => {
  const state = globalThis[__SITECMD_PAINT_ISOLATION_STATE__];
  if (!state || !state.hidden) return null;
  return JSON.stringify(state.markers.map(marker => {
    const box = marker.getBoundingClientRect();
    return {
      left: box.left,
      top: box.top,
      right: box.right,
      bottom: box.bottom,
    };
  }));
})()
""".replace(
                    "__SITECMD_PAINT_ISOLATION_STATE__",
                    json.dumps(paint_isolation_state),
                )
                webview.evaluate_javascript(
                    measure_script,
                    -1,
                    observer_world,
                    None,
                    None,
                    isolated_measured,
                )
                return False

            def hidden(hidden_view, hidden_task, *_hidden_args):
                if finished:
                    return
                try:
                    if not hidden_view.evaluate_javascript_finish(
                        hidden_task
                    ).to_boolean():
                        raise ValueError("Marker paint isolation did not start")
                    GLib.timeout_add(25, measure_isolated)
                except Exception as error:
                    close(str(error))

            hide_script = """
(() => {
  const state = globalThis[__SITECMD_PAINT_ISOLATION_STATE__];
  if (!state || state.hidden) return false;
  state.records = [];
  for (const element of state.elements) {
    if (!element.isConnected) continue;
    state.records.push({
      element,
      value: element.style.getPropertyValue('visibility'),
      priority: element.style.getPropertyPriority('visibility'),
    });
    element.style.setProperty('visibility', 'hidden', 'important');
  }
  state.hidden = true;
  return true;
})()
""".replace(
                "__SITECMD_PAINT_ISOLATION_STATE__",
                json.dumps(paint_isolation_state),
            )
            webview.evaluate_javascript(
                hide_script,
                -1,
                observer_world,
                None,
                None,
                hidden,
            )
        except Exception as error:
            close(str(error))

    script = marker_box_observer.replace(
        "__SITECMD_MAP_RENDER_BOX__",
        json.dumps(fixture["mapRenderBox"], separators=(",", ":")),
    ).replace(
        "__SITECMD_MARKER_HIT_X__",
        json.dumps(fixture["markerHitOffsetX"]),
    ).replace(
        "__SITECMD_MARKER_HIT_Y__",
        json.dumps(fixture["markerHitOffsetY"]),
    ).replace(
        "__SITECMD_PAINT_ISOLATION_STATE__",
        json.dumps(paint_isolation_state),
    )
    webview.evaluate_javascript(
        script,
        -1,
        observer_world,
        None,
        None,
        completed,
    )


def histogram_distance(left, right):
    if left["sampleCount"] <= 0 or right["sampleCount"] <= 0:
        raise ValueError("Map visual histogram is empty")
    return 0.5 * sum(
        abs(
            left_count / left["sampleCount"]
            - right_count / right["sampleCount"]
        )
        for left_count, right_count in zip(
            left["histogram"], right["histogram"], strict=True
        )
    )


def spatial_distance(left, right):
    try:
        left_grid = base64.b64decode(left["spatialGridBase64"], validate=True)
        right_grid = base64.b64decode(right["spatialGridBase64"], validate=True)
    except (KeyError, ValueError) as error:
        raise ValueError("Map spatial grid is invalid") from error
    if len(left_grid) != 64 * 3 or len(right_grid) != 64 * 3:
        raise ValueError("Map spatial grid is invalid")
    return sum(
        abs(left_value - right_value)
        for left_value, right_value in zip(left_grid, right_grid, strict=True)
    ) / (64 * 3 * 255)


def visual_signature_sha256(visual):
    return hashlib.sha256(
        json.dumps(
            visual, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def marker_crop_difference(observed, reference, require_box=True):
    observed_box = observed.get("box")
    reference_box = reference.get("box")
    if require_box and observed_box != reference_box:
        return None
    if (
        not isinstance(observed_box, dict)
        or not isinstance(reference_box, dict)
        or observed_box["right"] - observed_box["left"]
        != reference_box["right"] - reference_box["left"]
        or observed_box["bottom"] - observed_box["top"]
        != reference_box["bottom"] - reference_box["top"]
    ):
        return None
    try:
        def decode_pixels(crop):
            if "pixelsBase64" in crop:
                return base64.b64decode(crop["pixelsBase64"], validate=True)
            return marker_body_crop_pixels(crop)

        observed_pixels = decode_pixels(observed)
        reference_pixels = decode_pixels(reference)
    except (KeyError, TypeError, ValueError, zlib.error) as error:
        raise ValueError("Marker crop pixels are invalid") from error
    box = observed_box
    expected_length = (
        (box["right"] - box["left"])
        * (box["bottom"] - box["top"])
        * 3
    )
    if len(observed_pixels) != expected_length or len(reference_pixels) != expected_length:
        raise ValueError("Marker crop pixels are invalid")
    changed_pixels = 0
    material_pixels = 0
    total_difference = 0
    for offset in range(0, expected_length, 3):
        differences = [
            abs(observed_pixels[offset + channel] - reference_pixels[offset + channel])
            for channel in range(3)
        ]
        if max(differences) > 0:
            changed_pixels += 1
        if max(differences) >= fixture["markerMaterialDeltaThreshold"]:
            material_pixels += 1
        total_difference += sum(differences)
    return {
        "changedPixelCount": changed_pixels,
        "materialPixelCount": material_pixels,
        "totalAbsoluteDifference": total_difference,
    }


def marker_difference_score(item):
    return max(
        item["materialPixelCount"] / fixture["markerMaterialPixelLimit"],
        item["totalAbsoluteDifference"]
        / fixture["markerTotalDifferenceLimit"],
    )


def marker_head_crops_comparison(observed, references):
    candidates = []
    for index, reference in enumerate(references):
        counts_equal = (
            isinstance(reference, list)
            and len(observed) == len(reference)
        )
        distances = []
        matched_indexes = []
        if counts_equal:
            for observed_crop in observed:
                matches = [
                    (reference_index, marker_crop_difference(
                        observed_crop, reference_crop, False
                    ))
                    for reference_index, reference_crop in enumerate(reference)
                ]
                matches = [item for item in matches if item[1] is not None]
                if not matches:
                    counts_equal = False
                    distances = []
                    matched_indexes = []
                    break
                reference_index, distance = min(
                    matches,
                    key=lambda item: (
                        marker_difference_score(item[1]),
                        item[1]["materialPixelCount"],
                        item[1]["totalAbsoluteDifference"],
                        item[0],
                    ),
                )
                matched_indexes.append(reference_index)
                distances.append(distance)
        material_pixels = max(
            (item["materialPixelCount"] for item in distances), default=0
        ) if counts_equal else None
        total_difference = max(
            (item["totalAbsoluteDifference"] for item in distances), default=0
        ) if counts_equal else None
        candidates.append({
            "referenceIndex": index,
            "countsEqual": counts_equal,
            "matchedReferenceCropIndexes": matched_indexes,
            "materialPixelCount": material_pixels,
            "totalAbsoluteDifference": total_difference,
            "materialDeltaThreshold": fixture["markerMaterialDeltaThreshold"],
            "materialPixelLimit": fixture["markerMaterialPixelLimit"],
            "totalDifferenceLimit": fixture["markerTotalDifferenceLimit"],
            "accepted": (
                counts_equal
                and material_pixels <= fixture["markerMaterialPixelLimit"]
                and total_difference <= fixture["markerTotalDifferenceLimit"]
            ),
        })
    return min(
        candidates,
        key=lambda item: (
            not item["countsEqual"],
            math.inf if item["materialPixelCount"] is None else max(
                item["materialPixelCount"]
                / fixture["markerMaterialPixelLimit"],
                item["totalAbsoluteDifference"]
                / fixture["markerTotalDifferenceLimit"],
            ),
            item["referenceIndex"],
        ),
    )


def marker_body_crops_comparison(observed, references, minimum_count):
    reference_crops = [
        (frame_index, crop_index, crop)
        for frame_index, reference in enumerate(references)
        if isinstance(reference, list)
        for crop_index, crop in enumerate(reference)
    ]
    matches_complete = True
    matched_indexes = []
    distances = []
    for observed_crop in observed:
        matches = [
            (
                frame_index,
                crop_index,
                marker_crop_difference(observed_crop, reference_crop, False),
            )
            for frame_index, crop_index, reference_crop in reference_crops
        ]
        matches = [item for item in matches if item[2] is not None]
        if not matches:
            matches_complete = False
            break
        frame_index, crop_index, distance = min(
            matches,
            key=lambda item: (
                marker_difference_score(item[2]),
                item[2]["materialPixelCount"],
                item[2]["totalAbsoluteDifference"],
                item[0],
                item[1],
            ),
        )
        matched_indexes.append({
            "frameIndex": frame_index,
            "cropIndex": crop_index,
        })
        distances.append(distance)
    material_pixels = max(
        (item["materialPixelCount"] for item in distances), default=0
    ) if matches_complete else None
    total_difference = max(
        (item["totalAbsoluteDifference"] for item in distances), default=0
    ) if matches_complete else None
    count_accepted = len(observed) >= minimum_count
    return {
        "observedCount": len(observed),
        "minimumTargetCount": minimum_count,
        "countAccepted": count_accepted,
        "referenceCropCount": len(reference_crops),
        "matchesComplete": matches_complete,
        "matchedReferenceCrops": matched_indexes,
        "materialPixelCount": material_pixels,
        "totalAbsoluteDifference": total_difference,
        "materialDeltaThreshold": fixture["markerMaterialDeltaThreshold"],
        "materialPixelLimit": fixture["markerMaterialPixelLimit"],
        "totalDifferenceLimit": fixture["markerTotalDifferenceLimit"],
        "accepted": (
            count_accepted
            and matches_complete
            and material_pixels <= fixture["markerMaterialPixelLimit"]
            and total_difference <= fixture["markerTotalDifferenceLimit"]
        ),
    }


def marker_crops_comparison(observed, references):
    candidates = []
    for index, reference in enumerate(references):
        boxes_equal = (
            isinstance(reference, list)
            and len(observed) == len(reference)
            and all(
                left.get("box") == right.get("box")
                for left, right in zip(observed, reference, strict=True)
            )
        )
        distances = (
            [
                marker_crop_difference(left, right)
                for left, right in zip(observed, reference, strict=True)
            ]
            if boxes_equal
            else []
        )
        changed_pixels = max(
            (item["changedPixelCount"] for item in distances), default=0
        ) if boxes_equal else None
        material_pixels = max(
            (item["materialPixelCount"] for item in distances), default=0
        ) if boxes_equal else None
        total_difference = max(
            (item["totalAbsoluteDifference"] for item in distances), default=0
        ) if boxes_equal else None
        candidates.append({
            "referenceIndex": index,
            "boxesEqual": boxes_equal,
            "changedPixelCount": changed_pixels,
            "materialPixelCount": material_pixels,
            "totalAbsoluteDifference": total_difference,
            "materialDeltaThreshold": fixture["markerMaterialDeltaThreshold"],
            "materialPixelLimit": fixture["markerMaterialPixelLimit"],
            "totalDifferenceLimit": fixture["markerTotalDifferenceLimit"],
            "accepted": (
                boxes_equal
                and material_pixels <= fixture["markerMaterialPixelLimit"]
                and total_difference <= fixture["markerTotalDifferenceLimit"]
            ),
        })
    return min(
        candidates,
        key=lambda item: (
            not item["boxesEqual"],
            math.inf if item["materialPixelCount"] is None else max(
                item["materialPixelCount"] / fixture["markerMaterialPixelLimit"],
                item["totalAbsoluteDifference"]
                / fixture["markerTotalDifferenceLimit"],
            ),
            math.inf if item["materialPixelCount"] is None else (
                item["materialPixelCount"] / fixture["markerMaterialPixelLimit"]
            ),
            math.inf if item["totalAbsoluteDifference"] is None else (
                item["totalAbsoluteDifference"] / fixture["markerTotalDifferenceLimit"]
            ),
            item["referenceIndex"],
        ),
    )


def compare_transition_frame(frame, position, before):
    frame["targetComparison"] = render_comparison(
        frame, expected_details_frames[position], False
    )
    frame["preActionDetailsEqual"] = (
        frame["detailsBox"] == before["detailsBox"]
        and frame["detailsPixelsSha256"] == before["detailsPixelsSha256"]
    )
    frame["transitionDetailsEqual"] = any(
        frame["detailsBox"] == reference["detailsBox"]
        and frame["detailsPixelsSha256"]
        == reference["detailsPixelsSha256"]
        for reference in expected_transition_frames[position]
    )
    map_references = [
        ("pre-action", None, before["mapVisual"]),
        *[
            ("target", index, reference["mapVisual"])
            for index, reference in enumerate(expected_render_frames[position])
        ],
        *[
            ("transition", index, reference["mapVisual"])
            for index, reference in enumerate(expected_transition_frames[position])
        ],
    ]
    frame_references = [
        before,
        *expected_render_frames[position],
        *expected_transition_frames[position],
    ]
    frame["mapExactReference"] = any(
        frame["mapSha256"] == reference["mapSha256"]
        for reference in frame_references
    )
    frame["mapVisualExactReference"] = any(
        frame["mapVisual"] == reference["mapVisual"]
        for reference in frame_references
    )
    frame["routeVisibilityAccepted"] = any(
        frame["hiddenRouteCount"] == reference["hiddenRouteCount"]
        for reference in frame_references
    )
    frame["mapVisualSignatureSha256"] = visual_signature_sha256(
        frame["mapVisual"]
    )
    distances = [
        {
            "kind": kind,
            "referenceIndex": index,
            "histogramDistance": histogram_distance(frame["mapVisual"], visual),
            "spatialDistance": spatial_distance(frame["mapVisual"], visual),
        }
        for kind, index, visual in map_references
    ]
    nearest = min(
        distances,
        key=lambda item: max(
            item["histogramDistance"] / fixture["mapHistogramDistanceLimit"],
            item["spatialDistance"] / fixture["mapSpatialDistanceLimit"],
        ),
    )
    nearest["histogramLimit"] = fixture["mapHistogramDistanceLimit"]
    nearest["spatialLimit"] = fixture["mapSpatialDistanceLimit"]
    nearest["accepted"] = (
        nearest["histogramDistance"] <= nearest["histogramLimit"]
        and nearest["spatialDistance"] <= nearest["spatialLimit"]
    )
    frame["mapVisualComparison"] = nearest
    target_body_counts = [
        len(reference["markerBodyCrops"])
        for reference in expected_render_frames[position]
    ]
    exact_body_counts = [
        len(reference["markerBodyCrops"])
        for reference in frame_references
        if reference["mapSha256"] == frame["mapSha256"]
    ]
    minimum_body_count = (
        min(target_body_counts)
        if frame["phase"] in ("post-action", "settle")
        else min(exact_body_counts, default=min(target_body_counts))
    )
    frame["markerBodyCropsComparison"] = marker_body_crops_comparison(
        frame["markerBodyCrops"],
        [
            reference.get("markerBodyCrops")
            for reference in frame_references
        ],
        minimum_body_count,
    )
    frame["markerHeadCropsComparison"] = marker_head_crops_comparison(
        frame["markerHeadCrops"],
        [
            reference.get("markerHeadCrops")
            for reference in frame_references
        ],
    )
    native_marker_head_pixels_required = (
        frame["markerGeometryStable"]
        and (
            frame["phase"] in ("post-action", "settle")
            or (
                frame["phase"] == "pending"
                and frame["targetComparison"]["accepted"]
                and frame["mapExactReference"]
            )
        )
    )
    native_marker_body_pixels_required = (
        frame["markerGeometryStable"]
        and (
            frame["phase"] in ("post-action", "settle")
            or (
                frame["targetComparison"]["accepted"]
                and frame["mapExactReference"]
            )
        )
    )
    frame["markerBodyCropsComparison"]["required"] = (
        native_marker_body_pixels_required
    )
    frame["markerHeadCropsComparison"]["required"] = (
        native_marker_head_pixels_required
    )
    frame["markerSiblingPaintAccepted"] = (
        frame["markerBodyCropsComparison"]["accepted"]
        or frame["markerSiblingPaintComparison"]["accepted"]
    )
    frame["markerBodyPaintAccepted"] = all(
        frame["markerBodyUnobscured"]
    )
    frame["markerHeadPaintAccepted"] = all(
        frame["markerHeadUnobscured"]
    )
    frame["accepted"] = (
        (
            frame["preActionDetailsEqual"]
            or frame["transitionDetailsEqual"]
            or frame["targetComparison"]["accepted"]
        )
        and frame["mapVisualComparison"]["accepted"]
        and frame["routeVisibilityAccepted"]
        and frame["markerBodyPaintAccepted"]
        and frame["markerHeadPaintAccepted"]
        and (
            not frame["markerBodyCropsComparison"]["required"]
            or frame["markerBodyCropsComparison"]["accepted"]
        )
        and (
            not frame["markerHeadCropsComparison"]["required"]
            or frame["markerHeadCropsComparison"]["accepted"]
        )
    )


def compare_final_frame(frame, position):
    references = expected_render_frames[position]
    frame["targetComparison"] = render_comparison(
        frame, expected_details_frames[position], False
    )
    frame["preActionDetailsEqual"] = False
    frame["mapExactReference"] = any(
        frame["mapSha256"] == reference["mapSha256"]
        for reference in references
    )
    frame["mapVisualExactReference"] = any(
        frame["mapVisual"] == reference["mapVisual"]
        for reference in references
    )
    frame["routeVisibilityAccepted"] = any(
        frame["hiddenRouteCount"] == reference["hiddenRouteCount"]
        for reference in references
    )
    frame["mapVisualSignatureSha256"] = visual_signature_sha256(
        frame["mapVisual"]
    )
    distances = [
        {
            "kind": "target",
            "referenceIndex": index,
            "histogramDistance": histogram_distance(
                frame["mapVisual"], reference["mapVisual"]
            ),
            "spatialDistance": spatial_distance(
                frame["mapVisual"], reference["mapVisual"]
            ),
        }
        for index, reference in enumerate(references)
    ]
    nearest = min(
        distances,
        key=lambda item: max(
            item["histogramDistance"] / fixture["mapHistogramDistanceLimit"],
            item["spatialDistance"] / fixture["mapSpatialDistanceLimit"],
        ),
    )
    nearest["histogramLimit"] = fixture["mapHistogramDistanceLimit"]
    nearest["spatialLimit"] = fixture["mapSpatialDistanceLimit"]
    nearest["accepted"] = (
        nearest["histogramDistance"] <= nearest["histogramLimit"]
        and nearest["spatialDistance"] <= nearest["spatialLimit"]
    )
    frame["mapVisualComparison"] = nearest
    frame["activeMarkerCropComparison"] = marker_crops_comparison(
        [] if frame["activeMarkerCrop"] is None
        else [frame["activeMarkerCrop"]],
        [
            [] if reference.get("activeMarkerCrop") is None
            else [reference["activeMarkerCrop"]]
            for reference in references
        ],
    )
    frame["visibleMarkerCropsComparison"] = marker_crops_comparison(
        frame["visibleMarkerCrops"],
        [reference.get("visibleMarkerCrops") for reference in references],
    )
    frame["markerHeadCropsComparison"] = marker_head_crops_comparison(
        frame["markerHeadCrops"],
        [reference.get("markerHeadCrops") for reference in references],
    )
    frame["markerHeadCropsComparison"]["required"] = True
    frame["markerSiblingPaintAccepted"] = (
        frame["visibleMarkerCropsComparison"]["accepted"]
        or frame["markerSiblingPaintComparison"]["accepted"]
    )
    frame["markerBodyPaintAccepted"] = (
        all(frame["markerBodyUnobscured"])
        and frame["markerSiblingPaintAccepted"]
    )
    frame["markerHeadPaintAccepted"] = all(
        frame["markerHeadUnobscured"]
    )
    frame["accepted"] = (
        frame["targetComparison"]["accepted"]
        and frame["mapVisualComparison"]["accepted"]
        and frame["routeVisibilityAccepted"]
        and frame["activeMarkerCropComparison"]["accepted"]
        and frame["visibleMarkerCropsComparison"]["accepted"]
        and frame["markerHeadCropsComparison"]["accepted"]
        and frame["markerBodyPaintAccepted"]
        and frame["markerHeadPaintAccepted"]
    )


def has_persistent_nonreference_map(frames, required=3):
    consecutive = 0
    for frame in frames:
        comparison = frame.get("mapVisualComparison", {})
        reference_equivalent = (
            frame.get("mapVisualExactReference") is True
            or (
                isinstance(comparison.get("histogramDistance"), (int, float))
                and isinstance(comparison.get("spatialDistance"), (int, float))
                and comparison["histogramDistance"]
                <= fixture["mapPersistenceHistogramLimit"]
                and comparison["spatialDistance"]
                <= fixture["mapPersistenceSpatialLimit"]
            )
        )
        if reference_equivalent:
            consecutive = 0
            continue
        current_signature = frame.get("mapVisualSignatureSha256")
        if not isinstance(current_signature, str):
            return True
        consecutive += 1
        if consecutive >= required:
            return True
    return False


def has_nonreference_sibling_paint(frames):
    for frame in frames:
        comparison = frame.get("markerSiblingPaintComparison", {})
        signature = comparison.get("materialDifferenceSignatureSha256")
        if (
            frame.get("markerGeometryStable") is True
            and
            comparison.get("accepted") is False
            and isinstance(signature, str)
            and re.fullmatch(r"[a-f0-9]{64}", signature)
            and frame.get("markerBodyCropsComparison", {}).get("accepted")
            is False
        ):
            return True
    return False


def capture_transition_frame(record, started_at, phase, continuation):
    def captured(frame):
        try:
            frame["elapsedMs"] = int((time.monotonic() - started_at) * 1000)
            frame["phase"] = phase
            if render_mode == "compare":
                compare_transition_frame(
                    frame, record["position"], record["preActionFrame"]
                )
            record["samples"].append(frame)
            continuation(frame)
        except Exception as error:
            close(str(error))

    capture_marker_bound_frame(captured)


def schedule_pending_render(record, sampling_state, started_at):
    delay = 50 + secrets.randbelow(101)
    GLib.timeout_add(
        delay,
        capture_pending_render,
        record,
        sampling_state,
        started_at,
        delay,
    )


def capture_pending_render(record, sampling_state, started_at, delay):
    if finished or sampling_state["actionCompleted"]:
        return False
    sampling_state["captureInFlight"] = True
    record["delaysMs"].append(delay)

    def captured(_frame):
        sampling_state["captureInFlight"] = False
        if sampling_state["actionCompleted"]:
            return
        if len(record["samples"]) >= 200:
            record["samplingLimitReached"] = True
        else:
            schedule_pending_render(record, sampling_state, started_at)

    capture_transition_frame(record, started_at, "pending", captured)
    return False


def schedule_early_render(continuation, record, started_at):
    delay = 50 + secrets.randbelow(101)
    record["delaysMs"].append(delay)
    GLib.timeout_add(delay, capture_early_render, continuation, record, started_at)


def capture_early_render(continuation, record, started_at):
    if finished:
        return False

    def captured(frame):
        if len(record["samples"]) < 3 or frame["elapsedMs"] < 800:
            schedule_early_render(continuation, record, started_at)
        else:
            GLib.idle_add(
                settle_render,
                continuation,
                record,
                started_at,
                None,
                0,
                0,
                [],
            )

    capture_transition_frame(record, started_at, "post-action", captured)
    return False


def render_comparison(observed, references, require_map):
    candidates = []
    for index, reference in enumerate(references):
        exact = observed["sha256"] == reference["sha256"]
        map_equal = observed["mapBox"] == reference["mapBox"] and observed["mapSha256"] == reference["mapSha256"]
        details_equal = (
            observed["detailsBox"] == reference["detailsBox"]
            and observed["detailsPixelsSha256"] == reference["detailsPixelsSha256"]
        )
        candidates.append({"referenceIndex": index, "exactFullFrame": exact, "mapPixelsEqual": map_equal,
                           "mapPixelsRequired": require_map, "detailsPixelsEqual": details_equal})
    accepted = [item for item in candidates if item["detailsPixelsEqual"] and (not require_map or item["mapPixelsEqual"])]
    best = accepted[0] if accepted else next((item for item in candidates if item["detailsPixelsEqual"]), candidates[0])
    best["accepted"] = bool(accepted)
    return best


def observe(continuation):
    def completed(view, task, *_args):
        if finished:
            return
        try:
            row = json.loads(view.evaluate_javascript_finish(task).to_string())
            if not isinstance(row, dict):
                raise ValueError("Invalid browser observation")
            position = len(observations)

            def captured(frame):
                try:
                    observed_boxes = row.get("markerCropBoxes")
                    if not isinstance(observed_boxes, list):
                        raise ValueError("Final marker crop boxes are invalid")
                    observed_boxes = sorted(
                        observed_boxes,
                        key=lambda box: (
                            box["top"], box["left"],
                            box["bottom"], box["right"],
                        ),
                    )
                    if frame["markerBoxObservations"] != observed_boxes:
                        raise ValueError("Final marker observations changed")
                    if render_mode == "compare" and position in details_render_indexes:
                        early = early_render_samples[position]
                        check(
                            f"early details frame {position}",
                            len(early["samples"]) >= 3
                            and early["samples"][-1].get("elapsedMs", 0) >= 800
                            and len(early["settleSamples"]) >= 3
                            and all(
                                sample.get("accepted") is True
                                for sample in early["samples"] + early["settleSamples"]
                            )
                            and not has_persistent_nonreference_map(
                                early["samples"] + early["settleSamples"]
                            )
                            and not has_nonreference_sibling_paint(
                                early["samples"] + early["settleSamples"]
                            ),
                        )
                        compare_final_frame(frame, position)
                        row["renderComparison"] = frame["targetComparison"]
                        check(f"render frame {position}", frame["accepted"])
                    row["renderFrame"] = frame
                    observations.append(row)
                    continuation(row)
                except Exception as error:
                    close(str(error))

            capture_marker_bound_frame(
                captured,
                row.get("activeMarkerBox"),
                include_visible_marker_crops=True,
            )
        except Exception as error:
            close(str(error))
    route = json.dumps(expected_route, separators=(",", ":"))
    observation_script = (
        observer.replace("__SITECMD_EXPECTED_ROUTE__", route)
        .replace(
            "__SITECMD_MARKER_HIT_X__",
            json.dumps(fixture["markerHitOffsetX"]),
        )
        .replace(
            "__SITECMD_MARKER_HIT_Y__",
            json.dumps(fixture["markerHitOffsetY"]),
        )
    )
    webview.evaluate_javascript(
        observation_script,
        -1,
        observer_world,
        None,
        None,
        completed,
    )
    return False


def near(point, location):
    return isinstance(point, dict) and abs(point["lat"] - location["lat"]) < 0.0001 and abs(point["lon"] - location["lon"]) < 0.0001


def location_step(position=0):
    global expected_route
    if position == len(steps):
        return state_step("empty")
    index, action = steps[position]
    visited.add(index)
    expected_route = [fixture["samples"][item]["location"] for item in sorted(visited)]
    location = fixture["samples"][index]["location"]

    def validate(row):
        timestamp = datetime.fromisoformat(location["time"].replace("Z", "+00:00"))
        date = f"{timestamp.month}/{timestamp.day}/{timestamp.year}"
        clock = f"{timestamp.hour % 12 or 12}:{timestamp.minute:02}:{timestamp.second:02} {'AM' if timestamp.hour < 12 else 'PM'}"
        label = f"location {position} index {index}"
        check(label + " provider text", row["provider"] == location["provider"])
        check(label + " no interpreted input elements", row["interpretedElements"] == 0)
        check(label + " fields visible", all(row["visibility"].get(field) is True for field in ("provider", "battery", "deviceId", "date", "time")))
        check(label + " device fields", row["battery"] == f'{location["bat"]} %' and row["deviceId"] == fixture["deviceId"])
        check(label + " timestamp", row["date"] == date and row["time"] == clock)
        check(label + " map center", near(row["center"], location) and row["zoom"] == 16)
        points = row["markerPoints"]
        painted = row["markerPainted"]
        unobscured = row["markerUnobscured"]
        hit_in_map = row["markerHitInMap"]
        check(label + " cached markers", len(points) == len(painted) == len(visited)
              and len(unobscured) == len(visited)
              and len(hit_in_map) == len(visited)
              and all(value is True for value in painted)
              and all(
                  in_map is False or visible is True
                  for in_map, visible in zip(
                      hit_in_map, unobscured, strict=True
                  )
              )
              and any(
                  value is True and near(point, location)
                  for point, value in zip(points, unobscured, strict=True)
              )
              and all(any(near(point, fixture["samples"][item]["location"]) for point in points) for item in visited))
        distances = row["polylineMarkerDistances"]
        viewport_distances = row["markerViewportDistances"]
        route_covers_markers = len(visited) == 1 or (
            len(distances) == 1 and len(distances[0]) == len(points) == len(viewport_distances)
            and all(
                isinstance(distance, (int, float))
                and math.isfinite(distance)
                and distance <= (2 if viewport_distance == 0 else viewport_distance + 50)
                for distance, viewport_distance in zip(distances[0], viewport_distances)
            )
        )
        route_deviations = row["polylineRouteMaxDeviations"]
        expected_deviations = row["polylineExpectedRouteMaxDeviations"]
        route_matches_shape = len(visited) == 1 or (
            len(route_deviations) == 1
            and len(expected_deviations) == 1
            and isinstance(route_deviations[0], (int, float))
            and isinstance(expected_deviations[0], (int, float))
            and math.isfinite(route_deviations[0])
            and math.isfinite(expected_deviations[0])
            and route_deviations[0] <= 2
            and expected_deviations[0] <= 2
        )
        line_has_geometry = len(visited) == 1 or (len(row["polylineLengths"]) == 1 and row["polylineLengths"][0] > 1)
        line_is_painted = row["polylinePainted"] == [True]
        check(label + " connecting line", row["polylines"] == 1 and line_is_painted and line_has_geometry and route_covers_markers and route_matches_shape)
        check(label + " help link", row["help"] == {"link": "https://gitlab.com/Nulide/findmydevice/-/wikis/PushSupport", "label": "the wiki"})
        location_step(position + 1)
    drive(
        "await " + action,
        validate,
        [observations[-1]["provider"], location["provider"]],
    )


def state_step(next_mode):
    global mode
    mode = next_mode
    message = "No data available" if mode == "empty" else "Error parsing location data"

    def validate(row):
        check(mode + " visible", all(row["visibility"].get(field) is True for field in ("provider", "battery", "deviceId", "date", "time")))
        check(mode + " metadata", all(row[key] == message for key in ("provider", "date", "time")) and row["battery"] == "? %" and row["deviceId"] == fixture["deviceId"])
        if mode == "empty":
            return state_step("corrupt")
        fetched = [item["data"].get("Data") for item in requests if item["method"] == "PUT" and item["path"] == "/api/v1/location"]
        check("actual encrypted navigation requests", fetched == [str(index) for index, _ in steps] + ["3"])
        check("fixture expectations are not served", all(item["path"] != "/__qualification/select" for item in requests))
        close()
    drive(
        "await locate(-1)",
        validate,
        [observations[-1]["provider"], message],
    )


def initial_step(row):
    fields = ("provider", "battery", "deviceId", "date", "time")
    check(
        "initial fields hidden",
        all(row["visibility"].get(field) is False for field in fields),
    )
    check(
        "initial placeholders",
        row["provider"] == "Data"
        and row["battery"] == "Data"
        and row["deviceId"] == "ID"
        and row["date"] == "Date"
        and row["time"] == "Time",
    )
    check(
        "initial help link",
        row["help"]
        == {
            "link": "https://gitlab.com/Nulide/findmydevice/-/wikis/PushSupport",
            "label": "the wiki",
        },
    )
    location_step()


def loaded(view, event):
    global started
    if event != WebKit2.LoadEvent.FINISHED or started:
        return
    started = True
    bootstrap = (
        "const binary = Uint8Array.from(atob(" + json.dumps(fixture["privateKey"]) + "), c => c.charCodeAt(0));"
        "globalPrivateKey = await crypto.subtle.importKey('pkcs8', binary, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['decrypt']);"
        "globalAccessToken = " + json.dumps(fixture["token"]) + ";"
        "currentId = " + json.dumps(fixture["deviceId"]) + "; await setupPushWarning()"
    )
    drive(bootstrap, initial_step, ["Data"])


os.makedirs("/tmp/browser-runtime", mode=0o700, exist_ok=True)
os.environ["XDG_RUNTIME_DIR"] = "/tmp/browser-runtime"
subprocess.run([
    "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
    "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
    "-config", "/dev/null", "-keyout", "/tmp/browser-key.pem", "-out", "/tmp/browser-cert.pem",
], check=True, capture_output=True)
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("/tmp/browser-cert.pem", "/tmp/browser-key.pem")
server.socket = tls.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
context = WebKit2.WebContext.new_ephemeral()
context.set_preferred_languages(["en-US"])
certificate = Gio.TlsCertificate.new_from_files("/tmp/browser-cert.pem", "/tmp/browser-key.pem")
context.allow_tls_certificate_for_host(certificate, "127.0.0.1")
webview = WebKit2.WebView.new_with_context(context)
content_manager = webview.get_user_content_manager()
content_manager.connect(
    "script-message-received::" + message_handler,
    mutation_message_received,
)
content_manager.connect(
    "script-message-received::" + sink_message_handler,
    sink_message_received,
)
registered = (
    content_manager.register_script_message_handler(message_handler)
    if observer_world is None
    else content_manager.register_script_message_handler_in_world(
        message_handler, isolated_world
    )
)
if not registered:
    raise ValueError("Could not register mutation message bridge")
if not content_manager.register_script_message_handler(sink_message_handler):
    raise ValueError("Could not register sink message bridge")
content_manager.add_script(WebKit2.UserScript.new(
    sink_monitor_script,
    WebKit2.UserContentInjectedFrames.ALL_FRAMES,
    WebKit2.UserScriptInjectionTime.START,
    None,
    None,
))
webview.connect("load-changed", loaded)
window = Gtk.Window()
window.set_default_size(1280, 1600)
window.add(webview)
window.show_all()
GLib.timeout_add_seconds(55, lambda: close("Browser probe timed out") or False)
webview.load_uri(f"https://127.0.0.1:{server.server_port}/")
Gtk.main()
server.shutdown()
print("SITECMD_FMD_OBSERVATIONS " + json.dumps(result, separators=(",", ":")))
