const namedEntities = new Map([
  ["amp", "&"],
  ["gt", ">"],
  ["lt", "<"],
  ["nbsp", "\u00a0"],
  ["quot", '"'],
]);

function decodeEntities(value) {
  return String(value).replace(
    /&#([0-9]+);|&#x([a-f0-9]+);|&(amp|gt|lt|nbsp|quot);/gi,
    (_match, decimal, hexadecimal, name) => {
      if (name) return namedEntities.get(name.toLowerCase());
      const codePoint = Number.parseInt(decimal ?? hexadecimal, decimal ? 10 : 16);
      if (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) return "\ufffd";
      return String.fromCodePoint(codePoint);
    },
  );
}

function activeMarkup(value) {
  return /<(?:script|iframe|object|embed|svg|math|img)\b|\son[a-z]+\s*=|(?:javascript|vbscript)\s*:/i.test(
    value,
  );
}

function tokenizeHtml(value) {
  const html = String(value);
  const tokens = [];
  let cursor = 0;
  while (cursor < html.length) {
    let opening = html.indexOf("<", cursor);
    while (opening >= 0 && !/[a-z!/?]/i.test(html[opening + 1] ?? "")) {
      opening = html.indexOf("<", opening + 1);
    }
    if (opening < 0) {
      tokens.push({ tag: false, value: html.slice(cursor) });
      break;
    }
    if (opening > cursor) tokens.push({ tag: false, value: html.slice(cursor, opening) });
    let quote = null;
    let closing = -1;
    for (let index = opening + 1; index < html.length; index += 1) {
      const character = html[index];
      if (quote) {
        if (character === quote) quote = null;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === ">") {
        closing = index;
        break;
      }
    }
    if (closing < 0) {
      tokens.push({ tag: false, value: html.slice(opening) });
      break;
    }
    tokens.push({ tag: true, value: html.slice(opening, closing + 1) });
    cursor = closing + 1;
  }
  return tokens;
}

const blockTags = new Set([
  "article",
  "blockquote",
  "div",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "li",
  "p",
  "pre",
  "section",
  "tr",
]);

function renderedText(value) {
  const parts = [];
  for (const token of tokenizeHtml(value)) {
    if (!token.tag) {
      parts.push(decodeEntities(token.value));
      continue;
    }
    if (/^<\s*br\b[^>]*\/?>$/i.test(token.value)) {
      parts.push("\n");
      continue;
    }
    const closing = /^<\s*\/\s*([a-z0-9-]+)\s*>$/i.exec(token.value);
    if (closing && blockTags.has(closing[1].toLowerCase())) parts.push("\n");
  }
  return parts.join("");
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

class ClassList {
  constructor(element) {
    this.element = element;
    this.values = new Set();
  }

  add(...values) {
    values.forEach((value) => this.values.add(value));
  }

  remove(...values) {
    values.forEach((value) => this.values.delete(value));
  }

  contains(value) {
    return this.values.has(value);
  }

  toggle(value, force) {
    if (force === true || (force === undefined && !this.values.has(value))) this.values.add(value);
    else this.values.delete(value);
    return this.values.has(value);
  }

  toString() {
    return [...this.values].join(" ");
  }
}

export class TextNode {
  constructor(value, ownerDocument) {
    this.nodeType = 3;
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.textContent = String(value);
  }

  cloneNode() {
    return new TextNode(this.textContent, this.ownerDocument);
  }
}

function selectorMatches(element, selector) {
  const value = selector.trim();
  if (!value) return false;
  if (value.startsWith(".")) return element.classList.contains(value.slice(1));
  if (value.startsWith("#")) return element.id === value.slice(1);
  const attribute = /^\[([^=\]]+)(?:=["']?([^\]"']+)["']?)?\]$/.exec(value);
  if (attribute) {
    const observed = element.getAttribute(attribute[1]);
    return attribute[2] === undefined ? observed !== null : observed === attribute[2];
  }
  return element.tagName.toLowerCase() === value.toLowerCase();
}

export class Element {
  constructor(tagName, ownerDocument) {
    this.nodeType = 1;
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.childNodes = [];
    this.children = this.childNodes;
    this.dataset = {};
    this.style = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.classList = new ClassList(this);
    this._text = "";
    this._html = null;
    this.value = "";
    this.placeholder = "";
    this.hidden = false;
    this.disabled = false;
    this.scrollTop = 0;
    this.scrollHeight = 100;
    this.clientHeight = 100;
    this.offsetTop = 0;
  }

  set className(value) {
    this.classList.values = new Set(String(value).split(/\s+/).filter(Boolean));
  }

  get className() {
    return this.classList.toString();
  }

  set innerHTML(value) {
    const html = String(value);
    this.ownerDocument.innerHTMLWrites.push({ element: this, value: html });
    if (activeMarkup(html)) this.ownerDocument.active = true;
    this.childNodes = [];
    this.children = this.childNodes;
    this._html = html;
    this._text = renderedText(html);
  }

  get innerHTML() {
    if (this._html !== null) return this._html;
    return (
      escapeHtml(this._text) +
      this.childNodes.map((child) => escapeHtml(child.textContent ?? "")).join("")
    );
  }

  set textContent(value) {
    this.childNodes = [];
    this.children = this.childNodes;
    this._html = null;
    this._text = String(value ?? "");
  }

  get textContent() {
    return this._text + this.childNodes.map((child) => child.textContent ?? "").join("");
  }

  set innerText(value) {
    this.textContent = value;
  }

  get innerText() {
    return this.textContent;
  }

  get firstChild() {
    return this.childNodes[0] ?? null;
  }

  get lastChild() {
    return this.childNodes.at(-1) ?? null;
  }

  hasChildNodes() {
    return this.childNodes.length > 0;
  }

  appendChild(child) {
    if (child?.nodeType === 11) {
      for (const member of [...child.childNodes]) this.appendChild(member);
      child.childNodes.length = 0;
      return child;
    }
    this._html = null;
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  append(...values) {
    for (const value of values) {
      this.appendChild(
        typeof value === "string" ? this.ownerDocument.createTextNode(value) : value,
      );
    }
  }

  prepend(...values) {
    const nodes = values.map((value) =>
      typeof value === "string" ? this.ownerDocument.createTextNode(value) : value,
    );
    for (const node of nodes) node.parentNode = this;
    this.childNodes.unshift(...nodes);
  }

  replaceChildren(...values) {
    this.textContent = "";
    this.append(...values);
  }

  removeChild(child) {
    const index = this.childNodes.indexOf(child);
    if (index < 0) throw new Error("Node is not a child");
    this.childNodes.splice(index, 1);
    child.parentNode = null;
    return child;
  }

  replaceChild(next, previous) {
    const index = this.childNodes.indexOf(previous);
    if (index < 0) throw new Error("Node is not a child");
    this.childNodes[index] = next;
    next.parentNode = this;
    previous.parentNode = null;
    return previous;
  }

  remove() {
    this.parentNode?.removeChild(this);
  }

  insertAdjacentElement(position, element) {
    if (position === "afterbegin") this.prepend(element);
    else this.appendChild(element);
    return element;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === "id") this.id = String(value);
    if (name === "class") this.className = String(value);
    if (name.startsWith("data-")) {
      const key = name.slice(5).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
      this.dataset[key] = String(value);
    }
  }

  getAttribute(name) {
    if (name === "id" && this.id) return this.id;
    if (name === "class") return this.className;
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) ?? [];
    listeners.push(listener);
    this.listeners.set(name, listeners);
  }

  dispatchEvent(event) {
    event.target ??= this;
    for (const listener of this.listeners.get(event.type) ?? []) listener(event);
    return true;
  }

  click() {
    this.dispatchEvent({ type: "click", preventDefault() {} });
  }

  focus() {}
  blur() {}

  matches(selector) {
    return selectorMatches(this, selector);
  }

  querySelectorAll(selector) {
    const selectors = selector.split(",");
    const matches = [];
    function visit(node) {
      for (const child of node.childNodes ?? []) {
        if (child.nodeType === 1) {
          if (selectors.some((value) => selectorMatches(child, value))) matches.push(child);
          visit(child);
        }
      }
    }
    visit(this);
    return matches;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  cloneNode(deep = false) {
    const clone = new Element(this.tagName, this.ownerDocument);
    clone.className = this.className;
    clone.id = this.id;
    clone.dataset = { ...this.dataset };
    clone.style = { ...this.style };
    clone.attributes = new Map(this.attributes);
    clone._text = this._text;
    clone._html = this._html;
    if (deep) this.childNodes.forEach((child) => clone.appendChild(child.cloneNode(true)));
    return clone;
  }
}

export class DocumentFragment extends Element {
  constructor(ownerDocument) {
    super("#document-fragment", ownerDocument);
    this.nodeType = 11;
  }

  cloneNode(deep = false) {
    const clone = new DocumentFragment(this.ownerDocument);
    if (deep) this.childNodes.forEach((child) => clone.appendChild(child.cloneNode(true)));
    return clone;
  }
}

export class DocumentFixture {
  constructor() {
    this.active = false;
    this.innerHTMLWrites = [];
    this.ids = new Map();
    this.body = new Element("body", this);
    this.documentElement = new Element("html", this);
    this.documentElement.appendChild(this.body);
    this.listeners = new Map();
  }

  createElement(tagName) {
    return new Element(tagName, this);
  }

  createTextNode(value) {
    return new TextNode(value, this);
  }

  createDocumentFragment() {
    return new DocumentFragment(this);
  }

  register(id, element = this.createElement("div")) {
    element.id = id;
    this.ids.set(id, element);
    return element;
  }

  getElementById(id) {
    return this.ids.get(id) ?? null;
  }

  querySelector(selector) {
    if (selector.startsWith("#")) return this.getElementById(selector.slice(1));
    return this.body.querySelector(selector);
  }

  querySelectorAll(selector) {
    return this.body.querySelectorAll(selector);
  }

  importNode(node, deep) {
    return node.cloneNode(deep);
  }

  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) ?? [];
    listeners.push(listener);
    this.listeners.set(name, listeners);
  }
}

function parseIntoDocument(html) {
  const document = new DocumentFixture();
  document.body.childNodes = [];
  document.body.children = document.body.childNodes;
  const stack = [document.body];
  const excludedTags = new Set(["head", "noscript", "script", "style", "template"]);
  const excluded = [];
  const voidTags = new Set(["br", "img", "hr", "meta", "link", "input"]);
  for (const token of tokenizeHtml(html)) {
    if (!token.tag) {
      if (excluded.length === 0) {
        stack.at(-1).appendChild(document.createTextNode(decodeEntities(token.value)));
      }
      continue;
    }
    const close = /^<\s*\/\s*([a-z0-9-]+)/i.exec(token.value);
    const open = /^<\s*([a-z0-9-]+)/i.exec(token.value);
    if (excluded.length > 0) {
      if (close?.[1].toLowerCase() === excluded.at(-1)) excluded.pop();
      else if (open && excludedTags.has(open[1].toLowerCase()) && !token.value.endsWith("/>")) {
        excluded.push(open[1].toLowerCase());
      }
      continue;
    }
    if (close) {
      if (stack.length > 1) stack.pop();
      continue;
    }
    if (!open) continue;
    const tag = open[1].toLowerCase();
    if (excludedTags.has(tag)) {
      if (!token.value.endsWith("/>")) excluded.push(tag);
      continue;
    }
    const element = document.createElement(tag);
    stack.at(-1).appendChild(element);
    if (!voidTags.has(tag) && !token.value.endsWith("/>")) stack.push(element);
  }
  document.active = false;
  document.innerHTMLWrites = [];
  return document;
}

export class DOMParserFixture {
  parseFromString(value) {
    return parseIntoDocument(value);
  }
}

export function eventFixture(type, values = {}) {
  return {
    type,
    defaultPrevented: false,
    preventDefault() {
      this.defaultPrevented = true;
    },
    ...values,
  };
}

export function unsafePayload(label = "fixture") {
  return `${label}<img src=x onerror="globalThis.__active=true"><script>globalThis.__active=true</script>`;
}

export const NodeFixture = Object.freeze({ TEXT_NODE: 3, ELEMENT_NODE: 1 });
