/** Minimal DOM surface for the extension probe, not a browser conformance test. */
export function extensionHolder(state, document) {
  const children = [];
  const holder = {
    ownerDocument: document,
    children,
    childNodes: children,
    get firstChild() {
      return children[0] ?? null;
    },
    set innerHTML(value) {
      state.innerHtmlWrites.push(String(value));
      children.length = 0;
      if (!value) return;
      state.active ||= /<img\b|<script\b|\son[a-z]+\s*=/i.test(value);
      const name = /^<([a-z][a-z0-9_-]*)/i.exec(value)?.[1];
      if (name) children.push({ tagName: name });
    },
    set textContent(value) {
      children.length = 0;
      if (String(value)) children.push({ nodeType: 3, textContent: String(value) });
    },
    appendChild(element) {
      children.push(element);
      return element;
    },
    append(...elements) {
      for (const element of elements)
        holder.appendChild(
          typeof element === "string" ? { nodeType: 3, textContent: element } : element,
        );
    },
    replaceChildren(...elements) {
      children.length = 0;
      holder.append(...elements);
    },
    removeChild(element) {
      const index = children.indexOf(element);
      if (index === -1) throw new Error("The node is not a child of this holder");
      children.splice(index, 1);
      return element;
    },
  };
  Object.defineProperty(children, "item", { value: (index) => children[index] ?? null });
  return holder;
}
