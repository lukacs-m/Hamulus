// Classic script as well as a side-effect module: content scripts cannot import modules.
globalThis.Hamulus = (() => {
  const limits = { links: 100, images: 200, attachments: 50, url: 2048, text: 20000, excerpt: 240, excerpts: 20, nodes: 5000, findings: 200 };
  const warning = "Hamulus can produce false positives and false negatives. If you're unsure, don't interact with the email: don't click links, open attachments, reply, or enter information. Open the official website or app directly using a trusted bookmark or an address you know.";
  const labels = { safe: "No strong warning signs detected", caution: "Be careful with this email", danger: "Strong warning signs detected" };
  const text = value => String(value ?? "").replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, c => `[U+${c.charCodeAt(0).toString(16).toUpperCase()}]`);
  const heading = result => result?.status === "scanning" ? "Scanning email" : result?.status === "error" ? "Scan unavailable" : !result ? "No email scanned yet" : result.coverage?.incomplete ? `Incomplete assessment${result.level === "danger" ? " - strong warning signs detected" : ""}` : labels[result.level];
  const iconLevel = result => !result || result.status === "scanning" || result.status === "error" || result.coverage?.incomplete ? "neutral" : result.level;
  function append(parent, tag, value, className) {
    const el = parent.ownerDocument.createElement(tag);
    el.textContent = text(value);
    if (className) el.className = className;
    parent.append(el);
    return el;
  }
  function details(parent, result) {
    parent.textContent = "";
    append(parent, "p", "Heuristic assessment only. A high score is not authentication or proof that an email is safe.");
    for (const note of result.coverage?.notes || []) append(parent, "p", note, "coverage");
    if (result.error) append(parent, "p", result.error);
    const list = append(parent, "ul", "");
    for (const finding of result.findings || []) {
      const item = append(list, "li", "");
      append(item, "strong", finding.title);
      append(item, "p", finding.detail);
    }
    for (const link of result.linkEvidence || []) {
      const item = append(parent, "section", "", "evidence");
      append(item, "h3", "Flagged link");
      append(item, "p", `Displayed text: ${link.text || "(no text)"}`);
      append(item, "p", `Actual destination URL: ${link.href || "(unavailable)"}`);
      append(item, "p", `Destination hostname: ${link.hostname || "(not a web hostname)"}`);
      for (const reason of link.reasons) append(item, "p", reason);
      append(item, "p", "No link was fetched or followed. Any destination after a redirect is unknown.");
    }
    if (result.hiddenText?.chars) {
      append(parent, "h3", `${result.hiddenText.chars.toLocaleString()} hidden text characters detected`);
      append(parent, "p", "Legitimate preview text and accessibility markup can also be hidden.");
      for (const excerpt of result.hiddenText.excerpts) {
        const item = append(parent, "section", "", "evidence");
        append(item, "strong", excerpt.reason);
        append(item, "p", excerpt.text);
      }
      if (result.hiddenText.truncated) append(parent, "p", "Hidden-text excerpts are truncated. Only a bounded sample is shown.");
    }
    if (result.findingsOmitted) append(parent, "p", `${result.findingsOmitted} additional findings omitted from the summary; flagged-link evidence is shown above.`);
  }
  return { limits, warning, labels, text, heading, iconLevel, append, details };
})();
