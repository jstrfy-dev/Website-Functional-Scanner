const form = document.getElementById("scanForm");
const input = document.getElementById("url");
const button = document.getElementById("scanBtn");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
const progress = document.getElementById("progress");
let report = null;
let elapsedTimer = null;

form.addEventListener("submit", async event => {
  event.preventDefault();
  errorBox.textContent = "";
  results.hidden = true;
  button.disabled = true;
  button.textContent = "Testing…";
  progress.hidden = false;
  const started = Date.now();
  document.getElementById("elapsed").textContent = "0s elapsed";
  elapsedTimer = window.setInterval(() => {
    document.getElementById("elapsed").textContent = `${Math.floor((Date.now() - started) / 1000)}s elapsed`;
  }, 1000);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: input.value.trim(),
        pageLimit: Number(document.getElementById("pageLimit").value),
        depth: Number(document.getElementById("depth").value),
        testOrderFlow: document.getElementById("testOrderFlow").checked
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not scan this website.");
    report = data;
    render(data);
    results.hidden = false;
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    errorBox.textContent = error.message || "The scan failed.";
  } finally {
    window.clearInterval(elapsedTimer);
    progress.hidden = true;
    button.disabled = false;
    button.innerHTML = 'Full site test <span>→</span>';
  }
});

document.getElementById("rescan").addEventListener("click", () => {
  results.hidden = true;
  input.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});
document.getElementById("filter").addEventListener("change", () => renderIssues(report));
document.getElementById("interactionFilter").addEventListener("change", () => renderInteractions(report));
document.getElementById("exportJson").addEventListener("click", () => {
  if (report) download("accesscheck-report.json", JSON.stringify(report, null, 2), "application/json");
});
document.getElementById("exportHtml").addEventListener("click", () => {
  if (report) download("accesscheck-report.html", createHtmlReport(report), "text/html");
});
document.getElementById("exportPdf").addEventListener("click", () => window.print());

function render(data) {
  document.getElementById("siteTitle").textContent = data.title || "Website results";
  document.getElementById("siteUrl").textContent = `${data.url} · ${new Date(data.scannedAt).toLocaleString()}`;
  document.getElementById("score").textContent = data.summary.accessibilityScore === null
    ? "—" : `${data.summary.accessibilityScore}%`;
  document.getElementById("pageCount").textContent = data.summary.pages;
  document.getElementById("passed").textContent = data.summary.passed;
  document.getElementById("interactionSummary").textContent = `${data.summary.tested} tested · ${data.summary.elementsDetected} detected`;
  document.getElementById("total").textContent = data.summary.accessibilityIssues + data.summary.failed;
  document.getElementById("high").textContent = `${data.summary.failed} interaction issues`;
  document.getElementById("pageStatus").textContent = `${data.summary.accessibilityIssues} accessibility issues`;
  document.getElementById("incompleteBox").hidden = !data.warnings.length;
  document.getElementById("incompleteText").textContent = data.warnings.join(" · ");
  renderPages(data);
  renderIssues(data);
  renderInteractions(data);
  renderNetwork(data);
  renderOrderFlow(data);
}

function renderPages(data) {
  const container = document.getElementById("pageList");
  if (!data.pages.length) {
    container.innerHTML = '<div class="empty">No pages could be scanned.</div>';
    return;
  }
  container.innerHTML = data.pages.map(page => `
    <article class="issue">
      <div class="issue-top"><div><h4>${escapeHtml(page.title || page.url)}</h4><p>${escapeHtml(page.url)}</p></div>
      <span class="pill ${page.status === "failed" ? "serious" : "worked"}">${escapeHtml(page.status || "scanned")}</span></div>
      <p>HTTP ${escapeHtml(page.status === null ? "unknown" : page.status)} · ${page.interactiveElementsDetected || 0} interactive element(s) · ${page.accessibility?.violations.length || 0} accessibility issue(s) · ${page.accessibility?.passes || 0} automated pass(es) · ${page.brokenImages?.length || 0} broken image(s)</p>
      ${page.brokenImages?.length ? `<p>Broken images: ${page.brokenImages.map(image => `${escapeHtml(image.selector)} (${escapeHtml(image.src)})`).join(" · ")}</p>` : ""}
      <p>Keyboard check: ${page.keyboard?.tabbables ? (page.keyboard.moved ? "focus moved on Tab" : "no verified focus movement") : "no tabbable elements found"} (basic automated check only) ${page.keyboard?.error ? `· ${escapeHtml(page.keyboard.error)}` : ""}</p>
    </article>`).join("");
}

function renderIssues(data) {
  const list = document.getElementById("issueList");
  if (!data) return;
  const filter = document.getElementById("filter").value;
  const priority = { critical: 0, serious: 1, moderate: 2, minor: 3 };
  const items = data.accessibility
    .filter(issue => filter === "all" || issue.impact === filter)
    .slice()
    .sort((a, b) => (priority[a.impact] ?? 4) - (priority[b.impact] ?? 4));
  if (!items.length) {
    list.innerHTML = '<div class="empty">No accessibility issues in this category were detected.</div>';
    return;
  }
  list.innerHTML = items.map(issue => {
    const nodes = issue.nodes.map(node => `
      <div class="issue-node"><span class="selector">${escapeHtml((node.target || []).join(", ") || "Element")}</span>
      <p>${escapeHtml(node.failureSummary || node.html || "")}</p></div>`).join("");
    const help = safeWebLink(issue.helpUrl);
    return `<article class="issue"><div class="issue-top"><div><h4>${escapeHtml(issue.help || issue.id)}</h4>
      <p>${escapeHtml(issue.description || "")} · WCAG tags: ${escapeHtml(issue.criterion)}</p></div>
      <span class="pill ${escapeHtml(issue.impact)}">${escapeHtml(issue.impact)}</span></div>
      <p>Page: ${escapeHtml(issue.page)}</p>${nodes}
      ${help ? `<p><a href="${help}" target="_blank" rel="noopener noreferrer">Learn how to fix ↗</a></p>` : ""}
      <p class="suggestion"><b>Suggested fix:</b> ${escapeHtml(issue.help || "Review this element against the linked accessibility guidance.")}</p>
      </article>`;
  }).join("");
}

function renderInteractions(data) {
  const rows = document.getElementById("interactionRows");
  const empty = document.getElementById("interactionEmpty");
  if (!data) return;
  const filter = document.getElementById("interactionFilter").value;
  const items = data.interactions.filter(item => filter === "all" || item.status === filter);
  empty.hidden = items.length > 0;
  rows.innerHTML = items.map(item => `<tr>
    <td><strong>${escapeHtml(item.name)}</strong><small class="table-meta">${escapeHtml(item.type)}</small>
      <span class="selector">${escapeHtml(item.selector || "Not applicable")}</span></td>
    <td class="url-cell">${escapeHtml(item.page)}</td>
    <td>${escapeHtml(item.action)}</td>
    <td><b>Expected:</b> ${escapeHtml(item.expected)}<br><b>Actual:</b> ${escapeHtml(item.actual)}
      ${item.error ? `<p class="error-detail">${escapeHtml(item.error)}</p>` : ""}</td>
    <td><span class="pill ${interactionClass(item.status)}">${escapeHtml(item.status)}</span></td>
    <td>${item.screenshot ? `<a href="${item.screenshot}" download="interaction-failure.jpg"><img class="failure-shot" src="${item.screenshot}" alt="Screenshot of failed interaction"></a>` : "—"}</td>
    </tr>`).join("");
}

function renderNetwork(data) {
  const list = document.getElementById("networkList");
  const entries = [
    ...data.consoleErrors.map(item => ({ label: "Console error", page: item.url, message: item.message })),
    ...data.failedRequests.map(item => ({ label: "Failed request", page: item.url, message: `${item.request}: ${item.error}` })),
    ...data.blockedRequests.map(url => ({ label: "Blocked unsafe request", page: "", message: url }))
  ];
  list.innerHTML = entries.length ? entries.slice(0, 100).map(item => `
    <article class="issue"><h4>${escapeHtml(item.label)}</h4><p>${escapeHtml(item.page)}</p>
    <p>${escapeHtml(item.message)}</p></article>`).join("") :
    '<div class="empty">No browser console errors or failed/blocked requests were observed.</div>';
}

function renderOrderFlow(data) {
  const box = document.getElementById("orderBox");
  if (!data.orderFlow) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  box.innerHTML = `<b>Commerce observation only — order flow not executed</b>
    <p>${escapeHtml(data.orderFlow.message)}</p>
    <p>Discovered pages: ${data.orderFlow.candidates.length
      ? data.orderFlow.candidates.map(escapeHtml).join(" · ") : "No product/cart/checkout URL found."}</p>
    <p>${data.orderFlow.steps.map(step => `${escapeHtml(step.step)}: ${escapeHtml(step.status)}`).join(" · ")}</p>`;
}

function interactionClass(status) {
  return status === "worked" ? "worked" : (status === "failed" || status === "no-response" ? "serious" : "");
}
function safeWebLink(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" ? escapeAttr(url.toString()) : "";
  } catch { return ""; }
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[character]));
}
function escapeAttr(value) { return escapeHtml(value); }
function download(filename, content, type) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(new Blob([content], { type }));
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function createHtmlReport(data) {
  const title = escapeHtml(data.title || "Website test report");
  const reportMarkup = document.getElementById("results").cloneNode(true);
  reportMarkup.hidden = false;
  reportMarkup.querySelectorAll("button,select").forEach(element => element.remove());
  const styles = `
    body{font:14px Arial,sans-serif;color:#14231f;max-width:1100px;margin:32px auto;padding:0 20px}
    h2,h3{margin-top:24px}.issue,.stat,.note{border:1px solid #dfe7e1;border-radius:10px;padding:14px;margin:10px 0}
    .pill{float:right;padding:5px 8px;background:#edf2ed;border-radius:15px}.selector{font:12px monospace}
    .failure-shot{max-width:500px;display:block;margin-top:8px}.muted{color:#66766d}
  `;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>${title} report</title><style>${styles}</style>
    <h1>${title} — Full Site Test</h1><p>${escapeHtml(data.url)} · ${escapeHtml(data.scannedAt)}</p>
    ${reportMarkup.outerHTML}</html>`;
}
