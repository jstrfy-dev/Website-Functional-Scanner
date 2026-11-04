const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");
const { chromium } = require("playwright");
const axe = require("axe-core");

const MAX_PAGES = 25;
const MAX_INTERACTIONS_PER_PAGE = 60;
const MAX_DISCOVERED_INTERACTIONS_PER_PAGE = 300;
const MAX_SCREENSHOTS = 20;
const PAGE_TIMEOUT_MS = 20000;
const MAX_SCAN_MS = 8 * 60 * 1000;
const REPORTS_DIRECTORY = path.join(__dirname, "reports");

class ScanInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScanInputError";
  }
}

function redactUrls(value) {
  return String(value || "").replace(/https?:\/\/\S+/g, url => safeReportUrl(url));
}

function safeReportUrl(value) {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "";
  }
}

function isPrivateIPv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 2 || b === 168)) ||
    (a === 192 && b === 88 && parts[2] === 99) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && parts[2] === 100) ||
    (a === 203 && b === 0 && parts[2] === 113) ||
    (a === 168 && b === 63 && parts[2] === 129 && parts[3] === 16);
}

function expandIPv6(address) {
  let value = address.toLowerCase().split("%")[0];
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const ipv4 = value.slice(lastColon + 1).split(".").map(Number);
    if (ipv4.length !== 4) return null;
    value = `${value.slice(0, lastColon)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  const parts = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  return parts.length === 8 ? parts.map(part => parseInt(part || "0", 16)) : null;
}

function isPrivateIPv6(address) {
  const parts = expandIPv6(address);
  if (!parts) return true;
  const [first, second] = parts;
  // Only global-unicast space is accepted; deny documentation, transition and special ranges.
  return first < 0x2000 || first > 0x3fff ||
    (first === 0x2001 && (second <= 0x0002 || second === 0x0db8 || (second & 0xfff0) === 0x0010 || second === 0x0020)) ||
    first === 0x2002;
}

function normalizeUrl(raw) {
  if (typeof raw !== "string" || raw.trim().length === 0 || raw.length > 2048) {
    throw new ScanInputError("Enter a website URL or domain name (maximum 2048 characters).");
  }
  const input = raw.trim();
  const explicitProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(input);
  if (!explicitProtocol && /^[a-z][a-z\d+.-]*:(?!\d+(?:\/|$))/i.test(input)) {
    throw new ScanInputError("Only HTTP and HTTPS websites can be scanned.");
  }
  const withProtocol = explicitProtocol ? input : `https://${input}`;
  let url;
  try {
    url = new URL(withProtocol);
  } catch {
    throw new ScanInputError("Enter a valid website URL or domain name.");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new ScanInputError("Only HTTP and HTTPS websites can be scanned.");
  if (!url.hostname || url.username || url.password) throw new ScanInputError("The URL must have a public hostname and no credentials.");
  if (url.port && !["80", "443"].includes(url.port)) throw new ScanInputError("Only standard HTTP and HTTPS ports can be scanned.");
  return url.toString();
}

async function resolvePublicAddresses(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
      host.endsWith(".internal") || host === "metadata.google.internal") {
    throw new Error("For safety, local and internal hostnames cannot be scanned.");
  }
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    if (isPrivateIPv4(host)) throw new Error("Private network IP addresses cannot be scanned.");
    return [{ address: host, family: 4 }];
  }
  if (ipVersion === 6) {
    if (isPrivateIPv6(host)) throw new Error("Private or special-use IP addresses cannot be scanned.");
    return [{ address: host, family: 6 }];
  }
  let records;
  let timer;
  try {
    records = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("DNS lookup timed out.")), 5000); })
    ]);
  } catch (error) {
    if (error.message === "DNS lookup timed out.") throw error;
    throw new Error("The website hostname could not be resolved.");
  } finally {
    clearTimeout(timer);
  }
  if (!records.length || records.some(record =>
    (net.isIPv4(record.address) && isPrivateIPv4(record.address)) ||
    (net.isIPv6(record.address) && isPrivateIPv6(record.address)))) {
    throw new Error("The website resolves to a private or special-use network address and cannot be scanned.");
  }
  return records;
}

async function assertPublicHost(hostname) {
  await resolvePublicAddresses(hostname);
}

async function startPinnedProxy() {
  const server = http.createServer(async (request, response) => {
    let destination;
    try {
      destination = new URL(request.url);
      if (destination.protocol !== "http:" || destination.username || destination.password ||
          (destination.port && destination.port !== "80")) {
        throw new Error("Only standard HTTP proxy requests are permitted.");
      }
      const addresses = await resolvePublicAddresses(destination.hostname);
      const address = addresses[0];
      const headers = { ...request.headers, host: destination.host };
      delete headers["proxy-authorization"];
      delete headers["proxy-connection"];
      const upstream = http.request({
        hostname: address.address,
        family: address.family,
        port: 80,
        method: request.method,
        path: `${destination.pathname}${destination.search}`,
        headers,
        timeout: PAGE_TIMEOUT_MS
      }, upstreamResponse => {
        response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      });
      upstream.on("timeout", () => upstream.destroy(new Error("Upstream request timed out.")));
      upstream.on("error", error => {
        if (!response.headersSent) response.writeHead(502, { "content-type": "text/plain" });
        response.end(`Public target request failed: ${error.message}`);
      });
      request.pipe(upstream);
    } catch (error) {
      response.writeHead(403, { "content-type": "text/plain" });
      response.end(error.message);
    }
  });
  server.on("connect", async (request, client, head) => {
    let upstream;
    try {
      const destination = new URL(`http://${request.url}`);
      if (destination.port !== "443") throw new Error("Only HTTPS connections on port 443 are permitted.");
      const addresses = await resolvePublicAddresses(destination.hostname);
      const address = addresses[0];
      upstream = net.connect({ host: address.address, family: address.family, port: 443, timeout: PAGE_TIMEOUT_MS });
      upstream.setTimeout(PAGE_TIMEOUT_MS);
      upstream.once("connect", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length) upstream.write(head);
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on("timeout", () => upstream.destroy(new Error("Upstream connection timed out.")));
      upstream.on("error", () => {
        if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      });
      client.on("error", () => upstream.destroy());
    } catch {
      if (upstream) upstream.destroy();
      if (!client.destroyed) client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise(resolve => server.close(resolve))
  };
}

async function validateTarget(raw) {
  const normalized = normalizeUrl(raw);
  try {
    await assertPublicHost(new URL(normalized).hostname);
  } catch (error) {
    throw new ScanInputError(error.message);
  }
  return normalized;
}

function robotsAllows(pathname, rules) {
  const applicable = rules.filter(rule => pathname.startsWith(rule.path));
  if (!applicable.length) return true;
  applicable.sort((a, b) => b.path.length - a.path.length || Number(b.allow) - Number(a.allow));
  return applicable[0].allow;
}

function getWcagCriteria(tags) {
  const criteria = tags
    .filter(tag => /^wcag\d{3,4}$/.test(tag))
    .map(tag => {
      const digits = tag.slice(4);
      return `${digits[0]}.${digits[1]}.${digits.slice(2)}`;
    });
  return criteria.length ? criteria.join(", ") : "No exact success criterion tagged by axe-core";
}

function parseRobots(text) {
  const rules = [];
  let appliesToAll = false;
  let crawlDelay = 1;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim();
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key === "user-agent") appliesToAll = value === "*";
    if (!appliesToAll) continue;
    if (key === "disallow" && value) rules.push({ path: value, allow: false });
    if (key === "allow" && value) rules.push({ path: value, allow: true });
    if (key === "crawl-delay") {
      const delay = Number(value);
      if (Number.isFinite(delay) && delay >= 0) crawlDelay = Math.min(delay, 10);
    }
  }
  return { rules, delayMs: Math.max(1000, crawlDelay * 1000) };
}

function resultForStatus(status) {
  if (status === "worked") return "PASS";
  if (status === "failed") return "FAIL";
  return "NEEDS REVIEW";
}

function canonicalUrl(value) {
  try {
    const url = new URL(value);
    url.hash = "";
    return url.toString();
  } catch {
    return "";
  }
}

function buildLinkTests(links, pages) {
  const pageByUrl = new Map();
  for (const page of pages) {
    for (const value of [page.url, page.requestedUrl]) {
      const pageUrl = canonicalUrl(value);
      if (pageUrl) pageByUrl.set(pageUrl, page);
    }
  }
  const testByUrl = new Map();
  for (const link of links) {
    const url = canonicalUrl(link.url);
    if (url && link.sameHost && !testByUrl.has(url)) testByUrl.set(url, pageByUrl.get(url));
  }

  return links.map(link => {
    let result = "NEEDS REVIEW";
    let actual = "Destination was not crawled; no request was made just to test this link.";
    let error = "";
    let destination;
    if (link.kind === "limit") {
      actual = `${link.count} additional link(s) were discovered but not individually checked because the per-page link limit was reached.`;
    } else if (!link.hasDestination) {
      result = "FAIL";
      actual = "The link has an empty or missing href destination.";
      error = "Missing link destination.";
    } else if (link.kind === "unsupported") {
      result = "FAIL";
      actual = "The href does not use a supported HTTP(S) destination.";
      error = "Unsupported link destination.";
    } else if (link.kind === "fragment") {
      actual = "In-page navigation was not activated; verify the fragment target manually.";
    } else if (!link.sameHost) {
      actual = `External destination was not requested or activated${link.url ? ` (${safeReportUrl(link.url)})` : ""}.`;
    } else {
      destination = testByUrl.get(canonicalUrl(link.url));
      if (destination && Number.isInteger(destination.status)) {
        if (destination.status >= 400) {
          result = "FAIL";
          actual = `The destination ${safeReportUrl(link.url)} returned HTTP ${destination.status}.`;
          error = `HTTP ${destination.status}`;
        } else if (destination.status >= 200 && destination.status < 400) {
          result = "PASS";
          actual = `The destination ${safeReportUrl(link.url)} was crawled and returned HTTP ${destination.status}.`;
        }
      } else if (destination?.status === "skipped") {
        actual = destination.reason || actual;
      } else if (destination?.status === "redirected-out-of-scope") {
        actual = "The destination redirected outside the scanned host and was not followed.";
      }
    }

    return {
      category: "link",
      page: link.page,
      selector: link.selector,
      name: link.name,
      destination: link.url ? safeReportUrl(link.url) : "",
      type: link.kind === "external" ? "external link" : "link",
      action: "check destination without activating link",
      expected: "A non-empty link destination responds successfully on the scanned host.",
      actual,
      result,
      error,
      screenshot: result === "FAIL" ? (destination?.failureScreenshot || link.failureScreenshot || null) : null,
      screenshotPath: result === "FAIL" ? (destination?.failureScreenshotPath || link.failureScreenshotPath || null) : null
    };
  });
}

function buildFormTests(forms) {
  return forms.map(form => ({
    category: "form",
    page: form.page,
    selector: form.selector,
    name: form.name,
    type: "form",
    action: "inspect form structure (not submitted)",
    expected: "Required fields have native validation and a clear submit control.",
    actual: `${form.fieldCount} field(s), ${form.requiredFields} required, ${form.submitButtons} submit control(s). ` +
      `${form.nativeValidationEnabled ? "Native validation is enabled." : "Native validation is disabled."} ` +
      "Submission and form-interaction JavaScript errors were not tested." +
      (form.submitButtons ? "" : " No native submit control was found; custom submission behavior was not tested."),
    result: "NEEDS REVIEW",
    error: "",
    screenshot: null,
    screenshotPath: null
  }));
}

function summarizeFunctionality(tests, javascriptErrors) {
  return {
    total: tests.length,
    working: tests.filter(test => test.result === "PASS").length,
    failed: tests.filter(test => test.result === "FAIL").length,
    manualReview: tests.filter(test => test.result === "NEEDS REVIEW").length,
    brokenLinks: tests.filter(test => test.category === "link" && test.result === "FAIL").length,
    javascriptErrors
  };
}

async function captureFailureScreenshot(page, scanId, screenshots, warnings) {
  if (screenshots.length >= MAX_SCREENSHOTS) {
    if (!warnings.includes("Screenshot limit reached; some failures have no screenshot.")) {
      warnings.push("Screenshot limit reached; some failures have no screenshot.");
    }
    return { screenshot: null, screenshotPath: null };
  }
  try {
    const image = await page.screenshot({ type: "jpeg", quality: 45, timeout: 2500 });
    const filename = `${scanId}-${screenshots.length + 1}.jpg`;
    await fs.mkdir(REPORTS_DIRECTORY, { recursive: true });
    await fs.writeFile(path.join(REPORTS_DIRECTORY, filename), image);
    const screenshot = `data:image/jpeg;base64,${image.toString("base64")}`;
    screenshots.push(screenshot);
    return { screenshot, screenshotPath: `/reports/${filename}` };
  } catch (error) {
    warnings.push(`Could not capture or save a failure screenshot: ${error.message}`);
    return { screenshot: null, screenshotPath: null };
  }
}

async function inspectPage(page, url) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT_MS });
  await page.waitForTimeout(500);
  const snapshot = await page.evaluate(maxDiscoveredElements => {
    const safeImageUrl = value => {
      try {
        const url = new URL(value, location.href);
        url.search = "";
        url.hash = "";
        return url.toString();
      } catch {
        return "";
      }
    };
    const selectorFor = element => {
      if (element.id) return `#${CSS.escape(element.id)}`;
      const parts = [];
      let current = element;
      while (current && current.nodeType === Node.ELEMENT_NODE && parts.length < 5) {
        let part = current.tagName.toLowerCase();
        if (current.parentElement) {
          const siblings = Array.from(current.parentElement.children).filter(sibling => sibling.tagName === current.tagName);
          if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
        }
        parts.unshift(part);
        current = current.parentElement;
      }
      return parts.join(" > ");
    };
    const linkCount = document.querySelectorAll("a").length;
    const links = Array.from(document.querySelectorAll("a")).slice(0, 500).map(anchor => {
      const rawHref = anchor.getAttribute("href");
      let destination = null;
      try {
        if (rawHref?.trim()) destination = new URL(rawHref, location.href);
      } catch { /* Invalid destinations are reported below. */ }
      const hasDestination = Boolean(rawHref?.trim());
      const isHttp = destination && ["http:", "https:"].includes(destination.protocol);
      const pathLooksStateful = destination &&
        /(?:delete|remove|logout|log-out|purchase|payment|order|checkout|unsubscribe|cancel|signout)/i.test(
          `${destination.pathname}${destination.search}`
        );
      const sameHost = Boolean(isHttp && destination.hostname === location.hostname);
      const kind = !hasDestination ? "empty" :
        !destination || (!isHttp && !["mailto:", "tel:"].includes(destination.protocol)) ? "unsupported" :
          rawHref.startsWith("#") ? "fragment" : sameHost ? "internal" : "external";
      return {
        page: location.href,
        selector: selectorFor(anchor),
        name: (anchor.innerText || "").trim() || anchor.getAttribute("aria-label") || anchor.getAttribute("title") || "(unnamed link)",
        hasDestination,
        url: isHttp ? destination.toString() : "",
        sameHost,
        kind,
        safeToCrawl: Boolean(sameHost && !pathLooksStateful && !anchor.hasAttribute("download") && anchor.target !== "_blank")
      };
    });
    const forms = Array.from(document.forms).map(form => {
      const fields = Array.from(form.elements).filter(element =>
        element.matches("input:not([type=hidden]):not([type=submit]),select,textarea")
      );
      const requiredFields = fields.filter(element => element.required);
      const submitButtons = Array.from(form.elements).filter(element =>
        element.matches("button:not([type]),button[type=submit],input[type=submit],input[type=image]")
      );
      return {
        page: location.href,
        selector: selectorFor(form),
        name: form.getAttribute("aria-label") || form.getAttribute("name") || "Form",
        fieldCount: fields.length,
        requiredFields: requiredFields.length,
        submitButtons: submitButtons.length,
        nativeValidationEnabled: !form.noValidate
      };
    });
    const elements = Array.from(document.querySelectorAll(
      "button,input:not([type=hidden]),textarea,[role=button],[role=tab],[role=menuitem],[aria-haspopup],[aria-expanded],[aria-controls],[onclick],[tabindex]:not([tabindex='-1']),select,summary"
    )).filter(element => !(element instanceof HTMLAnchorElement)).map((element, index) => {
      const type = element.getAttribute("type") || element.tagName.toLowerCase();
      const inputButton = element.matches("input[type=button],input[type=submit]");
      const labelText = element.labels ? Array.from(element.labels).map(label => label.innerText).join(" ").trim() : "";
      const name = (element.tagName === "FORM" ? "" : element.innerText) ||
        (inputButton ? element.value : "") || labelText || element.getAttribute("aria-label") ||
        element.getAttribute("title") || (element.tagName === "FORM" ? "Form" : "");
      const form = element.form || element.closest("form");
      const style = getComputedStyle(element);
      const visible = element.getClientRects().length > 0 && style.visibility !== "hidden" && style.display !== "none";
      const defaultButtonType = element.tagName === "BUTTON" && !element.hasAttribute("type") ? "submit" : type;
      const label = `${name} ${element.getAttribute("title") || ""} ${element.getAttribute("aria-label") || ""} ${element.value || ""}`;
      const sideEffectControl =       /(?:delete|remove|log\s*out|sign\s*out|purchase|payment|buy\b|checkout|unsubscribe|cancel|submit|send\b|post\b|publish|transfer|place\s+order|confirm|save|update|create|add|edit|register|subscribe|share|invite)/i.test(label);
      let safe = true;
      let skipReason = "";
      if (!visible) {
        safe = false;
        skipReason = "Skipped because the element is not visible.";
      } else if (element.matches(":disabled,[aria-disabled='true']")) {
        safe = false;
        skipReason = "Disabled in the page; whether this is unexpected requires manual review.";
      } else if (element.matches("select,textarea,input:not([type=button])")) {
        safe = false;
        skipReason = "Skipped because changing this field could alter site state or submit data.";
      } else if (form && element.tagName !== "A") {
        safe = false;
        skipReason = "Skipped because this control is inside a form.";
      } else if (element.tagName === "BUTTON" && defaultButtonType !== "button") {
        safe = false;
        skipReason = "Skipped because this button may submit a form.";
      } else if (sideEffectControl) {
        safe = false;
        skipReason = "Skipped because the control may perform a destructive or state-changing action.";
      } else if (element.tagName === "SUMMARY") {
        safe = true;
      } else if (element.matches("[role=tab]") || element.matches("[role=menuitem]") || element.hasAttribute("aria-haspopup")) {
        safe = true;
      }
      const role = element.getAttribute("role");
      const controlledId = element.getAttribute("aria-controls");
      const controlledElement = controlledId ? document.getElementById(controlledId) : null;
      const category = element.tagName === "SUMMARY" ? "accordion" :
        role === "tab" ? "tab" :
          controlledElement?.matches("[role=dialog],dialog") ? "modal" :
            element.hasAttribute("aria-haspopup") ? "dropdown" :
              role === "menuitem" ? "menu" :
                element.hasAttribute("aria-expanded") ? "accordion" :
          element.tagName === "BUTTON" || inputButton || role === "button" ? "button" : "control";
      const expected = category === "tab" ? "The selected tab or its associated panel changes." :
        category === "dropdown" || category === "menu" ? "The menu opens or its selection state changes." :
                category === "accordion" ? "The disclosure expands or collapses." :
                  category === "modal" ? "The controlled dialog opens or closes." :
                    "The control responds without submitting data or changing protected state.";
      return {
        selector: selectorFor(element), name: name || "(unnamed)", type, category, expected,
        action: category === "accordion" ? "toggle disclosure" : "click control",
        safe, skipReason, index
      };
    });
    return {
      title: document.title,
      url: location.href,
      links,
      linkCount,
      forms,
      elements: elements.slice(0, maxDiscoveredElements),
      elementCount: elements.length,
      totalElementCount: elements.length + forms.length + linkCount,
      bodyText: (document.body?.innerText || "").slice(0, 6000),
      accessibility: {
        imagesMissingAlt: document.querySelectorAll("img:not([alt])").length,
        brokenImages: Array.from(document.images)
          .filter(image => image.complete && image.naturalWidth === 0)
          .map(image => ({ selector: selectorFor(image), src: safeImageUrl(image.currentSrc || image.src) })),
        unnamedButtons: Array.from(document.querySelectorAll("button,[role=button]")).filter(element =>
          !(element.innerText || "").trim() && !element.getAttribute("aria-label") && !element.getAttribute("aria-labelledby")
        ).length
      }
    };
  }, MAX_DISCOVERED_INTERACTIONS_PER_PAGE);

  await page.addScriptTag({ content: axe.source });
  const axeResults = await page.evaluate(async () => axe.run(document, {
    runOnly: {
      type: "tag",
      values: ["wcag22a", "wcag22aa", "wcag21a", "wcag21aa", "wcag2a", "wcag2aa", "best-practice"]
    }
  }));
  const accessibility = {
    violations: axeResults.violations.map(violation => ({
      id: violation.id,
      impact: violation.impact || "moderate",
      criterion: getWcagCriteria(violation.tags || []),
      description: violation.description,
      help: violation.help,
      helpUrl: violation.helpUrl,
      nodes: violation.nodes.slice(0, 30).map(node => ({
        html: node.html, target: node.target, failureSummary: node.failureSummary || ""
      }))
    })),
    passes: axeResults.passes.length,
    incomplete: axeResults.incomplete.map(item => ({ id: item.id, help: item.help, description: item.description }))
  };
  const keyboard = await page.evaluate(() => {
    return { tabbables: document.querySelectorAll(
      "a[href],button,input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex='-1'])"
    ).length };
  });
  let keyboardError = "";
  try {
    await page.keyboard.press("Tab");
  } catch (error) {
    keyboardError = error.message;
  }
  const keyboardAfter = await page.evaluate(() => document.activeElement !== document.body && document.activeElement !== document.documentElement);
  return { response, snapshot, accessibility, keyboard: { tabbables: keyboard.tabbables, moved: keyboardAfter, error: keyboardError } };
}

async function scanWebsite(options) {
  const target = await validateTarget(options.url);
  const pageLimit = Math.min(MAX_PAGES, Math.max(1, Number(options.pageLimit) || 10));
  const depthLimit = Math.min(5, Math.max(0, Number(options.depth) || 2));
  let browser;
  let context;
  const consoleErrors = [];
  const failedRequests = [];
  const blockedRequests = [];
  const visited = new Map();
  const interactions = [];
  const discoveredLinks = [];
  const discoveredForms = [];
  const screenshots = [];
  const scanId = crypto.randomUUID();
  const allAccessibility = [];
  const queue = [{ url: target, depth: 0 }];
  let proxy;
  let effectiveHost;
  let robots = { rules: [], delayMs: 1000 };
  let lastNavigationAt = 0;
  const warnings = [];
  const deadline = Date.now() + MAX_SCAN_MS;

  try {
    proxy = await startPinnedProxy();
    browser = await chromium.launch({ headless: true, proxy: { server: proxy.url } });
    context = await browser.newContext({
      viewport: { width: 1365, height: 900 },
      acceptDownloads: false,
      serviceWorkers: "block"
    });
    await context.route("**/*", async route => {
      const requestUrl = route.request().url();
      let parsed;
      try { parsed = new URL(requestUrl); } catch { blockedRequests.push(requestUrl); return route.abort(); }
      if (["data:", "blob:", "about:"].includes(parsed.protocol)) return route.continue();
      if (!["http:", "https:"].includes(parsed.protocol)) {
        blockedRequests.push(requestUrl);
        return route.abort();
      }
      try {
        await assertPublicHost(parsed.hostname);
        if (parsed.port && !["80", "443"].includes(parsed.port)) throw new Error("Non-standard network port blocked.");
        await route.continue();
      } catch {
        blockedRequests.push(requestUrl);
        await route.abort("blockedbyclient");
      }
    });

    const robotsPage = await context.newPage();
    const robotsUrl = new URL("/robots.txt", target).toString();
    try {
      const robotsResponse = await robotsPage.goto(robotsUrl, { waitUntil: "domcontentloaded", timeout: 8000 });
      if (robotsResponse?.ok()) robots = parseRobots(await robotsPage.locator("body").innerText({ timeout: 2000 }));
    } catch (error) {
      warnings.push(`Could not read robots.txt (${redactUrls(error.message)}); scanning with a minimum 1-second delay.`);
    }
    await robotsPage.close();

    while (queue.length && visited.size < pageLimit) {
      if (Date.now() >= deadline) {
        warnings.push("The 8-minute scan time limit was reached; remaining discovered pages were not scanned.");
        break;
      }
      const item = queue.shift();
      let pageUrl;
      try {
        pageUrl = new URL(item.url);
        pageUrl.hash = "";
        if (!["http:", "https:"].includes(pageUrl.protocol)) continue;
        await assertPublicHost(pageUrl.hostname);
      } catch {
        continue;
      }
      if (!effectiveHost) effectiveHost = pageUrl.hostname;
      if (pageUrl.hostname !== effectiveHost || visited.has(pageUrl.toString())) continue;
      if (!robotsAllows(pageUrl.pathname, robots.rules)) {
        visited.set(pageUrl.toString(), { url: pageUrl.toString(), status: "skipped", reason: "Disallowed by robots.txt." });
        continue;
      }
      const waitMs = Math.max(0, robots.delayMs - (Date.now() - lastNavigationAt));
      if (lastNavigationAt && waitMs) await new Promise(resolve => setTimeout(resolve, waitMs));
      lastNavigationAt = Date.now();

      const page = await context.newPage();
      page.setDefaultNavigationTimeout(PAGE_TIMEOUT_MS);
      let activeInteractionErrors = null;
      page.on("console", message => {
        if (message.type() === "error") consoleErrors.push({
          url: page.url(),
          message: message.text().replace(/https?:\/\/\S+/g, value => safeReportUrl(value)).slice(0, 500)
        });
        if (message.type() === "error" && activeInteractionErrors) {
          activeInteractionErrors.push(message.text().replace(/https?:\/\/\S+/g, value => safeReportUrl(value)).slice(0, 500));
        }
      });
      page.on("pageerror", error => {
        consoleErrors.push({ url: page.url(), message: redactUrls(error.message).slice(0, 500) });
        if (activeInteractionErrors) activeInteractionErrors.push(redactUrls(error.message).slice(0, 500));
      });
      page.on("requestfailed", request => failedRequests.push({
        url: page.url(), request: request.url(), error: request.failure()?.errorText || "Request failed"
      }));

      let inspected;
      let navigationError;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          inspected = await inspectPage(page, pageUrl.toString(), screenshots.length);
          const responseStatus = inspected.response?.status() || 0;
          if (responseStatus === 429 || responseStatus >= 500) {
            if (attempt > 0) throw new Error(`The server continued returning HTTP ${responseStatus} after a retry.`);
            const retryAfter = Number(await inspected.response.headerValue("retry-after"));
            await new Promise(resolve => setTimeout(resolve, Number.isFinite(retryAfter) && retryAfter > 0
              ? Math.min(retryAfter * 1000, 10000) : 1000));
            throw new Error(`The server returned HTTP ${responseStatus}; retrying once.`);
          }
          navigationError = null;
          break;
        } catch (error) {
          navigationError = error;
          if (attempt === 0) await new Promise(resolve => setTimeout(resolve, 750));
        }
      }
      if (navigationError) {
        visited.set(pageUrl.toString(), { url: pageUrl.toString(), status: "failed", error: navigationError.message });
        warnings.push(`Could not scan ${safeReportUrl(pageUrl.toString())}: ${redactUrls(navigationError.message)}`);
        await page.close();
        continue;
      }

      const finalUrl = new URL(inspected.snapshot.url);
      if (finalUrl.hostname !== effectiveHost) {
        if (visited.size === 0) {
          effectiveHost = finalUrl.hostname;
          queue.unshift({ url: finalUrl.toString(), depth: item.depth });
        }
        visited.set(pageUrl.toString(), { url: finalUrl.toString(), title: inspected.snapshot.title, status: "redirected-out-of-scope" });
        await page.close();
        continue;
      }
      const pageResult = {
        url: finalUrl.toString(),
        requestedUrl: pageUrl.toString(),
        title: inspected.snapshot.title,
        status: inspected.response?.status() ?? null,
        depth: item.depth,
        accessibility: inspected.accessibility,
        keyboard: inspected.keyboard,
        manual: inspected.snapshot.accessibility,
        interactiveElementsDetected: inspected.snapshot.totalElementCount
      };
      const needsPageScreenshot = (pageResult.status >= 400) ||
        inspected.snapshot.links.some(link => !link.hasDestination || link.kind === "unsupported");
      if (needsPageScreenshot) {
        Object.assign(pageResult, await captureFailureScreenshot(page, scanId, screenshots, warnings));
        pageResult.failureScreenshot = pageResult.screenshot;
        pageResult.failureScreenshotPath = pageResult.screenshotPath;
        delete pageResult.screenshot;
        delete pageResult.screenshotPath;
      }
      discoveredLinks.push(...inspected.snapshot.links.map(link => ({
        ...link,
        page: finalUrl.toString(),
        failureScreenshotPath: !link.hasDestination || link.kind === "unsupported" ? pageResult.failureScreenshotPath : null,
        failureScreenshot: !link.hasDestination || link.kind === "unsupported" ? pageResult.failureScreenshot : null
      })));
      if (inspected.snapshot.linkCount > inspected.snapshot.links.length) {
        discoveredLinks.push({
          page: finalUrl.toString(),
          selector: "",
          name: `${inspected.snapshot.linkCount - inspected.snapshot.links.length} additional links`,
          hasDestination: true,
          url: "",
          sameHost: false,
          kind: "limit",
          count: inspected.snapshot.linkCount - inspected.snapshot.links.length
        });
      }
      discoveredForms.push(...inspected.snapshot.forms.map(form => ({ ...form, page: finalUrl.toString() })));
      visited.set(pageUrl.toString(), pageResult);
      allAccessibility.push(...inspected.accessibility.violations.map(violation => ({ ...violation, page: finalUrl.toString() })));

      for (const linkInfo of inspected.snapshot.links) {
        if (item.depth >= depthLimit) break;
        try {
          if (!linkInfo.safeToCrawl) continue;
          const link = new URL(linkInfo.url);
          link.hash = "";
          if (link.hostname === effectiveHost && !visited.has(link.toString()) &&
              !queue.some(entry => entry.url === link.toString())) {
            queue.push({ url: link.toString(), depth: item.depth + 1 });
          }
        } catch { /* Invalid page links are ignored. */ }
      }

      const elements = inspected.snapshot.elements.slice(0, MAX_INTERACTIONS_PER_PAGE);
      let stoppedAfterNavigation = false;
      let timedOut = false;
      let timedOutIndex = -1;
      for (const [elementIndex, element] of elements.entries()) {
        const record = {
          page: finalUrl.toString(), selector: element.selector, name: element.name,
          type: element.type, category: element.category, action: element.action,
          expected: element.expected,
          actual: "", status: "skipped", error: "", screenshot: null
        };
        if (!element.safe) {
          record.actual = element.skipReason;
          interactions.push(record);
          continue;
        }
        if (Date.now() >= deadline) {
          record.actual = "Skipped because the scan time limit was reached.";
          interactions.push(record);
          timedOut = true;
          timedOutIndex = elementIndex;
          break;
        }
        if (stoppedAfterNavigation) {
          record.actual = "Skipped after an earlier interaction navigated away from this page.";
          interactions.push(record);
          continue;
        }
        try {
          const locator = page.locator(element.selector).first();
          const before = await page.evaluate(() => ({
            url: location.href,
            text: (document.body?.innerText || "").slice(0, 6000),
            expanded: document.querySelectorAll("[aria-expanded='true']").length,
            selected: document.querySelectorAll("[aria-selected='true'],[aria-pressed='true']").length,
            openDisclosures: document.querySelectorAll("details[open]").length,
            dialogs: document.querySelectorAll("[role=dialog],dialog[open]").length
          }));
          const actionErrors = [];
          activeInteractionErrors = actionErrors;
          await locator.click({ timeout: 1800, noWaitAfter: true });
          await page.waitForTimeout(500);
          activeInteractionErrors = null;
          const after = await page.evaluate(() => ({
            url: location.href,
            text: (document.body?.innerText || "").slice(0, 6000),
            expanded: document.querySelectorAll("[aria-expanded='true']").length,
            selected: document.querySelectorAll("[aria-selected='true'],[aria-pressed='true']").length,
            openDisclosures: document.querySelectorAll("details[open]").length,
            dialogs: document.querySelectorAll("[role=dialog],dialog[open]").length
          }));
          const changed = after.url !== before.url || after.text !== before.text ||
            after.expanded !== before.expanded || after.selected !== before.selected ||
            after.openDisclosures !== before.openDisclosures || after.dialogs !== before.dialogs;
          if (actionErrors.length) {
            record.status = "failed";
            record.error = [...new Set(actionErrors)].join(" · ").slice(0, 500);
            record.actual = "A JavaScript error occurred during activation.";
          } else {
            record.status = changed ? "worked" : "no-response";
            record.actual = changed ? "A URL, visible text, expanded control, or dialog changed." :
              "No observable response; this does not prove the control is broken.";
          }
          stoppedAfterNavigation = after.url !== before.url;
        } catch (error) {
          activeInteractionErrors = null;
          record.status = "failed";
          record.error = error.message.slice(0, 500);
          record.actual = "The control could not be activated.";
        }
        if ((record.status === "failed" || record.status === "no-response") && screenshots.length < MAX_SCREENSHOTS) {
          Object.assign(record, await captureFailureScreenshot(page, scanId, screenshots, warnings));
        } else if (record.status === "failed" || record.status === "no-response") {
          await captureFailureScreenshot(page, scanId, screenshots, warnings);
        }
        interactions.push(record);
      }
      if (timedOut) {
        warnings.push("The 8-minute scan time limit was reached during interaction testing.");
        for (const element of elements.slice(timedOutIndex + 1)) {
          interactions.push({
            page: finalUrl.toString(), selector: element.selector, name: element.name,
            type: element.type, category: element.category, action: element.action,
            expected: element.expected,
            actual: "Skipped because the scan time limit was reached.",
            status: "skipped", error: "", screenshot: null
          });
        }
      }
      if (inspected.snapshot.elements.length > MAX_INTERACTIONS_PER_PAGE) {
        for (const element of inspected.snapshot.elements.slice(MAX_INTERACTIONS_PER_PAGE)) {
          interactions.push({
            page: finalUrl.toString(), selector: element.selector, name: element.name,
            type: element.type, category: element.category, action: element.action,
            expected: element.expected,
            actual: "Skipped because the per-page interaction test limit was reached.",
            status: "skipped", error: "", screenshot: null
          });
        }
      }
      if (inspected.snapshot.elementCount > MAX_DISCOVERED_INTERACTIONS_PER_PAGE) {
        interactions.push({
          page: finalUrl.toString(), selector: "", name: `${inspected.snapshot.elementCount - MAX_DISCOVERED_INTERACTIONS_PER_PAGE} additional elements`,
          type: "limit", action: "not enumerated", expected: "", actual: "The per-page discovery limit was reached.",
          status: "skipped", error: "", screenshot: null
        });
      }
      await page.close();
    }

    if (queue.length) warnings.push(`Page limit of ${pageLimit} reached; ${queue.length} discovered page(s) were not scanned.`);
    const pages = Array.from(visited.values());
    const scannedPages = pages.filter(page => page.accessibility);
    if (!scannedPages.length) {
      const failure = pages.find(page => page.error || page.reason);
      throw new Error(`No pages could be scanned${failure ? `: ${failure.error || failure.reason}` : "."}`);
    }
    const counts = {
      pages: scannedPages.length,
      tested: interactions.filter(item => item.status !== "skipped").length,
      passed: interactions.filter(item => item.status === "worked").length,
      failed: interactions.filter(item => item.status === "failed" || item.status === "no-response").length,
      skipped: Math.max(0, scannedPages.reduce((sum, page) => sum + page.interactiveElementsDetected, 0) -
        interactions.filter(item => item.status !== "skipped").length),
      accessibilityIssues: allAccessibility.length,
      accessibilityPasses: scannedPages.reduce((sum, page) => sum + page.accessibility.passes, 0),
      elementsDetected: scannedPages.reduce((sum, page) => sum + page.interactiveElementsDetected, 0),
      brokenImages: scannedPages.reduce((sum, page) => sum + (page.manual?.brokenImages.length || 0), 0)
    };
    const linkTests = buildLinkTests(discoveredLinks, pages);
    const formTests = buildFormTests(discoveredForms);
    const interactionTests = interactions.map(item => ({
      ...item,
      category: item.category || "control",
      result: resultForStatus(item.status)
    }));
    const functionalityTests = [...interactionTests, ...linkTests, ...formTests];
    const functionalitySummary = summarizeFunctionality(functionalityTests, consoleErrors.length);
    const totalChecks = counts.accessibilityPasses + counts.accessibilityIssues;
    const accessibilityScore = totalChecks ? Math.round(counts.accessibilityPasses * 100 / totalChecks) : null;
    const commerceCandidates = scannedPages.filter(page => /product|item|cart|checkout|basket/i.test(page.url));
    return {
      url: safeReportUrl(target),
      scannedAt: new Date().toISOString(),
      title: scannedPages[0]?.title || new URL(target).hostname,
      summary: { ...counts, accessibilityScore },
      pages: pages.map(({ requestedUrl, failureScreenshot, failureScreenshotPath, ...page }) => ({
        ...page,
        url: safeReportUrl(page.url),
        brokenImages: page.manual?.brokenImages || [],
        error: page.error ? page.error.replace(/https?:\/\/\S+/g, value => safeReportUrl(value)) : page.error
      })),
      interactions: interactions.map(item => ({
        ...item,
        page: safeReportUrl(item.page),
        error: redactUrls(item.error)
      })),
      functionalitySummary,
      functionalityTests: functionalityTests.map(item => ({
        ...item,
        page: safeReportUrl(item.page),
        error: redactUrls(item.error)
      })),
      accessibility: allAccessibility.map(issue => ({
        ...issue,
        page: safeReportUrl(issue.page),
        nodes: issue.nodes.map(node => ({
          ...node,
          html: node.html.replace(/\svalue=(["']).*?\1/gi, ' value="[redacted]"'),
          failureSummary: redactUrls(node.failureSummary)
        }))
      })),
      consoleErrors: consoleErrors.slice(0, 200).map(item => ({ ...item, url: safeReportUrl(item.url) })),
      failedRequests: failedRequests.slice(0, 200).map(item => ({
        ...item, url: safeReportUrl(item.url), request: safeReportUrl(item.request)
      })),
      blockedRequests: blockedRequests.slice(0, 100).map(safeReportUrl),
      warnings: warnings.map(redactUrls),
      orderFlow: options.testOrderFlow ? {
        mode: "safe-observation-only",
        status: "not-executed",
        message: "Order placement, personal/payment data entry, and form submission are disabled. The scan only reports discovered commerce-related pages.",
        candidates: commerceCandidates.map(page => safeReportUrl(page.url)),
        steps: [
          { step: "Browse pages", status: scannedPages.length ? "observed" : "not-observed" },
          { step: "Product/cart/checkout discovery", status: commerceCandidates.length ? "observed" : "not-observed" },
          { step: "Enter customer or payment details", status: "not-executed" },
          { step: "Place order", status: "not-executed" },
          { step: "Verify confirmation", status: "not-executed" }
        ]
      } : null,
      limitations: [
        "Automated checks cannot prove keyboard quality, focus order, intended interaction behavior, or WCAG conformance.",
        "Forms are inspected but never submitted; external links are never requested, and state-changing controls are not activated.",
        "Link HTTP results use only same-host pages already visited by the bounded crawler; uncrawled destinations need manual review."
      ]
    };
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (proxy) await proxy.close().catch(() => {});
  }
}

module.exports = {
  normalizeUrl,
  ScanInputError,
  assertPublicHost,
  resolvePublicAddresses,
  validateTarget,
  isPrivateIPv4,
  isPrivateIPv6,
  parseRobots,
  robotsAllows,
  resultForStatus,
  buildLinkTests,
  buildFormTests,
  summarizeFunctionality,
  scanWebsite
};
