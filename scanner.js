const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const { chromium } = require("playwright");
const axe = require("axe-core");

const MAX_PAGES = 25;
const MAX_INTERACTIONS_PER_PAGE = 60;
const MAX_DISCOVERED_INTERACTIONS_PER_PAGE = 300;
const MAX_SCREENSHOTS = 20;
const PAGE_TIMEOUT_MS = 20000;
const MAX_SCAN_MS = 8 * 60 * 1000;

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
    const links = Array.from(document.querySelectorAll("a[href]"))
      .map(anchor => anchor.href).filter(href => /^https?:/i.test(href)).slice(0, 500);
    const elements = Array.from(document.querySelectorAll(
      "form,button,a[href],input:not([type=hidden]),textarea,[role=button],[role=tab],[role=menuitem],[aria-haspopup],[onclick],[tabindex]:not([tabindex='-1']),select,summary"
    )).map((element, index) => {
      const type = element.getAttribute("type") || element.tagName.toLowerCase();
      const inputButton = element.matches("input[type=button],input[type=submit]");
      const labelText = element.labels ? Array.from(element.labels).map(label => label.innerText).join(" ").trim() : "";
      const name = (element.tagName === "FORM" ? "" : element.innerText) ||
        (inputButton ? element.value : "") || labelText || element.getAttribute("aria-label") ||
        element.getAttribute("title") || (element.tagName === "FORM" ? "Form" : "");
      const href = element instanceof HTMLAnchorElement ? element.href : "";
      const form = element.closest("form");
      const style = getComputedStyle(element);
      const visible = element.getClientRects().length > 0 && style.visibility !== "hidden" && style.display !== "none";
      const defaultButtonType = element.tagName === "BUTTON" && !element.hasAttribute("type") ? "submit" : type;
      const sideEffectPath = /(?:delete|remove|logout|log-out|purchase|payment|order|checkout|unsubscribe|cancel|signout)/i.test(href);
      let safe = true;
      let skipReason = "";
      if (!visible) {
        safe = false;
        skipReason = "Skipped because the element is not visible.";
      } else if (element.matches(":disabled,[aria-disabled='true']")) {
        safe = false;
        skipReason = "Skipped because the element is disabled.";
      } else if (element.matches("select,input,textarea") || element.tagName === "FORM" || element.tagName === "SUMMARY") {
        safe = false;
        skipReason = "Skipped to avoid changing site state or submitting data.";
      } else if (form && element.tagName !== "A") {
        safe = false;
        skipReason = "Skipped because this control is inside a form.";
      } else if (element.tagName === "BUTTON" && defaultButtonType !== "button") {
        safe = false;
        skipReason = "Skipped because this button may submit a form.";
      } else if (element.tagName === "A" &&
          (new URL(href, location.href).hostname !== location.hostname ||
           element.hasAttribute("download") || sideEffectPath || element.target === "_blank")) {
        safe = false;
        skipReason = "Skipped external, new-window, download, or potentially state-changing link.";
      }
      return {
        selector: selectorFor(element), name: name || "(unnamed)", type,
        action: element.tagName === "A" ? "click link" : "click control",
        safe, skipReason, index
      };
    });
    return {
      title: document.title,
      url: location.href,
      links,
      elements: elements.slice(0, maxDiscoveredElements),
      elementCount: elements.length,
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
  const screenshots = [];
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
      page.on("console", message => {
        if (message.type() === "error") consoleErrors.push({
          url: page.url(),
          message: message.text().replace(/https?:\/\/\S+/g, value => safeReportUrl(value)).slice(0, 500)
        });
      });
      page.on("pageerror", error => consoleErrors.push({ url: page.url(), message: redactUrls(error.message).slice(0, 500) }));
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
        title: inspected.snapshot.title,
        status: inspected.response?.status() ?? null,
        depth: item.depth,
        accessibility: inspected.accessibility,
        keyboard: inspected.keyboard,
        manual: inspected.snapshot.accessibility,
        interactiveElementsDetected: inspected.snapshot.elementCount
      };
      visited.set(pageUrl.toString(), pageResult);
      allAccessibility.push(...inspected.accessibility.violations.map(violation => ({ ...violation, page: finalUrl.toString() })));

      for (const href of inspected.snapshot.links) {
        if (item.depth >= depthLimit) break;
        try {
          const link = new URL(href);
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
          type: element.type, action: element.action, expected: "Activation has an observable response.",
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
            dialogs: document.querySelectorAll("[role=dialog],dialog[open]").length
          }));
          await locator.click({ timeout: 1800, noWaitAfter: true });
          await page.waitForTimeout(350);
          const after = await page.evaluate(() => ({
            url: location.href,
            text: (document.body?.innerText || "").slice(0, 6000),
            expanded: document.querySelectorAll("[aria-expanded='true']").length,
            dialogs: document.querySelectorAll("[role=dialog],dialog[open]").length
          }));
          const changed = after.url !== before.url || after.text !== before.text ||
            after.expanded !== before.expanded || after.dialogs !== before.dialogs;
          record.status = changed ? "worked" : "no-response";
          record.actual = changed ? "A URL, visible text, expanded control, or dialog changed." : "No observable page response after activation.";
          stoppedAfterNavigation = after.url !== before.url;
        } catch (error) {
          record.status = "failed";
          record.error = error.message.slice(0, 500);
          record.actual = "The control could not be activated.";
        }
        if ((record.status === "failed" || record.status === "no-response") && screenshots.length < MAX_SCREENSHOTS) {
          try {
            record.screenshot = `data:image/jpeg;base64,${(await page.screenshot({ type: "jpeg", quality: 45, timeout: 2500 })).toString("base64")}`;
            screenshots.push(record.screenshot);
          } catch (error) {
            warnings.push(`Could not capture a failure screenshot: ${error.message}`);
          }
        } else if ((record.status === "failed" || record.status === "no-response") &&
            !warnings.includes("Screenshot limit reached; some failures have no screenshot.")) {
          warnings.push("Screenshot limit reached; some failures have no screenshot.");
        }
        interactions.push(record);
      }
      if (timedOut) {
        warnings.push("The 8-minute scan time limit was reached during interaction testing.");
        for (const element of elements.slice(timedOutIndex + 1)) {
          interactions.push({
            page: finalUrl.toString(), selector: element.selector, name: element.name,
            type: element.type, action: element.action, expected: "Activation has an observable response.",
            actual: "Skipped because the scan time limit was reached.",
            status: "skipped", error: "", screenshot: null
          });
        }
      }
      if (inspected.snapshot.elements.length > MAX_INTERACTIONS_PER_PAGE) {
        for (const element of inspected.snapshot.elements.slice(MAX_INTERACTIONS_PER_PAGE)) {
          interactions.push({
            page: finalUrl.toString(), selector: element.selector, name: element.name,
            type: element.type, action: element.action, expected: "Activation has an observable response.",
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
    const totalChecks = counts.accessibilityPasses + counts.accessibilityIssues;
    const accessibilityScore = totalChecks ? Math.round(counts.accessibilityPasses * 100 / totalChecks) : null;
    const commerceCandidates = scannedPages.filter(page => /product|item|cart|checkout|basket/i.test(page.url));
    return {
      url: safeReportUrl(target),
      scannedAt: new Date().toISOString(),
      title: scannedPages[0]?.title || new URL(target).hostname,
      summary: { ...counts, accessibilityScore },
      pages: pages.map(page => ({
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
        "Interactive form controls and potentially state-changing links are skipped; order submission is never attempted.",
        "Only same-host pages discovered through links are crawled."
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
  scanWebsite
};
