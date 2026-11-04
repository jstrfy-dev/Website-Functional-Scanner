const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeUrl,
  isPrivateIPv4,
  isPrivateIPv6,
  parseRobots,
  robotsAllows,
  resultForStatus,
  buildLinkTests,
  buildFormTests,
  summarizeFunctionality
} = require("../scanner");

test("normalizes domain names and complete URLs", () => {
  assert.equal(normalizeUrl("example.com"), "https://example.com/");
  assert.equal(normalizeUrl("https://example.com/path"), "https://example.com/path");
  assert.equal(normalizeUrl("http://example.com"), "http://example.com/");
});

test("rejects unsafe URL schemes, credentials, and nonstandard ports", () => {
  assert.throws(() => normalizeUrl("javascript:alert(1)"), /HTTP and HTTPS/);
  assert.throws(() => normalizeUrl("https://user:pass@example.com"), /credentials/);
  assert.throws(() => normalizeUrl("https://example.com:8443"), /standard/);
  assert.throws(() => normalizeUrl("not a domain"), /valid website/);
});

test("identifies private, reserved, and public IPv4 addresses", () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "172.20.1.1", "192.168.1.1", "169.254.10.2", "198.51.100.2", "168.63.129.16"]) {
    assert.equal(isPrivateIPv4(address), true, `${address} should be blocked`);
  }
  assert.equal(isPrivateIPv4("8.8.8.8"), false);
});

test("blocks private and special-use IPv6 while accepting global unicast", () => {
  for (const address of ["::1", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPrivateIPv6(address), true, `${address} should be blocked`);
  }
  assert.equal(isPrivateIPv6("2606:4700:4700::1111"), false);
});

test("parses wildcard robots rules and rate limits", () => {
  const robots = parseRobots("User-agent: *\nDisallow: /private\nAllow: /private/public\nCrawl-delay: 2");
  assert.equal(robotsAllows("/private/page", robots.rules), false);
  assert.equal(robotsAllows("/private/public/page", robots.rules), true);
  assert.equal(robotsAllows("/home", robots.rules), true);
  assert.equal(robots.delayMs, 2000);
});

test("applies a minimum robots crawl delay and ignores other user agents", () => {
  const robots = parseRobots("User-agent: OtherBot\nDisallow: /\nUser-agent: *\nDisallow: /blocked\nCrawl-delay: 0");
  assert.equal(robotsAllows("/blocked/page", robots.rules), false);
  assert.equal(robotsAllows("/ok", robots.rules), true);
  assert.equal(robots.delayMs, 1000);
});

test("prefers an equally specific robots Allow rule", () => {
  const robots = parseRobots("User-agent: *\nDisallow: /public\nAllow: /public");
  assert.equal(robotsAllows("/public/page", robots.rules), true);
});

test("maps interaction observations to clear functionality outcomes", () => {
  assert.equal(resultForStatus("worked"), "PASS");
  assert.equal(resultForStatus("failed"), "FAIL");
  assert.equal(resultForStatus("no-response"), "NEEDS REVIEW");
  assert.equal(resultForStatus("skipped"), "NEEDS REVIEW");
});

test("checks links only against already crawled same-host pages", () => {
  const links = [
    { page: "https://site.test/", selector: "a:nth-of-type(1)", name: "Working", hasDestination: true, url: "https://site.test/ok", sameHost: true, kind: "internal" },
    { page: "https://site.test/", selector: "a:nth-of-type(2)", name: "Broken", hasDestination: true, url: "https://site.test/missing", sameHost: true, kind: "internal" },
    { page: "https://site.test/", selector: "a:nth-of-type(3)", name: "Empty", hasDestination: false, url: "", sameHost: false, kind: "empty" },
    { page: "https://site.test/", selector: "a:nth-of-type(4)", name: "External", hasDestination: true, url: "https://other.test/", sameHost: false, kind: "external" }
  ];
  const pages = [
    { url: "https://site.test/ok", status: 200 },
    { url: "https://site.test/missing", status: 404, failureScreenshot: "data:image/jpeg;base64,shot" }
  ];
  const tests = buildLinkTests(links, pages);
  assert.deepEqual(tests.map(test => test.result), ["PASS", "FAIL", "FAIL", "NEEDS REVIEW"]);
  assert.equal(tests[1].error, "HTTP 404");
  assert.equal(tests[1].screenshot, "data:image/jpeg;base64,shot");
  assert.match(tests[3].actual, /not requested or activated/);
});

test("reports forms without submitting them", () => {
  const [form] = buildFormTests([{
    page: "https://site.test/contact",
    selector: "form",
    name: "Contact",
    fieldCount: 3,
    requiredFields: 2,
    submitButtons: 0,
    nativeValidationEnabled: true
  }]);
  assert.equal(form.result, "NEEDS REVIEW");
  assert.match(form.action, /not submitted/);
  assert.match(form.actual, /2 required/);
  assert.match(form.actual, /No native submit control/);
});

test("recognizes redirects and reports the bounded link-discovery limit", () => {
  const links = [
    { page: "https://site.test/", selector: "a.old", name: "Redirected", hasDestination: true, url: "https://site.test/old", sameHost: true, kind: "internal" },
    { page: "https://site.test/", selector: "", name: "3 additional links", hasDestination: true, url: "", sameHost: false, kind: "limit", count: 3 }
  ];
  const tests = buildLinkTests(links, [{
    url: "https://site.test/new",
    requestedUrl: "https://site.test/old",
    status: 200
  }]);
  assert.equal(tests[0].result, "PASS");
  assert.equal(tests[1].result, "NEEDS REVIEW");
  assert.match(tests[1].actual, /3 additional link/);
});

test("summarizes functionality outcomes and link errors", () => {
  const summary = summarizeFunctionality([
    { category: "button", result: "PASS" },
    { category: "link", result: "FAIL" },
    { category: "form", result: "NEEDS REVIEW" }
  ], 2);
  assert.deepEqual(summary, {
    total: 3,
    working: 1,
    failed: 1,
    manualReview: 1,
    brokenLinks: 1,
    javascriptErrors: 2
  });
});
