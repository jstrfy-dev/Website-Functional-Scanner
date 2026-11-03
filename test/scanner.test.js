const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeUrl,
  isPrivateIPv4,
  isPrivateIPv6,
  parseRobots,
  robotsAllows
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
