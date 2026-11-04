# AccessCheck — Full Site Test

Local Express application for crawling a bounded number of same-host pages with Playwright and axe-core. Includes WCAG 2.2 A/AA automated checks, conservative functionality checks for controls, links, and forms, browser error reporting, failure screenshots, and JSON/HTML/print-to-PDF exports.

## Requirements and installation

- Windows 10/11 and Node.js 20+
- Network access to install packages and scan public websites

From the `accessibility-scanner` project directory:

```powershell
npm install
npx playwright install chromium
npm test
npm start
```

Open `http://127.0.0.1:3030`. Enter either `https://example.com` or `example.com`; the scanner adds HTTPS when no scheme is given. Choose a page limit (up to 25) and crawl depth (up to 5), then start the scan. Use the export buttons to download JSON or HTML; use **Print / Save PDF** and choose “Save as PDF” in the browser print dialog.

To use another port in PowerShell:

```powershell
$env:PORT=3031
npm start
```

## What it does

- Crawls same-host links only, bounded by the selected page limit/depth, following public redirects.
- Checks `robots.txt` for wildcard-agent allow/disallow paths and applies at least a one-second crawl delay.
- Runs axe-core WCAG 2.2 A/AA (plus older WCAG tags and best-practice rules) on each scanned page.
- Checks a basic Tab-focus movement signal and reports it as a limited automated observation, not a focus-order audit.
- Tests a capped set of safe buttons, tabs, menus, disclosures, and ARIA controls. It records selectors, actions, visible responses, JavaScript errors, and screenshots for failed or non-responsive interactions.
- Adds a **Functionality Test Results** dashboard with PASS, FAIL, and NEEDS REVIEW outcomes. Same-host link results use pages already visited by the bounded crawler; external and uncrawled links are not requested just to test them.
- Inspects forms and required-field/submit-control counts without entering data, triggering validation, or submitting the form.
- Detects images that are missing `alt` text or whose loaded resource is broken.
- Captures browser console errors, failed requests, and blocked network destinations.

## Safety and limitations

- Only scan websites you own or have explicit permission to test.
- Local/private/special-use IPs and internal hostnames are blocked after DNS resolution. Browser requests and redirects are also checked, unsafe protocols and nonstandard ports are blocked, and the browser context is isolated.
- This is a local scanner, not a network sandbox. It should not be exposed to untrusted users or run with privileged network access.
- Safe mode never submits forms, changes input values, or activates links. It skips submit controls and buttons whose labels suggest destructive or state-changing actions. External links are not requested just to test them. No personal/payment details are collected, no order is submitted, and no payment is attempted.
- The optional **Observe commerce pages** toggle only reports discovered product/cart/checkout-like URLs. It does not execute an order flow.
- Each run scans one host and a bounded subset of pages and interactive elements. The UI shows skipped items and page-limit warnings. Failure screenshots are saved under `reports/` and are also embedded in the report.
- A PASS link result means the same-host destination was crawled and returned a successful HTTP response; it does not prove that the destination is the intended one. Uncrawled links, forms, and non-responsive controls require manual review.
- “Worked” means the browser observed a URL/text/dialog/expanded-state change; it is not proof that the action fulfilled its business purpose. “No response” is not necessarily a site defect.
- axe-core cannot fully verify keyboard operation, focus order, semantic correctness, or actual WCAG conformance. Manual review remains necessary.
- PDF is generated through the browser print dialog. Screenshots are embedded in JSON/HTML reports and may make exports large.

## Troubleshooting

- If Chromium is missing, run `npx playwright install chromium`.
- A scan may take several minutes because page visits follow robots.txt crawl-delay and navigation timeouts.
- If a site is inaccessible, blocks automation, or redirects to a private/unsupported destination, the scanner reports a failure or blocked request instead of bypassing its protections.
