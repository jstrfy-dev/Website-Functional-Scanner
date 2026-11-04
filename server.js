const express = require("express");
const path = require("path");
const { scanWebsite } = require("./scanner");

const app = express();
const PORT = Number(process.env.PORT || 3030);
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/reports", express.static(path.join(__dirname, "reports")));

let scanInProgress = false;

app.post("/api/scan", async (req, res) => {
  if (scanInProgress) return res.status(429).json({ error: "A scan is already running. Please try again shortly." });
  if (typeof req.body?.url !== "string" || req.body.url.length > 2048) {
    return res.status(400).json({ error: "Please provide a website URL or domain name (maximum 2048 characters)." });
  }
  const pageLimit = Number(req.body.pageLimit);
  const depth = Number(req.body.depth);
  if ((req.body.pageLimit !== undefined && (!Number.isInteger(pageLimit) || pageLimit < 1 || pageLimit > 25)) ||
      (req.body.depth !== undefined && (!Number.isInteger(depth) || depth < 0 || depth > 5))) {
    return res.status(400).json({ error: "Page limit must be 1–25 and crawl depth must be 0–5." });
  }
  scanInProgress = true;
  try {
    const report = await scanWebsite({
      url: req.body.url,
      pageLimit: req.body.pageLimit,
      depth: req.body.depth,
      testOrderFlow: req.body.testOrderFlow === true
    });
    res.json(report);
  } catch (error) {
    const status = error.name === "ScanInputError" ? 400 : 502;
    res.status(status).json({ error: error.message || "The website scan failed." });
  } finally {
    scanInProgress = false;
  }
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Accessibility Scanner running at http://127.0.0.1:${PORT}`);
});
