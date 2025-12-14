const path = require("path");
const express = require("express");
const fetch = require("node-fetch");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const logFilePath = path.join(__dirname, "server.log");

app.use(express.json());
app.use(express.static(path.join(__dirname, "app")));

function create4DigitId(str) {
  let hash = 0;

  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }

  const positiveHash = Math.abs(hash);
  const fourDigitNumber = positiveHash % 10000;
  
  return fourDigitNumber;
}

app.get("/api/ipinfo", async (req, res) => {
  try {
    const token = process.env.IPINFO_TOKEN;

    if (!token) {
      return res.status(500).json({
        error: "Server configuration error",
        details: "IP info service is not configured",
      });
    }

    // Add timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, 8000);

    const url = `https://ipinfo.io/json?token=${token}`;

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "FingerprintApp/1.0",
        Accept: "application/json",
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        error: "Failed to fetch IP information",
        statusCode: response.status,
        details: errorText,
      });
    }

    const data = await response.json();

    // Validate response
    if (!data.ip) {
      return res.status(502).json({
        error: "Invalid response from IP info service",
      });
    }

    res.json(data);
  } catch (error) {
    if (error.name === "AbortError") {
      return res.status(504).json({
        error: "Request timeout",
        message: "IPInfo API took too long to respond",
      });
    }

    // Check for specific fetch errors
    if (error.code === "ENOTFOUND") {
      return res.status(503).json({
        error: "Cannot reach IPInfo API",
        message: "DNS lookup failed",
      });
    }

    if (error.code === "ECONNREFUSED") {
      return res.status(503).json({
        error: "Cannot reach IPInfo API",
        message: "Connection refused",
      });
    }

    res.status(500).json({
      error: "Internal server error",
      message: error.message,
      type: error.name,
    });
  }
});

app.post("/api/data", (req, res) => {
  const hashes = req.body;
  hashes.userID = create4DigitId(hashes.fingerprints.deviceFingerprint);
  hashes.networkID = create4DigitId(
    hashes.fingerprints.ipFingerprint + hashes.fingerprints.timeZoneFingerprint
  );

  if (!hashes || !hashes.fingerprints) {
    return res.status(400).send({ error: "Missing fingerprints object" });
  }

  const logLine = JSON.stringify(hashes) + "\n";

  fs.appendFile(logFilePath, logLine, (err) => {
    if (err) {
      return res.status(500).send({ error: "Failed to save log on server." });
    }
    res.status(200).send({ status: "Success", message: "Object logged." });
  });
});

// Root route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "app", "index.html"));
});

app.use((req, res) => {
  res.redirect(301, "/");
});

// Global error handler
app.use((err, req, res, next) => {
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(process.env.IPINFO_TOKEN ? "" : "❌ IPINFO_TOKEN is Missing");
});
