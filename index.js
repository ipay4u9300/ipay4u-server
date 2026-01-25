const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

/* =======================
   ENV & Supabase
======================= */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ Missing Supabase ENV");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

/* =======================
   Middleware
======================= */
app.use(bodyParser.json({ limit: "50kb" }));

/* =======================
   Utils - Security
======================= */
function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hmacSHA256(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

/* =======================
   Health Check
======================= */
app.get("/", (req, res) => {
  res.send("ipay4u api running");
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString()
  });
});

/* =======================
   POST /register
   - Android เรียกครั้งแรก
   - คืน device_token
======================= */
app.post("/register", async (req, res) => {
  try {
    const { device_id, device_name } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: "missing device_id" });
    }

    const device_token = generateToken();

    const { data, error } = await supabase
      .from("devices")
      .upsert({
        device_id,
        device_name,
        device_token,
        status: "active"
      })
      .select()
      .single();

    if (error) {
      console.error("Register error:", error);
      return res.status(500).json({ error: "register failed" });
    }

    res.json({
      device_token: data.device_token
    });
  } catch (err) {
    console.error("Register exception:", err);
    res.status(500).json({ error: "internal error" });
  }
});

/* =======================
   POST /notify
   - รับ noti จาก Android
   - HMAC + timestamp + nonce
======================= */
app.post("/notify", async (req, res) => {
  try {
    const signature = req.headers["x-signature"];
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const deviceToken = req.headers["x-device-token"];

    if (!signature || !timestamp || !nonce || !deviceToken) {
      return res.status(401).json({ error: "missing security headers" });
    }

    /* ---------- Timestamp Check (±2 นาที) ---------- */
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - Number(timestamp)) > 120) {
      return res.status(401).json({ error: "timestamp expired" });
    }

    /* ---------- Replay Protection (nonce) ---------- */
    const { data: nonceUsed } = await supabase
      .from("nonces")
      .select("nonce")
      .eq("nonce", nonce)
      .maybeSingle();

    if (nonceUsed) {
      return res.status(409).json({ error: "replay detected" });
    }

    await supabase.from("nonces").insert({ nonce });

    /* ---------- Validate Device ---------- */
    const { data: device } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .eq("status", "active")
      .maybeSingle();

    if (!device) {
      return res.status(403).json({ error: "invalid device" });
    }

    /* ---------- Signature Verify ---------- */
    const rawBody = JSON.stringify(req.body);
    const expectedSignature = hmacSHA256(
      device.device_token,
      rawBody + timestamp + nonce
    );

    if (expectedSignature !== signature) {
      return res.status(403).json({ error: "bad signature" });
    }

    /* ---------- Business Validation ---------- */
    const {
      client_txn_id,
      bank,
      amount,
      title,
      message
    } = req.body;

    if (!client_txn_id || !bank || !amount) {
      return res.status(400).json({ error: "missing fields" });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: "invalid amount" });
    }

    /* ---------- Insert Payment ---------- */
    const { error } = await supabase
      .from("payments")
      .insert([{
        event_id: client_txn_id,
        bank,
        amount,
        title,
        message,
        device_id: device.device_id,
        device_name: device.device_name
      }]);

    // duplicate → ถือว่าสำเร็จ
    if (error && error.code === "23505") {
      return res.json({ status: "duplicate_ignored" });
    }

    if (error) {
      console.error("Insert payment error:", error);
      return res.status(500).json({ error: "db insert failed" });
    }

    res.json({ status: "ok" });

  } catch (err) {
    console.error("Notify exception:", err);
    res.status(500).json({ error: "internal server error" });
  }
});

/* =======================
   Start Server
======================= */
app.listen(PORT, () => {
  console.log(`🚀 ipay4u API running on port ${PORT}`);
});
