const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== ENV =====
const SECRET_KEY = process.env.SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SECRET_KEY) {
  console.error("❌ Missing ENV");
  process.exit(1);
}

// ===== Supabase =====
const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

app.use(bodyParser.json());

// ===== Health =====
app.get("/", (_, res) => res.send("ipay4u api running"));
app.get("/health", (_, res) => res.json({ status: "ok" }));

// =====================================================
// 🔐 REGISTER DEVICE
// =====================================================
app.post("/register", async (req, res) => {
  try {
    const clientKey = req.headers["x-secret-key"];
    if (clientKey !== SECRET_KEY) {
      return res.status(403).json({ error: "forbidden" });
    }

    const { device_id, device_name } = req.body;
    if (!device_id || !device_name) {
      return res.status(400).json({ error: "missing device data" });
    }

    const deviceToken = crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
      .from("devices")
      .insert([{
        device_id,
        device_name,
        device_token: deviceToken,
        status: "active"
      }])
      .select()
      .single();

    if (error) {
      console.error("register error:", error);
      return res.status(500).json({ error: "register failed" });
    }

    res.json({ device_token: data.device_token });

  } catch (err) {
    console.error("register crash:", err);
    res.status(500).json({ error: "server error" });
  }
});

// =====================================================
// 🔔 NOTIFY (รับแจ้งเงินเข้า)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    const clientKey = req.headers["x-secret-key"];
    if (clientKey !== SECRET_KEY) {
      return res.status(403).json({ error: "forbidden" });
    }

    const deviceToken = req.headers["x-device-token"];
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const signature = req.headers["x-signature"];

    if (!deviceToken || !timestamp || !nonce || !signature) {
      return res.status(401).json({ error: "missing security headers" });
    }

    // 🔍 หา device
    console.log("x-device-token =", deviceToken);
    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();
    console.log("device from db =", device);
    console.log("device error =", error);

    if (deviceError || !device) {
      return res.status(403).json({ error: "invalid device" });
    }

    if (device.status !== "active") {
      return res.status(403).json({ error: "device disabled" });
    }

    // 🔏 verify signature
    const rawBody = JSON.stringify(req.body || {});
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      return res.status(401).json({ error: "invalid signature" });
    }

    // ===== data =====
    const {
      client_txn_id,
      bank,
      amount,
      title,
      message
    } = req.body;

    if (!client_txn_id || !amount) {
      return res.status(400).json({ error: "missing payment data" });
    }

    const { data: payment, error: insertError } = await supabase
      .from("payments")
      .insert([{
        client_txn_id,
        bank,
        amount,
        title,
        message,
        device_id: device.device_id
      }])
      .select()
      .single();

    // duplicate → ถือว่าสำเร็จ
    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored" });
    }

    if (insertError) {
      console.error("payment insert error:", insertError);
      return res.status(500).json({ error: "db insert failed" });
    }

    res.json({ status: "ok", payment });

  } catch (err) {
    console.error("notify crash:", err);
    res.status(500).json({ error: "server error" });
  }
});

// ===== START =====
app.listen(PORT, () => {
  console.log(`🚀 ipay4u api running on ${PORT}`);
});
