const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== 1. ENV CONFIGURATION =====
const SECRET_KEY = process.env.SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SECRET_KEY) {
  console.error("❌ Missing environment variables. Please check your .env file.");
  process.exit(1);
}

// ===== 2. SUPABASE CLIENT =====
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== 3. MIDDLEWARE (สำคัญ: เก็บ Raw Body เพื่อใช้ Verify Signature) =====
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// ===== 4. HEALTH CHECK =====
app.get("/", (_, res) => res.send("ipay4u API is Online"));
app.get("/health", (_, res) => res.json({ status: "ok", timestamp: new Date() }));

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

    // ใช้ UPSERT เพื่อป้องกัน Error เมื่อ Device เดิมขอ Token ใหม่
    const { data, error } = await supabase
      .from("devices")
      .upsert({
        device_id,
        device_name,
        device_token: deviceToken,
        status: "active",
        updated_at: new Date()
      }, { onConflict: 'device_id' })
      .select()
      .single();

    if (error) {
      console.error("Registration Error:", error.message);
      return res.status(500).json({ error: "database error during registration" });
    }

    console.log(`✅ Device Registered: ${device_name} (${device_id})`);
    res.json({ device_token: data.device_token });

  } catch (err) {
    console.error("Register Crash:", err);
    res.status(500).json({ error: "internal server error" });
  }
});

// =====================================================
// 🔔 NOTIFY (รับแจ้งยอดเงินเข้า)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    // 1. Basic Auth Check
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

    // 2. ค้นหา Device ใน Database
    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();

    if (deviceError || !device) {
      console.error("Device Auth Failed:", deviceToken);
      return res.status(403).json({ error: "invalid device token" });
    }

    if (device.status !== "active") {
      return res.status(403).json({ error: "device is disabled" });
    }

    // 3. Verify HMAC Signature (ใช้ rawBody เพื่อความแม่นยำ 100%)
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      console.warn("❌ Invalid Signature attempt from device:", device.device_id);
      return res.status(401).json({ error: "invalid signature" });
    }

    // 4. บันทึกข้อมูลการชำระเงิน
    const { client_txn_id, bank, amount, title, message } = req.body;

    if (!client_txn_id || amount === undefined) {
      return res.status(400).json({ error: "incomplete payment data" });
    }

    const { data: payment, error: insertError } = await supabase
      .from("payments")
      .insert([{
        client_txn_id,
        bank,
        amount: parseFloat(amount),
        title,
        message,
        device_id: device.device_id,
        created_at: new Date()
      }])
      .select()
      .single();

    // กรณีข้อมูลซ้ำ (Unique Constraint)
    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored", client_txn_id });
    }

    if (insertError) {
      console.error("DB Insert Error:", insertError.message);
      return res.status(500).json({ error: "failed to record payment" });
    }

    console.log(`💰 New Payment: ${amount} THB via ${bank} (Txn: ${client_txn_id})`);
    res.json({ status: "ok", payment_id: payment.id });

  } catch (err) {
    console.error("Notify Crash:", err);
    res.status(500).json({ error: "internal server error" });
  }
});

// ===== 5. START SERVER =====
app.listen(PORT, () => {
  console.log(`
  🚀 iPay4U Backend Running
  --------------------------
  Port:      ${PORT}
  Supabase:  ${SUPABASE_URL}
  --------------------------
  `);
});
