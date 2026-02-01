const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== 1. การตั้งค่าสิทธิ์และการเชื่อมต่อ (ENV) =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ ERROR: Missing Supabase environment variables!");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== 2. MIDDLEWARE =====
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// หน้าแรกสำหรับเช็คว่า API ออนไลน์อยู่ไหม
app.get("/", (_, res) => res.send("iPay4U Backend API: Active and Secure"));

// =====================================================
// 🔐 1. REGISTER DEVICE (ลงทะเบียนเครื่อง)
// =====================================================
app.post("/register", async (req, res) => {
  try {
    const fingerprint = req.headers["x-device-fingerprint"];
    if (!fingerprint) return res.status(403).json({ error: "Forbidden: Missing Fingerprint" });

    const { device_id, device_name, device_fingerprint } = req.body;
    if (!device_id || !device_name) return res.status(400).json({ error: "Missing required data" });

    const deviceToken = crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
      .from("devices")
      .upsert({
        device_id,
        device_name,
        device_token: deviceToken,
        status: "active",
        last_fingerprint: fingerprint || device_fingerprint
      }, { onConflict: 'device_id' })
      .select().single();

    if (error) throw error;

    console.log(`📱 New Device Registered: ${device_name} (ID: ${device_id})`);
    res.json({ device_token: data.device_token });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "Server internal error" });
  }
});

// =====================================================
// 🔍 2. DEVICE STATUS (เช็คสถานะจากแอป)
// =====================================================
app.get("/device-status", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const deviceToken = authHeader ? authHeader.split(" ")[1] : null;

    if (!deviceToken) return res.status(401).json({ error: "Unauthorized" });

    const { data: device, error } = await supabase
      .from("devices")
      .select("status")
      .eq("device_token", deviceToken)
      .single();

    if (error || !device) return res.status(404).json({ error: "Device not found" });

    res.json({ status: device.status });
  } catch (err) {
    console.error("Status Sync Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================================
// ⚙️ 3. APP CONFIG (ดึง Keywords และ Bank Packages จาก Supabase)
// =====================================================
app.get("/config", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const deviceToken = authHeader ? authHeader.split(" ")[1] : null;

    if (!deviceToken) return res.status(401).json({ error: "Unauthorized" });

    // 1. ตรวจสอบก่อนว่าเครื่องนี้มีสิทธิ์ดึงข้อมูลไหม (ต้องเป็นเครื่องที่ลงทะเบียนแล้ว)
    const { data: device, error: devError } = await supabase
      .from("devices")
      .select("status")
      .eq("device_token", deviceToken)
      .single();

    if (devError || !device) return res.status(404).json({ error: "Device not found" });

    // 2. ดึงข้อมูลจากตาราง app_configs ที่เราสร้างไว้
    const { data: config, error: configError } = await supabase
      .from("app_configs")
      .select("config_value")
      .eq("config_key", "bank_configs")
      .single();

    if (configError || !config) {
      console.error("❌ Config not found in DB");
      return res.status(404).json({ error: "Config not found" });
    }

    // ส่งข้อมูล JSON (keywords และ packages) กลับไปที่แอป
    res.json(config.config_value);
  } catch (err) {
    console.error("Config Fetch Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================================
// 🔔 4. NOTIFY (รับข้อมูลเงินเข้า)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const deviceToken = authHeader ? authHeader.split(" ")[1] : null;
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const signature = req.headers["x-signature"];

    if (!deviceToken || !signature) return res.status(401).json({ error: "Unauthorized" });

    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();

    if (deviceError || !device) return res.status(403).json({ error: "Device invalid" });
    if (device.status !== "active") return res.status(403).json({ error: "Device access suspended" });

    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const { client_txn_id, bank, amount, title, message } = req.body;

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
      .select().single();

    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored", txn_id: client_txn_id });
    }

    if (insertError) throw insertError;

    console.log(`💰 Success: ${amount} THB (Txn: ${client_txn_id}) from ${device.device_name}`);
    res.json({ status: "ok", txn_id: payment.client_txn_id });

  } catch (err) {
    console.error("Notify Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`
  🚀 iPay4U Backend is running on port ${PORT}
  🛠  Remote Config: /config is ready
  ⏱  Sync: 10-min status check support
  `);
});
