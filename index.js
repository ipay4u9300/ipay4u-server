const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== 1. การตั้งค่า ENV (ดึงค่าจาก Environment Variables) =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ Missing Supabase Configuration");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== 2. MIDDLEWARE =====
// เก็บข้อมูลดิบ (Raw Body) ไว้สำหรับตรวจสอบ Signature ให้แม่นยำ 100%
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Health Check
app.get("/", (_, res) => res.send("iPay4U API: Active and Secure"));

// =====================================================
// 🔐 1. REGISTER DEVICE (ลงทะเบียนเครื่องครั้งแรก)
// =====================================================
app.post("/register", async (req, res) => {
  try {
    const fingerprint = req.headers["x-device-fingerprint"];
    if (!fingerprint) return res.status(403).json({ error: "Forbidden: Missing Fingerprint" });

    const { device_id, device_name } = req.body;
    if (!device_id || !device_name) return res.status(400).json({ error: "Missing data" });

    // สร้าง Token สุ่ม 64 ตัวอักษร (Hex)
    const deviceToken = crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
      .from("devices")
      .upsert({
        device_id,
        device_name,
        device_token: deviceToken,
        status: "active" // สถานะเริ่มต้น
      }, { onConflict: 'device_id' })
      .select().single();

    if (error) throw error;
    console.log(`📱 Registered: ${device_name} (${device_id})`);
    res.json({ device_token: data.device_token });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================================
// 🔍 2. DEVICE STATUS (เช็คสถานะจาก Android ทุก 30 นาที)
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

    // คืนค่าสถานะเพื่อให้ Android ตัดสินใจว่าจะดักจับยอดต่อไหม
    res.json({ status: device.status });
  } catch (err) {
    console.error("Status Check Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================================
// 🔔 3. NOTIFY (รับแจ้งเตือนยอดเงินเข้า)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    // ดึงข้อมูลความปลอดภัยจาก Header
    const authHeader = req.headers["authorization"];
    const deviceToken = authHeader ? authHeader.split(" ")[1] : null;
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const signature = req.headers["x-signature"];

    if (!deviceToken || !signature) return res.status(401).json({ error: "Unauthorized" });

    // 1. ตรวจสอบว่า Device มีจริงและสถานะ active หรือไม่
    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();

    if (deviceError || !device) return res.status(403).json({ error: "Invalid device" });
    if (device.status !== "active") return res.status(403).json({ error: "Device is locked" });

    // 2. ตรวจสอบ Signature (HMAC-SHA256)
    // สูตรเดียวกับใน Android: RawBody + Timestamp + Nonce
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      console.log("❌ Signature Mismatch! Potentially tampered request.");
      return res.status(401).json({ error: "Invalid signature" });
    }

    // 3. รับข้อมูลธุรกรรม
    const { client_txn_id, bank, amount, title, message } = req.body;

    if (!client_txn_id || amount === undefined) {
      return res.status(400).json({ error: "Missing transaction data" });
    }

    // 4. บันทึกลงตาราง payments
    const { data: payment, error: insertError } = await supabase
      .from("payments")
      .insert([{
        client_txn_id: client_txn_id,
        bank,
        amount: parseFloat(amount),
        title,
        message,
        device_id: device.device_id
      }])
      .select().single();

    // ดักจับข้อมูลซ้ำ (Unique Constraint Error)
    if (insertError && insertError.code === "23505") {
      console.log(`♻️ Duplicate ignored: ${client_txn_id}`);
      return res.json({ status: "duplicate_ignored", client_txn_id });
    }

    if (insertError) throw insertError;

    console.log(`💰 Success: ${amount} THB (Txn: ${client_txn_id}) from ${device.device_name}`);
    res.json({ status: "ok", client_txn_id: payment.client_txn_id });

  } catch (err) {
    console.error("Notify Error Detail:", err);
    res.status(500).json({ error: "Server error", message: err.message });
  }
});

// เริ่มต้น Server
app.listen(PORT, () => {
  console.log(`
🚀 iPay4U API is Running!
📡 Port: ${PORT}
🔐 Security: HMAC-SHA256 Enabled
⏱️ Sync Interval: 30 Minutes
  `);
});
