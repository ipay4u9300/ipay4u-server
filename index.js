const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== 1. การตั้งค่า SUPABASE =====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== 2. MIDDLEWARE =====
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString(); // เก็บข้อมูลดิบไว้สำหรับตรวจสอบ Signature
  }
}));

// ===== 3. HEALTH CHECK =====
app.get("/", (_, res) => res.send("iPay4U Central Control API is running"));

// =====================================================
// 🔐 REGISTER DEVICE (ใช้ Fingerprint)
// =====================================================
app.post("/register", async (req, res) => {
  try {
    const fingerprint = req.headers["x-device-fingerprint"];
    if (!fingerprint) return res.status(403).json({ error: "Forbidden: Missing Fingerprint" });

    const { device_id, device_name } = req.body;
    if (!device_id || !device_name) return res.status(400).json({ error: "Missing data" });

    const deviceToken = crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
      .from("devices")
      .upsert({
        device_id,
        device_name,
        device_token: deviceToken,
        status: "active" // ค่าเริ่มต้นเป็น active
      }, { onConflict: 'device_id' })
      .select().single();

    if (error) throw error;
    res.json({ device_token: data.device_token });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================================
// 🔔 NOTIFY (ตรวจสอบสิทธิ์เครื่องก่อนบันทึก)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    // 1. ดึง Token จาก Authorization Header (Bearer Token)
    const authHeader = req.headers["authorization"];
    const deviceToken = authHeader ? authHeader.split(" ")[1] : null;
    
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const signature = req.headers["x-signature"];

    if (!deviceToken || !signature) return res.status(401).json({ error: "Unauthorized" });

    // 2. ตรวจสอบ Device และ "สถานะการอนุญาต"
    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();

    if (deviceError || !device) {
      return res.status(403).json({ error: "Invalid device" });
    }

    // 🚀 จุดควบคุมหลัก: เช็คว่าเครื่องนี้ถูก "สั่งหยุด" หรือไม่
    if (device.status !== "active") {
      console.log(`🚫 Blocked: Transaction from disabled device (${device.device_name})`);
      return res.status(403).json({ error: "This device has been disabled by administrator" });
    }

    // 3. ตรวจสอบความถูกต้องของข้อมูล (Signature)
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      console.log("❌ Signature Mismatch!");
      return res.status(401).json({ error: "Invalid signature" });
    }

    // 4. รับข้อมูลที่ Android ส่งมา
    const { client_txn_id, bank, amount, title, message } = req.body;

    if (!client_txn_id || amount === undefined) {
      return res.status(400).json({ error: "Missing transaction data" });
    }

    // 5. บันทึกลง Supabase
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

    // ดักจับกรณีส่งข้อมูลซ้ำ (Duplicate client_txn_id)
    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored", client_txn_id });
    }

    if (insertError) throw insertError;

    console.log(`💰 ได้รับเงิน: ${amount} THB (Txn: ${client_txn_id}) จากเครื่อง: ${device.device_name}`);
    res.json({ status: "ok", client_txn_id: payment.client_txn_id });

  } catch (err) {
    console.error("Notify Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => console.log(`🚀 Centralized API running on port ${PORT}`));
