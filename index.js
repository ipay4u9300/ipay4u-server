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
  console.error("❌ Missing environment variables.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== 2. MIDDLEWARE =====
// เก็บ rawBody เพื่อใช้ตรวจสอบ Signature ให้แม่นยำ 100%
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// ===== 3. HEALTH CHECK =====
app.get("/", (_, res) => res.send("iPay4U Backend running with Lovable integration"));

// =====================================================
// 🔐 REGISTER DEVICE
// =====================================================
app.post("/register", async (req, res) => {
  try {
    const clientKey = req.headers["x-secret-key"];
    if (clientKey !== SECRET_KEY) return res.status(403).json({ error: "forbidden" });

    const { device_id, device_name } = req.body;
    if (!device_id || !device_name) return res.status(400).json({ error: "missing data" });

    const deviceToken = crypto.randomBytes(32).toString("hex");

    const { data, error } = await supabase
  .from("devices")
  .upsert({
    device_id,
    device_name,
    device_token: deviceToken,
    status: "active"
    // ลบบรรทัด updated_at ออก
  }, { onConflict: 'device_id' })
  .select()
  .single();

    if (error) throw error;
    res.json({ device_token: data.device_token });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "server error" });
  }
});

// =====================================================
// 🔔 NOTIFY (Mapping event_id -> client_txn_id)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    const clientKey = req.headers["x-secret-key"];
    if (clientKey !== SECRET_KEY) return res.status(403).json({ error: "forbidden" });

    const deviceToken = req.headers["x-device-token"];
    const timestamp = req.headers["x-timestamp"];
    const nonce = req.headers["x-nonce"];
    const signature = req.headers["x-signature"];

    // 1. ตรวจสอบ Device
    const { data: device, error: deviceError } = await supabase
      .from("devices")
      .select("*")
      .eq("device_token", deviceToken)
      .single();

    if (deviceError || !device) return res.status(403).json({ error: "invalid device" });

    // 2. Verify Signature
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      return res.status(401).json({ error: "invalid signature" });
    }

    // 3. รับค่าและ Mapping (ใช้ event_id แทนการสร้างใหม่)
    const {
      event_id, // รับค่านี้มาจาก Android
      bank,
      amount,
      title,
      message
    } = req.body;

    if (!event_id || amount === undefined) {
      return res.status(400).json({ error: "missing event_id or amount" });
    }

    // 4. บันทึกลง Supabase โดยให้ client_txn_id = event_id
    const { data: payment, error: insertError } = await supabase
      .from("payments")
      .insert([{
        client_txn_id: event_id, // ผูก event_id เข้ากับระบบเดิม
        bank,
        amount: parseFloat(amount),
        title,
        message,
        device_id: device.device_id,
        created_at: new Date()
      }])
      .select().single();

    // ดักจับ Duplicate (ถ้า event_id นี้เคยส่งมาแล้ว)
    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored", event_id });
    }

    if (insertError) throw insertError;

    console.log(`💰 Success: ${amount} THB (Event: ${event_id})`);
    res.json({ status: "ok", event_id: payment.client_txn_id });

  } catch (err) {
    console.error("Notify Error:", err.message);
    res.status(500).json({ error: "server error" });
  }
});

app.listen(PORT, () => console.log(`🚀 API Running on port ${PORT}`));
