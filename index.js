const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ===== ENV =====
const SECRET_KEY = process.env.SECRET_KEY; // ตัวนี้อาจเก็บไว้ใช้สำหรับระบบอื่น หรือใช้คู่กับ Fingerprint
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ===== MIDDLEWARE: เก็บ Raw Body สำหรับ Verify Signature =====
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

app.get("/", (_, res) => res.send("iPay4U API: Android Optimized Version"));

// =====================================================
// 🔐 REGISTER DEVICE (Using Fingerprint)
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
        status: "active"
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
// 🔔 NOTIFY (Using Bearer Token & client_txn_id)
// =====================================================
app.post("/notify", async (req, res) => {
  try {
    // ดึง Token จาก Bearer Token
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

    if (deviceError || !device) return res.status(403).json({ error: "Invalid device" });

    // Verify Signature: rawBody + timestamp + nonce
    const expectedSignature = crypto
      .createHmac("sha256", deviceToken)
      .update(req.rawBody + timestamp + nonce)
      .digest("hex");

    if (expectedSignature !== signature) {
      console.log("Signature Mismatch!");
      return res.status(401).json({ error: "Invalid signature" });
    }

    const { client_txn_id, bank, amount, title, message } = req.body;

    if (!client_txn_id || amount === undefined) {
      return res.status(400).json({ error: "Missing transaction data" });
    }

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

    if (insertError && insertError.code === "23505") {
      return res.json({ status: "duplicate_ignored", client_txn_id });
    }

    if (insertError) throw insertError;

    console.log(`💰 Success: ${amount} THB (Txn: ${client_txn_id})`);
    res.json({ status: "ok", client_txn_id: payment.client_txn_id });

  } catch (err) {
    console.error("Notify Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => console.log(`🚀 API Running on port ${PORT}`));
