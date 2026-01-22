const express = require("express");
const bodyParser = require("body-parser");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

// ENV
const SECRET_KEY = process.env.SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// ตรวจ ENV
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ Missing Supabase ENV");
  process.exit(1);
}

// Supabase client
const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);

app.use(bodyParser.json());

// health check
app.get("/", (req, res) => {
  res.send("ipay4u server is running");
});

// notify endpoint
app.post("/notify", async (req, res) => {
  try {
    const clientKey = req.headers["x-secret-key"];

    if (clientKey !== SECRET_KEY) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { bank, amount, title, message } = req.body;

    if (!bank || !amount) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const { data, error } = await supabase
      .from("payments")
      .insert([
        { bank, amount, title, message }
      ])
      .select();

    if (error) {
      console.error("❌ Supabase insert error:", error);
      return res.status(500).json({ error: "DB insert failed" });
    }

    res.json({ status: "ok", data });
  } catch (err) {
    console.error("❌ Server error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
