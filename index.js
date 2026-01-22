const express = require("express");
const bodyParser = require("body-parser");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY;

// 🔗 Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// รับ JSON
app.use(bodyParser.json());

// health check
app.get("/", (req, res) => {
  res.send("ipay4u server is running");
});

// webhook
app.post("/notify", async (req, res) => {
  const clientKey = req.headers["x-secret-key"];

  if (clientKey !== SECRET_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const data = req.body;

  try {
    await supabase.from("payments").insert({
      bank: data.bank,
      amount: data.amount,
      title: data.title,
      message: data.message,
      raw_payload: data
    });

    res.json({ status: "ok" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DB error" });
  }
});

// start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
