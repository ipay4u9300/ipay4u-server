const express = require("express");
const bodyParser = require("body-parser");
const { createClient } = require("@supabase/supabase-js");

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 10000;

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const app = express();
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("ipay4u server is running");
});

app.post("/notify", async (req, res) => {
  const clientKey = req.headers["x-secret-key"];
  if (clientKey !== SECRET_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const data = req.body;
  console.log("Payment notification received:", data);

  const { error } = await supabase
    .from("payments")
    .insert({
      bank: data.bank,
      amount: data.amount,
      title: data.title,
      message: data.message
    });

  if (error) {
    console.error("Supabase insert error:", error);
    return res.status(500).json({ error: "DB insert failed" });
  }

  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
