const SECRET_KEY = process.env.SECRET_KEY;
const express = require("express");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 3000;

// รับ JSON
app.use(bodyParser.json());

// ทดสอบว่า server ทำงาน
app.get("/", (req, res) => {
  res.send("ipay4u server is running");
});

// endpoint รับแจ้งเตือนจากแอป
app.post("/notify", (req, res) => {
  const clientKey = req.headers["x-secret-key"];

  if (clientKey !== SECRET_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  console.log("Payment notification received:");
  console.log(req.body);

  res.json({ status: "ok" });
});

// start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
