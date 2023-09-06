require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const MONGODB_URL = process.env.MONGO_DB_URL;
const app = express();
const userRouter = require("./routes/userApi");
const port = process.env.PORT || 3000;
const AccessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
mongoose
  .connect(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then((res) => console.log("connected to database"))
  .catch((e) => console.log("Error while connecting", e));

app.use(express.json()); // Middleware for parsing JSON request bodies
app.use(cookieParser()); // Use cookie-parser middleware
app.use("/user", userRouter);

const users = ["John Doe", "Jane Doe", "John Smith"];
// Middleware to check if the user is authenticated
const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const decoded = jwt.verify(token, AccessTokenSecret);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send("Unauthorized");
  }
};

app.get("/users", authenticateUser, (req, res) => {
  res.json(users);
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
