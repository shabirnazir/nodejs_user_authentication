require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
const port = 3000;
const AccessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
app.use(express.json()); // Middleware for parsing JSON request bodies
app.use(cookieParser()); // Use cookie-parser middleware
const users = [];
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

app.post("/register", async (req, res) => {
  try {
    console.log("hit", req.body);
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { name: req.body.name, password: hashedPassword };
    users.push(user);
    res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});
app.post("/login", async (req, res) => {
  const user = users.find((user) => user.name === req.body.name);
  if (!user) {
    return res.status(400).send("Cannot find user");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // Create a JWT token
      const token = jwt.sign({ name: user.name }, AccessTokenSecret, {
        expiresIn: "1h", // Token expiration time
      });
      console.log(token);
      // Set the token as a cookie
      res.cookie("token", token, {
        httpOnly: true,
        maxAge: 3600000, // 1 hour in milliseconds
      });

      res.send("Login successful");
    } else {
      res.status(403).send("Access Denied");
    }
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

app.post("/logout", (req, res) => {
  // Remove the cookie
  res.cookie("token", "", {
    maxAge: 0,
  });
  res.send("Logged out");
});
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
