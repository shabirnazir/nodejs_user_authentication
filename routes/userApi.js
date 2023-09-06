// user.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const user = require("../Schemas/userSchema");

const router = express.Router();

// Middleware to check if the user is authenticated
const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send("Unauthorized");
  }
};

router.post("/register", async (req, res) => {
  try {
    // check if user already exists
    const dbUser = await user.findOne({ name: req.body.name });
    if (dbUser) {
      return res.status(400).send("User already exists");
    }
    // hash password
    const newUser = new user({
      name: req.body.name,
      password: req.body.password,
    });
    await newUser.save();
    res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

router.post("/login", async (req, res) => {
  try {
    const userData = await user.findOne({ name: req.body.name });
    if (!userData) {
      return res.status(400).send("Cannot find user");
    }
    // compare password
    const validPassword = await bcrypt.compare(
      req.body.password,
      userData.password
    );
    if (!validPassword) {
      return res.status(400).send("Cannot find user");
    }
    //save user data in req.user
    req.user = userData;

    // generate token
    const token = userData.generateAuthToken();
    // set cookie
    res.cookie("token", token, {
      httpOnly: true,
    });
    res.send("Logged in");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

router.post("/update", authenticateUser, async (req, res) => {
  try {
    const userData = await user.findById(req.user._id);
    if (!userData) {
      return res.status(400).send("Cannot find user");
    }
    // compare password
    const validPassword = await bcrypt.compare(
      req.body.password,
      userData.password
    );
    if (!validPassword) {
      return res.status(400).send("Cannot find user");
    }
    // update password
    userData.password = req.body.password;
    await userData.save();
    req.user = userData;
    const token = userData.generateAuthToken();
    res.cookie("token", token, {
      httpOnly: true,
    });
    res.send("Password updated");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

router.post("/logout", (req, res) => {
  // Remove the cookie
  res.cookie("token", "", {
    maxAge: 0,
  });
  res.send("Logged out");
});

module.exports = router;
