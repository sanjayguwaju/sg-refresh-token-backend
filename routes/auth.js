const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Register route
router.post('/register', async (req, res) => {
  // Check if user already exists
  const existingUser = await User.findOne({ username: req.body.username });
  if (existingUser) return res.status(400).send('Username already exists');

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // Create new user
  const user = new User({
    username: req.body.username,
    password: hashedPassword
  });

  try {
    // Save user in the database
    const savedUser = await user.save();
    res.send(savedUser);
  } catch (err) {
    // Error handling
    res.status(400).send(err);
  }
});

// Login route
router.post('/login', async (req, res) => {
  // Find the user
  const user = await User.findOne({ username: req.body.username });
  
  // Check password
  const validPassword = await bcrypt.compare(req.body.password, user.password);
  
  if (!validPassword) return res.status(400).send('Invalid username or password');

  // Create tokens
  const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET);

  // Update refresh token
  user.refreshToken = refreshToken;
  await user.save();

  // Send tokens
  res.cookie('refreshToken', refreshToken, { httpOnly: true });
  res.json({ accessToken });
});

// Refresh token route
router.post('/token', async (req, res) => {
  // Get refresh token
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.sendStatus(401);

  // Verify refresh token
  let userId;
  try {
    const verified = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    userId = verified.userId;
  } catch {
    return res.sendStatus(403);
  }

  // Check if refresh token exists in database
  const user = await User.findById(userId);
  if (!user || user.refreshToken !== refreshToken) return res.sendStatus(403);

  // Create new tokens
  const newAccessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
  const newRefreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET);

  // Update refresh token in database
  user.refreshToken = newRefreshToken;
  await user.save();

  // Send tokens
  res.cookie('refreshToken', newRefreshToken, { httpOnly: true });
  res.json({ accessToken: newAccessToken });
});

// Logout route
router.post('/logout', async (req, res) => {
  // Get user from access token
  const accessToken = req.headers.authorization.split(' ')[1];
  const { userId } = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

  // Find user
  const user = await User.findById(userId);
  if (!user) return res.sendStatus(404);

  // Remove refresh token
  user.refreshToken = null;
  await user.save();

  // Clear cookie
  res.clearCookie('refreshToken');

  res.sendStatus(204); // Success with no content to send
});

module.exports = router;