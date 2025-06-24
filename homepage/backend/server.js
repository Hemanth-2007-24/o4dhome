// FILENAME: backend/server.js

// --- 1. SETUP AND IMPORTS ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.set('trust proxy', true); // Essential for getting user's IP address on Render

// --- 3. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- 4. USER DATABASE SCHEMA ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    loginMethod: { type: String, required: true, default: 'manual' },
    bio: { type: String, default: '' },
    picture: { type: String },
    lastLoginAt: { type: Date, default: Date.now },
    lastLoginIp: { type: String },
    lastUserAgent: { type: String },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// --- 5. HELPER FUNCTION ---
const findOrCreateUser = async (profile, req) => {
    let user = await User.findOne({ email: profile.email });
    if (user) {
        if (!user.loginMethod.includes(profile.loginMethod)) user.loginMethod += `, ${profile.loginMethod}`;
        user.picture = profile.picture || user.picture;
    } else {
        user = new User(profile);
    }
    user.lastLoginAt = new Date();
    if (req) {
        user.lastLoginIp = req.ip;
        user.lastUserAgent = req.headers['user-agent'];
    }
    await user.save();
    return user;
};

// --- 6. AUTHENTICATION & USER ROUTES ---

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, loginMethod: 'manual' });
        res.status(201).json(await newUser.save());
    } catch (error) { res.status(500).json({ message: 'Server error during registration.' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.loginMethod !== 'manual') return res.status(400).json({ message: 'Invalid credentials or not a manual account.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        user.lastLoginAt = new Date();
        user.lastLoginIp = req.ip;
        user.lastUserAgent = req.headers['user-agent'];
        res.status(200).json(await user.save());
    } catch (error) { res.status(500).json({ message: 'Server error during login.' }); }
});

app.post('/api/social-login', async (req, res) => {
    try {
        res.status(200).json(await findOrCreateUser(req.body, req));
    } catch (error) { res.status(500).json({ message: 'Server error during social login.' }); }
});

app.get('/api/github/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect(`${process.env.FRONTEND_URL}/index.html?error=github_no_code`);
    try {
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code }),
        });
        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;
        if (!accessToken) throw new Error('Could not get access token.');
        const userResponse = await fetch('https://api.github.com/user', { headers: { 'Authorization': `token ${accessToken}` } });
        const githubUser = await userResponse.json();
        const emailResponse = await fetch('https://api.github.com/user/emails', { headers: { 'Authorization': `token ${accessToken}` } });
        const emails = await emailResponse.json();
        const primaryEmail = emails.find(e => e.primary && e.verified).email;
        if (!primaryEmail) throw new Error('Could not get verified email.');
        const user = await findOrCreateUser({ name: githubUser.name || githubUser.login, email: primaryEmail, loginMethod: 'github', picture: githubUser.avatar_url }, req);
        const sessionData = Buffer.from(JSON.stringify(user)).toString('base64');
        res.redirect(`${process.env.FRONTEND_URL}/index.html?session=${sessionData}`);
    } catch (error) { res.redirect(`${process.env.FRONTEND_URL}/index.html?error=github_failed`); }
});

app.put('/api/profile', async (req, res) => {
    const userEmail = req.headers['x-user-email'];
    const { name, bio, picture } = req.body;
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized.' });
    try {
        const updateData = { name: name.trim(), bio: bio.trim() };
        if (picture) updateData.picture = picture;
        const updatedUser = await User.findOneAndUpdate({ email: userEmail }, { $set: updateData }, { new: true });
        if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json(updatedUser);
    } catch (error) { res.status(500).json({ message: 'Server error while updating profile.' }); }
});


// --- 7. ADMIN-SPECIFIC ROUTES ---

app.get('/api/users', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    try {
        res.json(await User.find({ email: { $ne: process.env.ADMIN_EMAIL } }).sort({ createdAt: -1 }));
    } catch (error) { res.status(500).json({ message: 'Failed to fetch users.' }); }
});

app.delete('/api/users/:id', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json({ message: 'User deleted successfully.' });
    } catch (error) { res.status(500).json({ message: 'Server error while deleting user.' }); }
});


// --- 8. START THE SERVER ---
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));