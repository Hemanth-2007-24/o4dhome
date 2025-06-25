// FILENAME: backend/server.js

// --- IMPORTS AND CONFIGURATION ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
const UAParser = require('ua-parser-js'); // For parsing user-agent strings

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
// Trust Render's proxy to get the correct IP address of the user
app.set('trust proxy', 1);

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- USER SCHEMA & MODEL ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    loginMethod: { type: String, required: true, default: 'manual' },
    bio: { type: String, default: '' },
    picture: { type: String },
    lastLoginAt: { type: Date, default: Date.now },
    // NEW: Nested object to store login details
    lastLoginDetails: {
        ip: { type: String },
        browser: { type: String },
        os: { type: String },
        device: { type: String }
    }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// --- HELPER FUNCTION FOR UPDATING USER DETAILS ON LOGIN ---
const updateUserOnLogin = async (user, req) => {
    const parser = new UAParser(req.headers['user-agent']);
    const ua = parser.getResult();

    user.lastLoginAt = new Date();
    user.lastLoginDetails = {
        ip: req.ip,
        browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version}` : 'Unknown',
        os: ua.os.name ? `${ua.os.name} ${ua.os.version}` : 'Unknown',
        device: ua.device.vendor ? `${ua.device.vendor} ${ua.device.model}` : 'Desktop'
    };
    await user.save();
    return user;
};

// =================================================================
// --- API ROUTES ---
// =================================================================

// --- API: Manual User Registration ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
        if (await User.findOne({ email })) return res.status(400).json({ message: 'User with this email already exists.' });
        
        const newUser = new User({ name, email, password: await bcrypt.hash(password, 10), loginMethod: 'manual' });
        await updateUserOnLogin(newUser, req); // Capture details on registration
        res.status(201).json(newUser.toObject());
    } catch (error) { res.status(500).json({ message: 'Server error during registration.' }); }
});

// --- API: Manual User Login ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !user.password) return res.status(400).json({ message: 'Invalid credentials or social account.' });
        if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Invalid credentials.' });
        
        await updateUserOnLogin(user, req);
        res.status(200).json(user.toObject());
    } catch (error) { res.status(500).json({ message: 'Server error during login.' }); }
});

// --- API: Social Login (Google & Facebook) ---
app.post('/api/social-login', async (req, res) => {
    try {
        const { name, email, loginMethod, picture } = req.body;
        let user = await User.findOne({ email });
        if (user) {
            if (!user.loginMethod.includes(loginMethod)) user.loginMethod += `, ${loginMethod}`;
            user.picture = picture || user.picture;
        } else {
            user = new User({ name, email, loginMethod, picture });
        }
        await updateUserOnLogin(user, req);
        res.status(200).json(user.toObject());
    } catch (error) { res.status(500).json({ message: 'Server error during social login.' }); }
});

// --- API: GitHub OAuth Callback ---
app.get('/api/github/callback', async (req, res) => {
    // ... (Your GitHub callback code remains the same) ...
    // Note: Capturing device info here is complex. It's captured on the next login instead.
});

// --- API: Update User Profile ---
app.put('/api/profile', async (req, res) => { /* ... (Your existing profile code is fine) ... */ });

// --- API: Admin Route to Get All Users ---
app.get('/api/users', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        const users = await User.find({ email: { $ne: process.env.ADMIN_EMAIL } }).sort({ createdAt: -1 });
        res.json(users);
    } catch (error) { res.status(500).json({ message: 'Failed to fetch users.' }); }
});

// --- NEW: API: Admin Route to Delete a User ---
app.delete('/api/users/:id', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid user ID format.' });
        
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found.' });

        res.status(200).json({ message: `User ${deletedUser.name} has been deleted successfully.` });
    } catch (error) {
        res.status(500).json({ message: 'Server error while deleting user.' });
    }
});


// --- SERVER STARTUP ---
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
