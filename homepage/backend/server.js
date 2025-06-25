// FILENAME: backend/server.js

// =================================================================
// --- IMPORTS AND CONFIGURATION ---
// =================================================================
require('dotenv').config(); // Loads environment variables from a .env file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Used for hashing and comparing passwords securely
const fetch = require('node-fetch'); // Used for making HTTP requests to social providers
const UAParser = require('ua-parser-js'); // Used to parse device information from the user-agent string

const app = express();
// This uses the port Render provides via the PORT environment variable, or defaults to 3000 for local development.
const PORT = process.env.PORT || 3000;

// =================================================================
// --- MIDDLEWARE ---
// =================================================================
app.use(cors()); // Allows your frontend (on a different domain) to make requests to this backend
app.use(express.json()); // Allows the server to understand JSON request bodies
// This setting is CRUCIAL for getting the user's real IP address when deployed on Render.
app.set('trust proxy', 1);

// =================================================================
// --- DATABASE CONNECTION ---
// =================================================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// =================================================================
// --- USER MONGOOSE SCHEMA & MODEL ---
// =================================================================
// This defines the structure for all user documents in the 'users' collection.
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Optional: Not present for initial social logins
    loginMethod: { type: String, required: true, default: 'manual' },
    bio: { type: String, default: '' },
    picture: { type: String }, // URL to the user's avatar
    lastLoginAt: { type: Date, default: Date.now },
    // A nested object to store detailed information about the user's last login session
    lastLoginDetails: {
        ip: { type: String },
        browser: { type: String },
        os: { type: String },
        device: { type: String }
    }
}, { timestamps: true }); // Automatically adds `createdAt` and `updatedAt` fields

const User = mongoose.model('User', UserSchema);

// =================================================================
// --- HELPER FUNCTION ---
// =================================================================
// This function updates a user's activity and device info upon every login.
const updateUserOnLogin = async (user, req) => {
    const parser = new UAParser(req.headers['user-agent']);
    const ua = parser.getResult();

    user.lastLoginAt = new Date();
    user.lastLoginDetails = {
        ip: req.ip, // Express gets the real IP thanks to the 'trust proxy' setting
        browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version}` : 'Unknown Browser',
        os: ua.os.name ? `${ua.os.name} ${ua.os.version}` : 'Unknown OS',
        // If the library can't identify a mobile device, we assume it's a Desktop.
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
        
        const hashedPassword = await bcrypt.hash(password, 10);
        let newUser = new User({ name, email, password: hashedPassword, loginMethod: 'manual' });
        
        // Capture device info on the very first login (registration)
        newUser = await updateUserOnLogin(newUser, req);
        
        res.status(201).json(newUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// --- API: Manual User Login ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !user.password) return res.status(400).json({ message: 'Invalid credentials or not a manual account.' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials.' });
        
        const updatedUser = await updateUserOnLogin(user, req);
        res.status(200).json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- API: Social Login (for Google & Facebook) ---
app.post('/api/social-login', async (req, res) => {
    try {
        const { name, email, loginMethod, picture } = req.body;
        let user = await User.findOne({ email });
        if (user) {
            user.picture = picture || user.picture;
            if (!user.loginMethod.includes(loginMethod)) user.loginMethod += `, ${loginMethod}`;
        } else {
            user = new User({ name, email, loginMethod, picture });
        }
        
        const updatedUser = await updateUserOnLogin(user, req);
        res.status(200).json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error during social login.' });
    }
});

// --- API: GitHub OAuth Server-Side Callback ---
app.get('/api/github/callback', async (req, res) => {
    // Note: The request here comes from GitHub's server, not the user's browser,
    // so we can't capture device info at this exact moment. It will be captured on the next login.
    const { code } = req.query;
    try {
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', { /* ... */ });
        const tokenData = await tokenResponse.json();
        // ... (rest of GitHub logic is fine)
        const user = await findOrCreateUser({ /* ... */ });
        const sessionData = Buffer.from(JSON.stringify(user.toObject())).toString('base64');
        res.redirect(`${process.env.FRONTEND_URL}/index.html?session=${sessionData}`);
    } catch (error) {
        console.error('GitHub auth error:', error);
        res.redirect(`${process.env.FRONTEND_URL}/index.html?error=github_failed`);
    }
});

// --- API: Update User Profile ---
app.put('/api/profile', async (req, res) => {
    const userEmail = req.headers['x-user-email'];
    const { name, bio, picture } = req.body;
    if (!userEmail) return res.status(401).json({ message: 'Unauthorized.' });
    
    try {
        const updateData = { name: name.trim(), bio: bio.trim() };
        if (picture) updateData.picture = picture;
        const updatedUser = await User.findOneAndUpdate({ email: userEmail }, { $set: updateData }, { new: true, select: '-password' });
        if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error while updating profile.' });
    }
});

// --- API: Admin Route to Get All Users ---
app.get('/api/users', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        const users = await User.find({ email: { $ne: process.env.ADMIN_EMAIL } }).sort({ createdAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users.' });
    }
});

// --- API: Admin Route to Delete a User ---
app.delete('/api/users/:id', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        const { id } = req.params;
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json({ message: `User ${deletedUser.name} has been deleted successfully.` });
    } catch (error) {
        res.status(500).json({ message: 'Server error while deleting user.' });
    }
});

// =================================================================
// --- SERVER STARTUP ---
// =================================================================
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
