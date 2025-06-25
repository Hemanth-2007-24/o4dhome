// FILENAME: backend/server.js

// --- IMPORTS AND CONFIGURATION ---
require('dotenv').config(); // Loads environment variables from a .env file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Used for hashing and comparing passwords securely
const fetch = require('node-fetch'); // Used for making HTTP requests (e.g., to GitHub's API)

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors()); // Allows your frontend to make requests to this backend
app.use(express.json()); // Allows the server to understand JSON request bodies

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- USER MONGOOSE SCHEMA & MODEL ---
// This defines the structure for all user documents in the database.
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Optional: Not present for social logins
    loginMethod: { type: String, required: true, default: 'manual' },
    bio: { type: String, default: '' },
    picture: { type: String }, // URL to the user's avatar
    lastLoginAt: { type: Date, default: Date.now }, // Tracks user activity
}, { timestamps: true }); // Automatically adds createdAt and updatedAt fields

const User = mongoose.model('User', UserSchema);

// --- HELPER FUNCTION FOR SOCIAL LOGINS ---
// This function finds an existing user or creates a new one for social logins.
const findOrCreateUser = async (profile) => {
    let user = await User.findOne({ email: profile.email });
    
    if (user) {
        // If user exists, update their details
        if (!user.loginMethod.includes(profile.loginMethod)) {
            user.loginMethod += `, ${profile.loginMethod}`; // Add new login method if different
        }
        user.picture = profile.picture || user.picture; // Update picture if a new one is provided
    } else {
        // If user does not exist, create a new one from the profile data
        user = new User(profile);
    }

    // For both existing and new users, update the last login time
    user.lastLoginAt = new Date();
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
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        if (await User.findOne({ email })) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        // Hash the password for security before saving it
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ 
            name, 
            email, 
            password: hashedPassword, 
            loginMethod: 'manual',
            lastLoginAt: new Date()
        });
        await newUser.save();
        res.status(201).json({ name: newUser.name, email: newUser.email, bio: newUser.bio, picture: newUser.picture });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// --- API: Manual User Login ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.loginMethod !== 'manual') {
            return res.status(400).json({ message: 'Invalid credentials or not a manual account.' });
        }
        // Compare the provided password with the hashed password in the database
        if (!await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        user.lastLoginAt = new Date();
        await user.save();
        res.status(200).json({ name: user.name, email: user.email, bio: user.bio, picture: user.picture });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- API: Social Login (for Google & Facebook) ---
app.post('/api/social-login', async (req, res) => {
    try {
        const { name, email, loginMethod, picture } = req.body;
        const user = await findOrCreateUser({ name, email, loginMethod, picture });
        res.status(200).json({ name: user.name, email: user.email, bio: user.bio, picture: user.picture });
    } catch (error) {
        res.status(500).json({ message: 'Server error during social login.' });
    }
});

// --- API: GitHub OAuth Server-Side Callback ---
app.get('/api/github/callback', async (req, res) => {
    const { code } = req.query;
    try {
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code,
            }),
        });
        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;
        
        const userResponse = await fetch('https://api.github.com/user', { headers: { 'Authorization': `token ${accessToken}` } });
        const githubUser = await userResponse.json();
        
        const emailResponse = await fetch('https://api.github.com/user/emails', { headers: { 'Authorization': `token ${accessToken}` } });
        const emails = await emailResponse.json();
        const primaryEmail = emails.find(e => e.primary && e.verified).email;

        if (!primaryEmail) throw new Error('Could not retrieve a verified primary email from GitHub.');

        const user = await findOrCreateUser({
            name: githubUser.name || githubUser.login,
            email: primaryEmail,
            loginMethod: 'github',
            picture: githubUser.avatar_url,
        });
        
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
        if (picture) updateData.picture = picture; // Only update picture if provided

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


// --- SERVER STARTUP ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
