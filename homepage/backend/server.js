// FILENAME: backend/server.js

// --- IMPORTS AND CONFIGURATION ---
require('dotenv').config(); // Loads environment variables from a .env file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Used for hashing and comparing passwords securely
const fetch = require('node-fetch'); // Used for making HTTP requests (e.g., to GitHub's API)
const UAParser = require('ua-parser-js'); // Used to parse User-Agent strings

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors()); // Allows your frontend to make requests to this backend
app.use(express.json()); // Allows the server to understand JSON request bodies
app.set('trust proxy', true); // CRITICAL: This allows Express to get the correct IP address when hosted on Render.

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
    lastLoginAt: { type: Date, default: Date.now },
    // --- METADATA FIELDS ---
    lastLoginIp: { type: String },
    lastUserAgent: { type: String },
    location: { type: String }, // e.g., "City, Country"
    device: { type: String },   // e.g., "iPhone" or "Desktop"
    os: { type: String },       // e.g., "Windows 10"
    browser: { type: String },  // e.g., "Chrome"
    githubPat: { type: String }, // Stores the user's GitHub Personal Access Token
}, { timestamps: true }); // Automatically adds createdAt and updatedAt fields

const User = mongoose.model('User', UserSchema);

// --- HELPER FUNCTION TO CREATE A SAFE USER OBJECT (removes password) ---
const toSafeUserObject = (user) => {
    if (!user) return null;
    const userObj = user.toObject ? user.toObject() : { ...user };
    delete userObj.password;
    return userObj;
};

// --- HELPER FUNCTION TO UPDATE LOGIN METADATA ---
// This function captures user metadata on every successful login.
const updateLoginDetails = async (user, req) => {
    const ip = req.ip; 
    const uaString = req.headers['user-agent'];

    user.lastLoginAt = new Date();
    user.lastLoginIp = ip;
    user.lastUserAgent = uaString;

    // Parse the User-Agent string for device, OS, and browser info
    if (uaString) {
        const parser = new UAParser(uaString);
        const result = parser.getResult();
        user.os = result.os.name && result.os.version ? `${result.os.name} ${result.os.version}` : (result.os.name || 'N/A');
        user.browser = result.browser.name && result.browser.version ? `${result.browser.name} ${result.browser.version}` : (result.browser.name || 'N/A');
        user.device = result.device.vendor ? `${result.device.vendor} ${result.device.model}` : 'Desktop';
    }

    // Fetch Geo-Location from IP address using a free service
    try {
        if (ip && ip !== '::1' && ip !== '127.0.0.1') { // Don't lookup localhost IPs
            const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,city,country`);
            const geoData = await geoResponse.json();
            if (geoData.status === 'success') {
                user.location = `${geoData.city}, ${geoData.country}`;
            }
        }
    } catch (geoError) {
        console.error("Could not fetch geolocation for IP:", ip, geoError);
        user.location = 'Unavailable';
    }

    await user.save();
};

// --- HELPER FUNCTION FOR SOCIAL LOGINS ---
const findOrCreateUser = async (profile, req) => {
    let user = await User.findOne({ email: profile.email });
    if (user) {
        if (!user.loginMethod.includes(profile.loginMethod)) {
            user.loginMethod += `, ${profile.loginMethod}`;
        }
        user.picture = profile.picture || user.picture;
    } else {
        user = new User(profile);
    }
    await updateLoginDetails(user, req); // Use the helper to update metadata
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
        const newUser = new User({ name, email, password: hashedPassword, loginMethod: 'manual' });
        
        await updateLoginDetails(newUser, req); // Capture metadata on registration
        res.status(201).json(toSafeUserObject(newUser));
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// --- API: Manual User Login ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.loginMethod !== 'manual') return res.status(400).json({ message: 'Invalid credentials or not a manual account.' });
        if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Invalid credentials.' });
        
        await updateLoginDetails(user, req); // Capture metadata on login
        res.status(200).json(toSafeUserObject(user));
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- API: Social Login (for Google & Facebook) ---
app.post('/api/social-login', async (req, res) => {
    try {
        const { name, email, loginMethod, picture } = req.body;
        const user = await findOrCreateUser({ name, email, loginMethod, picture }, req);
        res.status(200).json(toSafeUserObject(user));
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
            body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code }),
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
        }, req);
        
        const sessionData = Buffer.from(JSON.stringify(toSafeUserObject(user))).toString('base64');
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

// --- API: Update User's GitHub PAT ---
app.put('/api/user/pat', async (req, res) => {
    const userEmail = req.headers['x-user-email'];
    const { pat } = req.body;

    if (!userEmail) return res.status(401).json({ message: 'Unauthorized.' });
    if (typeof pat !== 'string') return res.status(400).json({ message: 'PAT must be a string.' });

    try {
        const updatedUser = await User.findOneAndUpdate(
            { email: userEmail },
            { $set: { githubPat: pat } },
            { new: true } // Return the updated document
        );

        if (!updatedUser) return res.status(404).json({ message: 'User not found.' });
        
        res.status(200).json(toSafeUserObject(updatedUser)); // Send back the updated user object
    } catch (error) {
        console.error('Error updating PAT:', error);
        res.status(500).json({ message: 'Server error while updating PAT.' });
    }
});


// --- ADMIN API: Get All Users ---
app.get('/api/users', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        const users = await User.find({ email: { $ne: process.env.ADMIN_EMAIL } }).sort({ lastLoginAt: -1 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users.' });
    }
});

// --- ADMIN API: Delete a User ---
app.delete('/api/users/:id', async (req, res) => {
    if (req.headers['x-user-email'] !== process.env.ADMIN_EMAIL) {
        return res.status(403).json({ message: 'Forbidden: Admin access only.' });
    }
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid user ID format.' });
        if (!await User.findByIdAndDelete(req.params.id)) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json({ message: 'User deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error while deleting user.' });
    }
});

// --- SERVER STARTUP ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
