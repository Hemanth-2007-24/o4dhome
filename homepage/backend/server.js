// FILENAME: backend/server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = a = require('cors');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch'); // Use node-fetch v2

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(express.json()); // To parse JSON bodies

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- User Schema and Model ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Not required for social logins
    loginMethod: { type: String, required: true, default: 'manual' },
    bio: { type: String, default: '' },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// --- Helper Functions ---
const findOrCreateUser = async (profile) => {
    let user = await User.findOne({ email: profile.email });
    if (user) {
        // If user exists but used a different social login, update the method
        if (!user.loginMethod.includes(profile.loginMethod)) {
            user.loginMethod += `, ${profile.loginMethod}`;
            await user.save();
        }
        return user;
    }
    // If user does not exist, create a new one
    const newUser = new User({
        name: profile.name,
        email: profile.email,
        loginMethod: profile.loginMethod,
    });
    await newUser.save();
    return newUser;
};

// --- API Routes ---

// POST /api/register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, loginMethod: 'manual' });
        await newUser.save();
        res.status(201).json({ name: newUser.name, email: newUser.email, bio: newUser.bio });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.loginMethod !== 'manual') {
            return res.status(400).json({ message: 'Invalid credentials or not a manual account.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }
        res.status(200).json({ name: user.name, email: user.email, bio: user.bio });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// POST /api/social-login
app.post('/api/social-login', async (req, res) => {
    try {
        const { name, email, loginMethod } = req.body;
        const user = await findOrCreateUser({ name, email, loginMethod });
        res.status(200).json({ name: user.name, email: user.email, bio: user.bio });
    } catch (error) {
        res.status(500).json({ message: 'Server error during social login.' });
    }
});

// GET /api/github/callback - GitHub OAuth Flow
app.get('/api/github/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        return res.status(400).send('Error: No code received from GitHub');
    }
    try {
        // 1. Exchange code for an access token
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

        // 2. Use the access token to get user info
        const userResponse = await fetch('https://api.github.com/user', {
            headers: { 'Authorization': `token ${accessToken}` }
        });
        const githubUser = await userResponse.json();

        // 3. Get user's primary email
        const emailResponse = await fetch('https://api.github.com/user/emails', {
            headers: { 'Authorization': `token ${accessToken}` }
        });
        const emails = await emailResponse.json();
        const primaryEmail = emails.find(e => e.primary && e.verified).email;

        if (!primaryEmail) {
            return res.status(400).send('Could not retrieve a verified primary email from GitHub.');
        }

        // 4. Find or create the user in our database
        const user = await findOrCreateUser({
            name: githubUser.name || githubUser.login,
            email: primaryEmail,
            loginMethod: 'github'
        });

        // 5. Redirect to frontend with user data encoded in the URL
        const sessionData = Buffer.from(JSON.stringify({
             name: user.name,
             email: user.email,
             bio: user.bio
        })).toString('base64');

        res.redirect(`${process.env.FRONTEND_URL}/index.html?session=${sessionData}#auth`);

    } catch (error) {
        console.error('GitHub auth error:', error);
        res.status(500).send('An error occurred during GitHub authentication.');
    }
});


// GET /api/users (Admin Only)
app.get('/api/users', async (req, res) => {
    // Basic auth check - for a real app, use JWT or a more secure session management
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


// PUT /api/profile (Authenticated Users)
app.put('/api/profile', async (req, res) => {
    const userEmail = req.headers['x-user-email'];
    const { name, bio } = req.body;
    
    if (!userEmail) {
        return res.status(401).json({ message: 'Unauthorized: User email header missing.' });
    }
    
    try {
        const updatedUser = await User.findOneAndUpdate(
            { email: userEmail },
            { $set: { name: name.trim(), bio: bio.trim() } },
            { new: true, select: '-password' } // `new: true` returns the updated doc
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }
        
        res.status(200).json(updatedUser);

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error while updating profile.' });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});