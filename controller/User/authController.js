const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const transporter = require('../../utils/mailer');
const User = require('../../model/User/userModel');
const { JWT_SECRET } = require('../../config/jwtConfig');

exports.signup = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
        const verificationUrl = `http://localhost:5000/api/auth/verify/${token}`;

        await transporter.sendMail({
            to: email,
            subject: 'Email Verification',
            text: `Click the link to verify your email: ${verificationUrl}`,
        });

        res.status(201).json({ message: 'User registered. Please verify your email.' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error.' });
    }
};

exports.verifyEmail = async (req, res) => {
    const { token } = req.params;

    try {
        const { email } = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'Invalid token or user not found.' });
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully.' });
    } catch (error) {
        res.status(400).json({ error: 'Token is invalid or expired.' });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ error: 'Email not verified.' });
        }

        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });

        res.cookie('access_token', token, {
            httpOnly: true,
            secure: true,
        }).status(200).json({ message: 'Login successful.' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error.' });
    }
};
