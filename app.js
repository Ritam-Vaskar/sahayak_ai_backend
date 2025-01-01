const express = require('express');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes');
const connectDB = require('./config/db');
require('./config/db');
require('dotenv').config(); 

const app = express();

connectDB();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/api/auth', authRoutes);

module.exports = app;
