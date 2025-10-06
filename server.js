const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const url = require('url');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const env = require('dotenv').config().parsed;

const app = express();
const port = 3001;

const JWT_SECRET = 'reeces_super_secret_token';
const FRONTEND_URL = "http://localhost:3000";

// Microsoft OAuth Details
const AZURE_CONFIG = {
	CLIENT_ID: env.CLIENT_ID,
	TENANT_ID: env.TENANT_ID,
	CLIENT_SECRET: env.CLIENT_SECRET,
	REDIRECT_URI: "http://localhost:3001/redirect",
	AUTHORITY: env.AUTHORITY,
	SCOPES: "openid profile email User.Read"
};

// Database Configuration
const dbConfig = {
	host: 'localhost',
	user: env.DB_USERNAME,
	password: env.DB_PASSWORD,
	database: 'raider_connect'
};

app.use(cors());
app.use(express.json());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
	fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, uploadDir)
	},
	filename: function (req, file, cb) {
		// Create a unique filename to avoid overwrites
		cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
	}
});

const upload = multer({
	storage: storage,
	limits: {
		fileSize: 5 * 1024 * 1024 // 5MB
	},
	fileFilter: (req, file, cb) => {
		const filetypes = /jpeg|jpg|png/;
		const mimetype = filetypes.test(file.mimetype);
		const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
		if (mimetype && extname) {
			return cb(null, true);
		}
		cb(new Error("Error: File upload only supports the following filetypes - " + filetypes));
	}
});

let connection;

async function initializeDb() {
	try {
		connection = await mysql.createPool(dbConfig);
		console.log('Successfully connected to the database.');
	} catch (error) {
		console.error('Error connecting to the database:', error);
		process.exit(1);
	}
}

const verifyToken = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) return res.status(401).json({ error: 'A token is required for authentication' });

	try {
		req.user = jwt.verify(token, JWT_SECRET);
	} catch (err) {
		return res.status(403).json({ error: 'Invalid Token' });
	}
	return next();
};

app.listen(port, () => {
	console.log(`Server running on http://localhost:${port}`);
})