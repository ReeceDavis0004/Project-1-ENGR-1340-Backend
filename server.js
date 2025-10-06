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

app.listen(port, () => {
	console.log(`Server running on http://localhost:${port}`);
})