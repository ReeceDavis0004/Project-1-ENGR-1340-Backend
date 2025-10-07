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





// API Requests






app.get('/redirect', async (req, res) => {
	const { code } = req.query;
	if (!code) {
		return res.status(400).send("Authorization code not provided.");
	}

	try {
		const tokenResponse = await axios.post(
			`${AZURE_CONFIG.AUTHORITY}/oauth2/v2.0/token`,
			new url.URLSearchParams({
				client_id: AZURE_CONFIG.CLIENT_ID,
				scope: AZURE_CONFIG.SCOPES,
				code: code,
				redirect_uri: AZURE_CONFIG.REDIRECT_URI,
				grant_type: 'authorization_code',
				client_secret: AZURE_CONFIG.CLIENT_SECRET,
			})
		);

		const accessToken = tokenResponse.data.access_token;

		const profileResponse = await axios.get('https://graph.microsoft.com/v1.0/me', {
			headers: { 'Authorization': `Bearer ${accessToken}` }
		});

		const { displayName, mail, id: microsoftOid } = profileResponse.data;

		let [rows] = await connection.execute('SELECT * FROM users WHERE microsoft_oid = ?', [microsoftOid]);
		let user = rows[0];

		if (!user) {
			const [userResult] = await connection.execute(
				'INSERT INTO users (name, email, account_type, microsoft_oid) VALUES (?, ?, ?, ?)',
				[displayName, mail, 'student', microsoftOid]
			);
			const userId = userResult.insertId;
			await connection.execute(
				'INSERT INTO student_profiles (user_id, profile_pic_url) VALUES (?, ?)',
				[userId, `https://placehold.co/150x150/3A3B3C/E4E6EB?text=${displayName.charAt(0)}`]
			);
			[rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [userId]);
			user = rows[0];
		}

		const appToken = jwt.sign(
			{ userId: user.id, name: user.name, email: user.email, accountType: user.account_type, companyId: null },
			JWT_SECRET,
			{ expiresIn: "2h" }
		);

		res.redirect(`${FRONTEND_URL}/auth/callback?token=${appToken}`);

	} catch (error) {
		console.error("Microsoft Auth Error:", error.response ? error.response.data : error.message);
		res.status(500).send("An error occurred during authentication.");
	}
});

app.post('/api/signup', async (req, res) => {
	const { name, email, password, accountType } = req.body;

	if (accountType !== 'company') {
		return res.status(400).json({ error: "This endpoint is for company signups only." });
	}

	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		const [companyResult] = await connection.execute(
			'INSERT INTO companies (name, logo_url) VALUES (?, ?)',
			[name, `https://placehold.co/150x150/ffffff/000000?text=${name.charAt(0)}`]
		);
		const companyId = companyResult.insertId;

		await connection.execute(
			'INSERT INTO users (name, email, password_hash, account_type, company_id) VALUES (?, ?, ?, ?, ?)',
			[`${name} Rep`, email, hashedPassword, 'company', companyId]
		);
		res.status(201).json({ message: "Company user created successfully" });
	} catch (error) {
		if (error.code === 'ER_DUP_ENTRY') {
			return res.status(409).json({ error: "User with this email already exists." });
		}
		res.status(500).json({ error: "An error occurred during registration." });
	}
});

app.post('/api/login', async (req, res) => {
	const { email, password, accountType } = req.body;

	if (accountType !== 'company') {
		return res.status(400).json({ error: "This endpoint is for company logins only. Students should use Microsoft login." });
	}
	try {
		const [rows] = await connection.execute('SELECT * FROM users WHERE email = ? AND account_type = ?', [email, accountType]);
		const user = rows[0];

		if (user && (await bcrypt.compare(password, user.password_hash))) {
			const token = jwt.sign(
				{ userId: user.id, name: user.name, email: user.email, accountType: user.account_type, companyId: user.company_id },
				JWT_SECRET,
				{ expiresIn: "2h" }
			);
			res.status(200).json({ token });
		} else {
			res.status(400).json({ error: "Invalid Credentials" });
		}
	} catch (error) {
		res.status(500).json({ error: 'An internal server error occurred.' });
	}
});


app.get('/api/students', async (req, res) => {
	const [rows] = await connection.execute(`
        SELECT u.id, u.name, p.major, p.year, p.skills, p.profile_pic_url as profilePic
        FROM users u JOIN student_profiles p ON u.id = p.user_id WHERE u.account_type = 'student'
    `);
	res.json(rows.map(s => ({ ...s, skills: s.skills ? JSON.parse(s.skills) : [] })));
});

app.get('/api/students/:id', async (req, res) => {
	const [rows] = await connection.execute(`
        SELECT u.id, u.name, p.major, p.year, p.bio, p.skills, p.profile_pic_url as profilePic
        FROM users u JOIN student_profiles p ON u.id = p.user_id WHERE u.id = ?
    `, [req.params.id]);
	if (rows.length === 0) return res.status(404).json({ error: 'Student not found' });
	res.json({ ...rows[0], skills: rows[0].skills ? JSON.parse(rows[0].skills) : [] });
});


app.get('/api/companies', async (req, res) => {
	const [rows] = await connection.execute('SELECT id, name, industry, description, location, logo_url as profilePic FROM companies');
	res.json(rows);
});

app.get('/api/companies/:id', async (req, res) => {
	const [companyRows] = await connection.execute('SELECT * FROM companies WHERE id = ?', [req.params.id]);
	if (companyRows.length === 0) return res.status(404).json({ error: 'Company not found' });
	const [jobRows] = await connection.execute('SELECT * FROM jobs WHERE company_id = ?', [req.params.id]);
	res.json({ company: companyRows[0], jobs: jobRows });
});


app.get('/api/jobs/:jobId/applicants', verifyToken, async (req, res) => {
	const { jobId } = req.params;

	if (req.user.accountType !== 'company' || !req.user.companyId) {
		return res.status(403).json({ error: 'Forbidden: Access denied.' });
	}

	try {
		// this is to make sure the job actually is accessible to the company, meaning we can't do a request of ANY companies job posting
		const [jobRows] = await connection.execute('SELECT company_id FROM jobs WHERE id = ?', [jobId]);
		if (jobRows.length === 0 || jobRows[0].company_id !== req.user.companyId) {
			return res.status(403).json({ error: 'Forbidden: You do not own this job posting.' });
		}

		const [applicants] = await connection.execute(`
			SELECT 
				u.id, 
				u.name, 
				sp.profile_pic_url AS profilePic, 
				sp.major, 
				sp.year
			FROM applications a
			JOIN users u ON a.student_id = u.id
			LEFT JOIN student_profiles sp ON u.id = sp.user_id
			WHERE a.job_id = ?
		`, [jobId]);

		res.json(applicants);

	} catch (error) {
		console.error('Error fetching applicants:', error);
		res.status(500).json({ error: 'Internal server error' });
	}
});

app.get('/api/jobs', async (req, res) => {
	const [rows] = await connection.execute(`
        SELECT 
            j.*, 
            c.name AS company, 
            c.logo_url 
        FROM jobs j 
        JOIN companies c ON j.company_id = c.id
    `);
	res.json(rows);
});

app.post('/api/upload', verifyToken, upload.single('profilePic'), async (req, res) => {
	if (!req.file) {
		return res.status(400).json({ error: 'No file uploaded.' });
	}

	const fileUrl = `/uploads/${req.file.filename}`;
	const { userId, accountType, companyId } = req.user;

	try {
		if (accountType === 'student') {
			await connection.execute('UPDATE student_profiles SET profile_pic_url = ? WHERE user_id = ?', [fileUrl, userId]);
		} else if (accountType === 'company') {
			await connection.execute('UPDATE companies SET logo_url = ? WHERE id = ?', [fileUrl, companyId]);
		} else {
			return res.status(400).json({ error: 'Invalid account type for upload.' });
		}
		res.json({ message: 'Upload successful', url: fileUrl });
	} catch (error) {
		console.error("Upload DB error:", error);
		res.status(500).json({ error: 'Failed to save upload reference.' });
	}
});

app.put('/api/students/:id', verifyToken, async (req, res) => {
	if (req.user.userId !== parseInt(req.params.id)) return res.status(403).json({ error: "Forbidden" });
	const { major, year, bio, skills } = req.body;
	await connection.execute('UPDATE student_profiles SET major = ?, year = ?, bio = ?, skills = ? WHERE user_id = ?', [major, year, bio, JSON.stringify(skills || []), req.params.id]);
	res.json({ message: 'Profile updated' });
});

app.put('/api/companies/:id', verifyToken, async (req, res) => {
	if (req.user.companyId !== parseInt(req.params.id)) return res.status(403).json({ error: "Forbidden" });
	const { name, industry, description, location } = req.body;
	await connection.execute('UPDATE companies SET name = ?, industry = ?, description = ?, location = ? WHERE id = ?', [name, industry, description, location, req.params.id]);
	res.json({ message: 'Company updated' });
});

app.post('/api/jobs', verifyToken, async (req, res) => {
	if (req.user.accountType !== 'company') return res.status(403).json({ error: "Forbidden" });
	const { title, description, location, type } = req.body;
	const [result] = await connection.execute('INSERT INTO jobs (company_id, title, description, location, type) VALUES (?, ?, ?, ?, ?)', [req.user.companyId, title, description, location, type]);
	const [companyRows] = await connection.execute('SELECT name FROM companies WHERE id = ?', [req.user.companyId]);
	res.status(201).json({ id: result.insertId, companyId: req.user.companyId, title, description, location, type, company: companyRows[0].name });
});

app.put('/api/jobs/:id', verifyToken, async (req, res) => {
	const [jobRows] = await connection.execute('SELECT company_id FROM jobs WHERE id = ?', [req.params.id]);
	if (jobRows.length === 0 || jobRows[0].company_id !== req.user.companyId) return res.status(403).json({ error: "Forbidden" });
	const { title, description, location, type } = req.body;
	await connection.execute('UPDATE jobs SET title = ?, description = ?, location = ?, type = ? WHERE id = ?', [title, description, location, type, req.params.id]);
	res.json({ message: 'Job updated' });
});

app.delete('/api/jobs/:id', verifyToken, async (req, res) => {
	const [jobRows] = await connection.execute('SELECT company_id FROM jobs WHERE id = ?', [req.params.id]);
	if (jobRows.length === 0 || jobRows[0].company_id !== req.user.companyId) return res.status(403).json({ error: "Forbidden" });
	await connection.execute('DELETE FROM jobs WHERE id = ?', [req.params.id]);
	res.json({ message: 'Job deleted' });
});

app.get('/api/applications', verifyToken, async (req, res) => {
	if (req.user.accountType !== 'student') return res.status(403).json({ error: "Forbidden" });
	const [rows] = await connection.execute('SELECT job_id FROM applications WHERE student_id = ?', [req.user.userId]);
	res.json(rows.map(r => r.job_id));
});

app.post('/api/applications', verifyToken, async (req, res) => {
	if (req.user.accountType !== 'student') return res.status(403).json({ error: "Forbidden" });
	await connection.execute('INSERT INTO applications (student_id, job_id) VALUES (?, ?)', [req.user.userId, req.body.jobId]);
	res.status(201).json({ message: 'Applied' });
});

initializeDb().then(() => {
	app.listen(port, () => {
		console.log(`Server running on http://localhost:${port}`);
	});
});