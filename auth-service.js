require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'PV_INCONS_SECRET_KEY_2026';

const USER_FILE_PATH = path.join(__dirname, 'assets', 'data', 'users.json');

app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    console.log(`[AUTH SERVICE] [${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

const dirPath = path.dirname(USER_FILE_PATH);
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
}

if (!fs.existsSync(USER_FILE_PATH)) {
    const defaultPasswordHash = bcrypt.hashSync("123456", 10);
    const defaultUsers = [
        {
            username: "master",
            passwordHash: defaultPasswordHash,
            role: "MASTER",
            fullName: "TRẦN HOÀNG PHƯỚC",
            position: "Giám đốc",
            company: "PV INCONS CO.LTD",
            status: "Đang triển khai"
        }
    ];
    fs.writeFileSync(USER_FILE_PATH, JSON.stringify(defaultUsers, null, 2), 'utf8');
}

app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập đầy đủ tài khoản và mật khẩu!' });
        }

        const data = fs.readFileSync(USER_FILE_PATH, 'utf8');
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);

        if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
            return res.status(401).json({ success: false, error: 'Tài khoản hoặc mật khẩu không chính xác!' });
        }

        const tokenPayload = {
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            position: user.position,
            company: user.company
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });

        res.json({
            success: true,
            message: 'Đăng nhập thành công!',
            token: token,
            user: tokenPayload
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const AUTH_PORT = process.env.AUTH_PORT || 3001;
app.listen(AUTH_PORT, '0.0.0.0', () => {
    console.log(`🔐 Auth Service đang chạy qua cổng ${AUTH_PORT}`);
});