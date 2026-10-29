require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// ===============================================================
// 1. CẤU HÌNH & MIDDLEWARE CHUNG
// ===============================================================
app.set('trust proxy', true);
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'PV_INCONS_SECRET_KEY_2026';
const PORT = process.env.PORT || 3000;

// Middleware ghi log request thời gian thực
app.use((req, res, next) => {
    console.log(`[PV INCONS SERVER] [${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// ===============================================================
// 2. KHỞI TẠO CÁC THƯ MỤC & DỮ LIỆU MẶC ĐỊNH
// ===============================================================
const USER_FILE_PATH = path.join(__dirname, 'assets', 'data', 'users.json');
const AVATAR_DIR = path.join(__dirname, 'assets', 'data', 'avatar');

// Đường dẫn database
const BASE_DATABASE_DIR = process.env.DATABASE_PATH || path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');
const ISSUES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'issues.json');
const RECALLS_FILE_PATH = path.join(BASE_DATABASE_DIR, 'recalls.json');

// Đảm bảo thư mục tồn tại
if (!fs.existsSync(path.dirname(USER_FILE_PATH))) {
    fs.mkdirSync(path.dirname(USER_FILE_PATH), { recursive: true });
}
if (!fs.existsSync(AVATAR_DIR)) {
    fs.mkdirSync(AVATAR_DIR, { recursive: true });
}
if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

// Khởi tạo tài khoản Administrator mặc định nếu chưa có
if (!fs.existsSync(USER_FILE_PATH)) {
    const defaultPasswordHash = bcrypt.hashSync("123456", 10);
    const defaultUsers = [
        {
            "id": 1,
            "username": "admin",
            "passwordHash": defaultPasswordHash,
            "role": "ADMIN",
            "permission": "ADMIN",
            "avatarLink": "",
            "fullName": "Administrator",
            "phone": "0939751194",
            "position": "Quản trị hệ thống",
            "discipline": "Kỹ sư IT",
            "projects": "Tất cả dự án",
            "company": "PV INCONS CO.LTD",
            "status": "Active"
        }
    ];
    fs.writeFileSync(USER_FILE_PATH, JSON.stringify(defaultUsers, null, 2), 'utf8');
}

// ===============================================================
// 3. PROXY CHO REVIT SERVER ADMINISTRATOR
// ===============================================================
app.use(
    '/RevitServerAdmin2027',
    createProxyMiddleware({
        target: 'https://localhost',
        changeOrigin: true,
        secure: false,
        pathRewrite: {
            '^/RevitServerAdmin2027': '/RevitServerAdmin2027',
        },
        onError: (err, req, res) => {
            res.status(500).send('Không thể kết nối tới Revit Server IIS service nội bộ!');
        }
    })
);

// ===============================================================
// 4. API XÁC THỰC & ĐĂNG NHẬP (AUTH SERVICE)
// ===============================================================
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
            company: user.company,
            phone: user.phone,
            groups: user.groups || []
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

// API ĐỔI MẬT KHẨU
app.post('/api/change-password', (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) {
            return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });
        }

        let payload;
        try {
            payload = jwt.verify(token, JWT_SECRET);
        } catch (e) {
            return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ!' });
        }

        const { newPassword } = req.body;
        if (!newPassword || !String(newPassword).trim()) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập mật khẩu mới!' });
        }

        const data = fs.readFileSync(USER_FILE_PATH, 'utf8');
        const users = JSON.parse(data || '[]');

        const userIndex = users.findIndex(u => u.username === payload.username);
        if (userIndex === -1) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy tài khoản người dùng trong hệ thống!' });
        }

        const hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        users[userIndex] = {
            ...users[userIndex],
            passwordHash: hashedNewPassword
        };

        fs.writeFileSync(USER_FILE_PATH, JSON.stringify(users, null, 2), 'utf8');
        res.json({ success: true, message: 'Đổi mật khẩu thành công!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 5. API UPLOAD AVATAR
// ===============================================================
app.post('/api/upload-avatar', (req, res) => {
    try {
        const { fileName, image } = req.body;
        if (!fileName || !image) {
            return res.status(400).json({ success: false, error: 'Thiếu tên file hoặc dữ liệu ảnh!' });
        }

        const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
        const buffer = Buffer.from(base64Data, 'base64');
        const filePath = path.join(AVATAR_DIR, fileName);

        fs.writeFileSync(filePath, buffer);
        res.json({ success: true, message: 'Tải lên avatar thành công!', path: `assets/data/avatar/${fileName}` });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 6. API QUẢN LÝ VẤN ĐỀ & QA-QC (ISSUES API)
// ===============================================================
function readIssuesDB() {
    try {
        if (fs.existsSync(ISSUES_FILE_PATH)) {
            return JSON.parse(fs.readFileSync(ISSUES_FILE_PATH, 'utf8') || '{}');
        }
    } catch (err) {
        console.error('Lỗi đọc issues.json:', err);
    }
    return {};
}

function writeIssuesDB(dbData) {
    try {
        fs.writeFileSync(ISSUES_FILE_PATH, JSON.stringify(dbData, null, 2), 'utf8');
        return true;
    } catch (err) {
        return false;
    }
}

function rekeyIssues(oldPath, newPath) {
    const oldKey = normRecallKey(oldPath);
    const newKey = normRecallKey(newPath);
    const db = readIssuesDB();
    let changed = false;
    Object.keys(db).forEach(k => {
        const nk = normRecallKey(k);
        if (nk === oldKey || nk.startsWith(oldKey + '/')) {
            const target = newKey + nk.slice(oldKey.length);
            db[target] = (db[target] || []).concat(db[k]);
            if (target !== k) delete db[k];
            changed = true;
        }
    });
    if (changed) writeIssuesDB(db);
}

function removeIssues(targetPath) {
    const key = normRecallKey(targetPath);
    const db = readIssuesDB();
    let changed = false;
    Object.keys(db).forEach(k => {
        const nk = normRecallKey(k);
        if (nk === key || nk.startsWith(key + '/')) { delete db[k]; changed = true; }
    });
    if (changed) writeIssuesDB(db);
}

app.get('/api/issues', (req, res) => {
    try { res.json(readIssuesDB()); } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/issues/add', (req, res) => {
    try {
        const { filePath, text, author } = req.body;
        if (!filePath || !text) return res.status(400).json({ success: false, error: 'Thiếu thông tin!' });
        const db = readIssuesDB();
        if (!db[filePath]) db[filePath] = [];
        db[filePath].push({
            text: text.trim(),
            time: new Date().toLocaleString('vi-VN'),
            author: author || 'TRẦN HOÀNG PHƯỚC'
        });
        if (writeIssuesDB(db)) res.json({ success: true, message: 'Đã lưu Issue!', issues: db[filePath] });
        else res.status(500).json({ success: false, error: 'Không thể ghi file' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/issues/delete', (req, res) => {
    try {
        const { filePath, index } = req.body;
        const db = readIssuesDB();
        if (db[filePath] && typeof db[filePath][index] !== 'undefined') {
            db[filePath].splice(index, 1);
            if (db[filePath].length === 0) delete db[filePath];
            writeIssuesDB(db);
            return res.json({ success: true, message: 'Đã xóa Issue!', issues: db[filePath] || [] });
        }
        res.status(404).json({ success: false, error: 'Không tìm thấy Issue!' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ===============================================================
// 7. API THU HỒI FILE (RECALL API)
// ===============================================================
function readRecallsDB() {
    try {
        if (fs.existsSync(RECALLS_FILE_PATH)) {
            return JSON.parse(fs.readFileSync(RECALLS_FILE_PATH, 'utf8') || '{}');
        }
    } catch (err) {
        console.error('Lỗi đọc recalls.json:', err);
    }
    return {};
}

function writeRecallsDB(dbData) {
    try {
        fs.writeFileSync(RECALLS_FILE_PATH, JSON.stringify(dbData, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Lỗi ghi recalls.json:', err);
        return false;
    }
}

function normRecallKey(p) {
    const rel = String(p || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/^database\/bim-vdc\/?/, '').replace(/\/+$/, '');
    return rel ? 'database/bim-vdc/' + rel : 'database/bim-vdc';
}

function rekeyRecalls(oldPath, newPath) {
    const oldKey = normRecallKey(oldPath);
    const newKey = normRecallKey(newPath);
    const db = readRecallsDB();
    let changed = false;
    Object.keys(db).forEach(k => {
        if (k === oldKey || k.startsWith(oldKey + '/')) {
            db[newKey + k.slice(oldKey.length)] = db[k];
            delete db[k];
            changed = true;
        }
    });
    if (changed) writeRecallsDB(db);
}

function removeRecalls(targetPath) {
    const key = normRecallKey(targetPath);
    const db = readRecallsDB();
    let changed = false;
    Object.keys(db).forEach(k => {
        if (k === key || k.startsWith(key + '/')) { delete db[k]; changed = true; }
    });
    if (changed) writeRecallsDB(db);
}

const UPLOAD_ZONES_BY_ROLE = {
    ADMIN: ['WIP', 'SHARED', 'PUBLISHED', 'ARCHIVE'],
    MASTER: ['WIP', 'SHARED', 'PUBLISHED', 'ARCHIVE'],
    DESIGNER: ['WIP'],
    CONTRACTOR: ['PUBLISHED']
};

function getZoneFromPath(p) {
    const upper = String(p || '').toUpperCase();
    if (upper.includes('02_SHARED')) return 'SHARED';
    if (upper.includes('03_PUBLISHED')) return 'PUBLISHED';
    if (upper.includes('04_ARCHIVE')) return 'ARCHIVE';
    return 'WIP';
}

function canUserUploadInZone(user, zone) {
    const role = String(user.role || '').toUpperCase();
    const permission = String(user.permission || role).toUpperCase();
    if (permission === 'ADMIN' || role === 'ADMIN' || permission === 'MASTER' || role === 'MASTER') return true;
    const zones = UPLOAD_ZONES_BY_ROLE[permission] || UPLOAD_ZONES_BY_ROLE[role] || [];
    return zones.includes(zone);
}

function requireUploadPermission(req, res, next) {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });

        let payload;
        try { payload = jwt.verify(token, JWT_SECRET); }
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn!' }); }

        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user) return res.status(401).json({ success: false, error: 'Tài khoản không tồn tại!' });

        if (!canUserUploadInZone(user, getZoneFromPath(req.body && req.body.filePath))) {
            return res.status(403).json({ success: false, error: 'Chỉ người có quyền tải file lên (Read & Write) mới được thu hồi tệp tin này!' });
        }
        req.authUser = user;
        next();
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
}

app.get('/api/recalls', (req, res) => {
    try { res.json(readRecallsDB()); } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/recalls/recall', requireUploadPermission, (req, res) => {
    try {
        const { filePath, reason } = req.body;
        const by = req.authUser.fullName || req.authUser.username;
        if (!filePath || !reason || !String(reason).trim()) {
            return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file hoặc lý do thu hồi!' });
        }
        const key = normRecallKey(filePath);
        const fullPath = path.join(ROOT_DIR, key.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(fullPath)) return res.status(404).json({ success: false, error: 'Tệp không tồn tại!' });

        const db = readRecallsDB();
        if (db[key]) return res.status(409).json({ success: false, error: 'Tệp này đã được thu hồi trước đó!' });

        db[key] = { by, at: new Date().toISOString(), reason: String(reason).trim() };
        if (writeRecallsDB(db)) res.json({ success: true, message: 'Đã thu hồi tệp!', recall: db[key] });
        else res.status(500).json({ success: false, error: 'Không thể ghi file' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/recalls/restore', requireUploadPermission, (req, res) => {
    try {
        const { filePath } = req.body;
        if (!filePath) return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file!' });
        const key = normRecallKey(filePath);
        const db = readRecallsDB();
        if (!db[key]) return res.status(404).json({ success: false, error: 'Tệp này chưa bị thu hồi!' });
        delete db[key];
        if (writeRecallsDB(db)) res.json({ success: true, message: 'Đã hủy thu hồi tệp!' });
        else res.status(500).json({ success: false, error: 'Không thể ghi file' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ===============================================================
// 8. TÍCH HỢP DỊCH VỤ CHỮ KÝ SỐ TỪ XA VIETTEL MYSIGN API (CHUẨN CSC & LƯU PHIÊN TỰ ĐỘNG KÝ)
// ===============================================================
const VIETTEL_MYSIGN_BASE_URL = process.env.VIETTEL_MYSIGN_BASE_URL || 'https://remotesigning.viettel.vn/vtss/service/ras';
const VIETTEL_MYSIGN_CLIENT_ID = process.env.VIETTEL_MYSIGN_CLIENT_ID || 'adss_client';
const VIETTEL_MYSIGN_CLIENT_SECRET = process.env.VIETTEL_MYSIGN_CLIENT_SECRET || 'your_client_secret';
const VIETTEL_MYSIGN_PROFILE_ID = process.env.VIETTEL_MYSIGN_PROFILE_ID || 'ADSS RAS Profile 001';

// 8.1. API Login lấy access_token từ Viettel MySign
app.post('/api/viettel/login', async (req, res) => {
    try {
        const { userId } = req.body;
        const user_id = userId || req.body.user_id;
        if (!user_id) {
            return res.status(400).json({ success: false, error: 'Thiếu thông tin user_id (mã tài khoản ký số)!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/v1/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
                client_id: VIETTEL_MYSIGN_CLIENT_ID,
                client_secret: VIETTEL_MYSIGN_CLIENT_SECRET,
                profile_id: VIETTEL_MYSIGN_PROFILE_ID,
                user_id: user_id
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi đăng nhập Viettel MySign' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.2. API Lấy danh sách Chứng thư số (Credentials/List)
app.post('/api/viettel/credentials/list', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const accessToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.access_token;
        if (!accessToken) {
            return res.status(401).json({ success: false, error: 'Thiếu access_token phiên Viettel MySign!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/list`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({})
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi lấy danh sách CTS' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.3. API Lấy thông tin chi tiết Chứng thư số (Credentials/Info)
app.post('/api/viettel/credentials/info', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const accessToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.access_token;
        const { credentialID, certificates, certInfo, authInfo } = req.body;

        if (!accessToken || !credentialID) {
            return res.status(400).json({ success: false, error: 'Thiếu access_token hoặc credentialID!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/info`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                credentialID: credentialID,
                certificates: certificates || 'chain',
                certInfo: certInfo !== undefined ? certInfo : true,
                authInfo: authInfo !== undefined ? authInfo : true
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi lấy thông tin CTS' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.4. API Gửi yêu cầu ủy quyền ký tới Mobile/App (Credentials/Authorize)
app.post('/api/viettel/credentials/authorize', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const accessToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.access_token;
        const { credentialID, numSignatures, documents, hash, description } = req.body;

        if (!accessToken || !credentialID || !hash) {
            return res.status(400).json({ success: false, error: 'Thiếu tham số bắt buộc (accessToken, credentialID, hash)!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                credentialID: credentialID,
                numSignatures: numSignatures || 1,
                documents: documents || [],
                hash: Array.isArray(hash) ? hash : [hash],
                description: description || 'Yêu cầu ký số văn bản CDE PV Incons'
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi ủy quyền ký trên MySign' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.5. API Gửi yêu cầu sinh chữ ký mã băm (SignHash)
app.post('/api/viettel/signatures/signHash', async (req, res) => {
    try {
        const { credentialID, SAD, documents, hash, hashAlgo, signAlgo } = req.body;
        if (!credentialID || !SAD || !hash) {
            return res.status(400).json({ success: false, error: 'Thiếu tham số bắt buộc (credentialID, SAD, hash)!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/signatures/signHash`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            },
            body: JSON.stringify({
                credentialID: credentialID,
                SAD: SAD,
                documents: documents || [],
                hash: Array.isArray(hash) ? hash : [hash],
                hashAlgo: hashAlgo || '2.16.840.1.101.3.4.2.1', // SHA256
                signAlgo: signAlgo || '1.2.840.113549.1.1.1', // RSA
                async: 0
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi sinh chữ ký SignHash' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.6. API Lấy cấu hình thời gian lưu phiên tối đa (Credentials/extendConfig)
app.get('/api/viettel/credentials/extendConfig', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const SAD = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.query.sad;
        if (!SAD) {
            return res.status(400).json({ success: false, error: 'Thiếu mã SAD ủy quyền!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/extendConfig`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            }
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi lấy cấu hình extendConfig' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.7. API Đăng ký sử dụng chức năng lưu phiên / tự động ký (Register/Extension)
app.post('/api/viettel/credentials/registerExtension', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const SAD = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.SAD;
        const { credential_id, duration } = req.body;

        if (!SAD || !credential_id || !duration) {
            return res.status(400).json({ success: false, error: 'Thiếu tham số (SAD, credential_id, duration)!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/registerExtension`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            },
            body: JSON.stringify({
                credential_id: credential_id,
                duration: Number(duration),
                SAD: SAD
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi đăng ký lưu phiên Register/Extension' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.8. API Gửi yêu cầu sinh chữ ký lưu phiên tự động (Credentials/extendTransaction)
app.post('/api/viettel/credentials/extendTransaction', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const SAD = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.SAD;
        const { credentialID, documents, hash, hashAlgo, signAlgo, description } = req.body;

        if (!SAD || !credentialID || !hash) {
            return res.status(400).json({ success: false, error: 'Thiếu tham số (SAD, credentialID, hash)!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/extendTransaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            },
            body: JSON.stringify({
                credentialID: credentialID,
                SAD: SAD,
                documents: documents || [],
                hash: Array.isArray(hash) ? hash : [hash],
                hashAlgo: hashAlgo || '2.16.840.1.101.3.4.2.1',
                signAlgo: signAlgo || '1.2.840.113549.1.1.1',
                description: description || 'Tự động ký lưu phiên PV Incons CDE'
            })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi extendTransaction' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.9. API Kiểm tra trạng thái lưu phiên ký (Timecheck)
app.post('/api/viettel/credentials/transaction/check', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const SAD = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.SAD;
        if (!SAD) {
            return res.status(400).json({ success: false, error: 'Thiếu mã SAD phiên ký!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/transaction/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            },
            body: JSON.stringify({ SAD: SAD })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi kiểm tra trạng thái Timecheck' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8.10. API Hủy đăng ký chức năng lưu phiên (Deletion/Extension)
app.delete('/api/viettel/credentials/deleteExtension', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const SAD = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : req.body.SAD;
        const { credential_id } = req.body;

        if (!SAD || !credential_id) {
            return res.status(400).json({ success: false, error: 'Thiếu SAD hoặc credential_id!' });
        }

        const response = await fetch(`${VIETTEL_MYSIGN_BASE_URL}/csc/v1/credentials/deleteExtension`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${SAD}`
            },
            body: JSON.stringify({ credential_id: credential_id })
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi hủy gia hạn Delete/Extension' });
        }

        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 9. API QUẢN LÝ TẬP TIN & CDE (MULTER MULTI-FILES UPLOAD)
// ===============================================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let targetFolder = req.body.targetFolder || req.query.path || 'database/bim-vdc';
        let rel = targetFolder.replace(/^database\/bim-vdc\/?/, '');
        let dest = path.join(ROOT_DIR, rel);
        if (!fs.existsSync(dest)) {
            fs.mkdirSync(dest, { recursive: true });
        }
        cb(null, dest);
    },
    filename: (req, file, cb) => {
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage });

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE & Auth Backend Server đang hoạt động ổn định!' });
});

app.get('/api/cde-files', (req, res) => {
    try {
        function walkDir(dir, fileList = []) {
            fs.readdirSync(dir, { withFileTypes: true }).forEach(file => {
                const fullPath = path.join(dir, file.name);
                const relPath = path.relative(BASE_DATABASE_DIR, fullPath).replace(/\\/g, '/');
                fileList.push({ name: file.name, path: 'database/' + relPath, type: file.isDirectory() ? 'folder' : 'file' });
                if (file.isDirectory()) walkDir(fullPath, fileList);
            });
            return fileList;
        }
        res.json(walkDir(ROOT_DIR));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// Sửa hỗ trợ upload mảng nhiều file (upload.array)
app.post('/api/upload', upload.array('files'), (req, res) => {
    try {
        res.json({ success: true, message: 'Tải lên tập tin vào CDE thành công!' });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/create-folder', (req, res) => {
    try {
        const { parentPath, folderName } = req.body;
        const targetDir = path.join(ROOT_DIR, (parentPath || 'database/bim-vdc').replace(/^database\/bim-vdc\/?/, ''), folderName);
        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
            res.json({ success: true, message: 'Tạo thư mục thành công!' });
        } else {
            res.status(400).json({ success: false, error: 'Thư mục đã tồn tại!' });
        }
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/rename', (req, res) => {
    try {
        const { path: itemPath, newName } = req.body;
        const oldFullPath = path.join(ROOT_DIR, itemPath.replace(/^database\/bim-vdc\/?/, ''));
        if (fs.existsSync(oldFullPath)) {
            fs.renameSync(oldFullPath, path.join(path.dirname(oldFullPath), newName));
            const renamedKey = path.posix.join(path.posix.dirname(normRecallKey(itemPath)), newName);
            rekeyRecalls(itemPath, renamedKey);
            rekeyIssues(itemPath, renamedKey);
            res.json({ success: true, message: 'Đổi tên thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Đường dẫn không tồn tại!' });
        }
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/delete', (req, res) => {
    try {
        const fullPath = path.join(ROOT_DIR, req.body.path.replace(/^database\/bim-vdc\/?/, ''));
        if (fs.existsSync(fullPath)) {
            fs.rmSync(fullPath, { recursive: true, force: true });
            removeRecalls(req.body.path);
            removeIssues(req.body.path);
            res.json({ success: true, message: 'Xóa thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Không tồn tại!' });
        }
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/move', (req, res) => {
    try {
        const { sourcePath, targetDir } = req.body;
        const srcFullPath = path.join(ROOT_DIR, sourcePath.replace(/^database\/bim-vdc\/?/, ''));
        const destParent = path.join(ROOT_DIR, targetDir.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(srcFullPath)) return res.status(404).json({ success: false, error: 'Nguồn không tồn tại!' });
        if (readRecallsDB()[normRecallKey(sourcePath)]) {
            return res.status(423).json({ success: false, error: 'Tệp đã bị thu hồi, không thể di chuyển!' });
        }
        if (!fs.existsSync(destParent)) fs.mkdirSync(destParent, { recursive: true });
        fs.renameSync(srcFullPath, path.join(destParent, path.basename(srcFullPath)));
        const movedKey = path.posix.join(normRecallKey(targetDir), path.basename(srcFullPath));
        rekeyRecalls(sourcePath, movedKey);
        rekeyIssues(sourcePath, movedKey);
        res.json({ success: true, message: 'Di chuyển thành công!' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ===============================================================
// 10. STATIC SERVE & KHỞI ĐỘNG SERVER
// ===============================================================
app.use('/files', express.static(ROOT_DIR));
app.use('/vendor/three', express.static(path.join(__dirname, 'node_modules', 'three')));
app.use('/vendor/web-ifc', express.static(path.join(__dirname, 'node_modules', 'web-ifc')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 PV INCONS Server đã khởi động hoàn chỉnh tại cổng ${PORT}`);
});