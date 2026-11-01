require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createProxyMiddleware } = require('http-proxy-middleware');

// Nhúng chữ ký số từ xa (VNPT SmartCA) vào PDF - xem smartca-pdf-sign.js
const smartcaPdf = require('./smartca-pdf-sign');

const app = express();

// ===============================================================
// 1. CẤU HÌNH & MIDDLEWARE CHUNG
// ===============================================================
app.set('trust proxy', true);

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// Bắt buộc có đủ biến môi trường (thiếu thì dừng server, KHÔNG dùng giá trị mặc định)
const REQUIRED_ENV = ['JWT_SECRET', 'VNPT_SMARTCA_BASE_URL', 'VNPT_SMARTCA_CLIENT_ID', 'VNPT_SMARTCA_CLIENT_SECRET'];
if (IS_PRODUCTION) REQUIRED_ENV.push('SMARTCA_WEBHOOK_TOKEN', 'PUBLIC_API_BASE_URL', 'CORS_ALLOWED_ORIGINS');
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k] || !String(process.env[k]).trim());
if (missingEnv.length) {
    console.error('[PV INCONS SERVER] LỖI CẤU HÌNH: file .env chưa được nạp hoặc thiếu biến:', missingEnv.join(', '));
    process.exit(1);
}
if (JWT_SECRET.length < 32 || JWT_SECRET === 'PV_INCONS_SECRET_KEY_2026') {
    console.error('[PV INCONS SERVER] LỖI CẤU HÌNH: JWT_SECRET quá ngắn (<32 ký tự) hoặc là giá trị mặc định cũ. Hãy tạo bằng: openssl rand -hex 48');
    process.exit(1);
}

// CORS: chỉ cho phép các website khai báo trong CORS_ALLOWED_ORIGINS (phân tách bằng dấu phẩy)
const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').map(o => o.trim().replace(/\/+$/, '')).filter(Boolean);
app.use(cors({
    origin(origin, cb) {
        if (!origin) return cb(null, true); // server-to-server (VNPT callback), curl, health-check: không có Origin
        if (CORS_ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        if (!IS_PRODUCTION && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true);
        return cb(null, false); // không trả header CORS -> trình duyệt chặn
    }
}));
app.use(express.json({ limit: '10mb' }));

// Middleware ghi log request thời gian thực
app.use((req, res, next) => {
    console.log(`[PV INCONS SERVER] [${new Date().toLocaleTimeString()}] ${req.method} ${req.url.replace(/([?&]token=)[^&]*/i, '$1***')}`);
    next();
});

// ===============================================================
// 2. KHỞI TẠO CÁC THƯ MỤC & DỮ LIỆU MẶC ĐỊNH
// ===============================================================
const USER_FILE_PATH = path.join(__dirname, 'assets', 'data', 'users.json');
const AVATAR_DIR = path.join(__dirname, 'assets', 'data', 'avatar');

// Linh hoạt đường dẫn: Biến môi trường DATABASE_PATH (Production/VPS) hoặc thư mục local
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

// ===============================================================
// 4.1 API ĐỔI MẬT KHẨU NGƯỜI DÙNG HIỆN TẠI
// ===============================================================
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

        const saltRounds = 10;
        const hashedNewPassword = bcrypt.hashSync(newPassword, saltRounds);

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
// 5. API UPLOAD AVATAR NGƯỜI DÙNG
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
        db[filePath].push({ text: text.trim(), time: new Date().toLocaleString('vi-VN'), author: author || 'Phương Vy' });
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

// ===============================================================
// 8. KIỂM TRA QUYỀN TẢI UP / THU HỒI
// ===============================================================
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
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn, vui lòng đăng nhập lại!' }); }

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

// ===============================================================
// 9. API LƯU ĐÁNH GIÁ VIEWER 3D
// ===============================================================
const REVIEW_ZONE_ACCESS = {
    ADMIN: { '01_WIP': 'FULL CONTROL', '02_SHARED': 'FULL CONTROL', '03_PUBLISHED': 'FULL CONTROL', '04_ARCHIVE': 'FULL CONTROL' },
    MASTER: { '01_WIP': 'FULL CONTROL', '02_SHARED': 'FULL CONTROL', '03_PUBLISHED': 'FULL CONTROL', '04_ARCHIVE': 'FULL CONTROL' },
    MANAGEMENT: { '01_WIP': 'NO ACCESS', '02_SHARED': 'FULL CONTROL', '03_PUBLISHED': 'FULL CONTROL', '04_ARCHIVE': 'READ & WRITE' },
    DESIGNER: { '01_WIP': 'FULL CONTROL', '02_SHARED': 'READ & WRITE', '03_PUBLISHED': 'READ-ONLY', '04_ARCHIVE': 'NO ACCESS' },
    CONTRACTOR: { '01_WIP': 'NO ACCESS', '02_SHARED': 'READ-ONLY', '03_PUBLISHED': 'READ & WRITE', '04_ARCHIVE': 'NO ACCESS' },
};

function getContainerFromPath(p) {
    const upper = String(p || '').toUpperCase();
    return ['01_WIP', '02_SHARED', '03_PUBLISHED', '04_ARCHIVE'].find(c => upper.includes(c)) || null;
}

function canUserWriteReview(user, container) {
    const role = String(user.role || '').toUpperCase();
    const permission = String(user.permission || role).toUpperCase();
    if (permission === 'ADMIN' || role === 'ADMIN') return true;
    if (!container) return false;
    const level = (REVIEW_ZONE_ACCESS[permission] || REVIEW_ZONE_ACCESS[role] || {})[container];
    return level === 'FULL CONTROL' || level === 'READ & WRITE';
}

app.post('/api/review/save', (req, res) => {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });
        let payload;
        try { payload = jwt.verify(token, JWT_SECRET); }
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn, vui lòng đăng nhập lại!' }); }

        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user || user.status === 'Inactive') return res.status(401).json({ success: false, error: 'Tài khoản không tồn tại hoặc đã bị khóa!' });

        const { filePath, comments } = req.body || {};
        if (!filePath || !Array.isArray(comments)) return res.status(400).json({ success: false, error: 'Thiếu thông tin file hoặc ý kiến!' });

        const rel = String(filePath).replace(/\\/g, '/').replace(/^database\/bim-vdc\/?/, '');
        const modelFull = path.resolve(ROOT_DIR, rel);
        if (modelFull !== ROOT_DIR && !modelFull.startsWith(ROOT_DIR + path.sep)) {
            return res.status(400).json({ success: false, error: 'Đường dẫn không hợp lệ!' });
        }
        if (!fs.existsSync(modelFull) || !fs.statSync(modelFull).isFile()) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy file mô hình trên server!' });
        }

        const container = getContainerFromPath(rel);
        if (!canUserWriteReview(user, container)) {
            return res.status(403).json({ success: false, error: 'Bạn cần quyền Read & Write hoặc Full Control trên thư mục này để lưu đánh giá!' });
        }

        const reviewFull = modelFull.replace(/\.[^./\\]+$/, '') + '.review.json';
        let saved = [];
        if (fs.existsSync(reviewFull)) {
            try {
                const old = JSON.parse(fs.readFileSync(reviewFull, 'utf8'));
                saved = Array.isArray(old) ? old : (old.comments || []);
            } catch (e) { saved = []; }
        }
        const byCid = new Map();
        saved.forEach(c => { if (c && c.cid) byCid.set(c.cid, c); });
        comments.forEach(c => {
            if (!c || !c.cid || !c.globalId || typeof c.text !== 'string') return;
            if (byCid.has(c.cid)) return;
            byCid.set(c.cid, {
                cid: String(c.cid).slice(0, 80),
                globalId: String(c.globalId).slice(0, 80),
                name: String(c.name || '').slice(0, 300),
                text: c.text.slice(0, 5000),
                author: user.fullName || user.username,
                username: user.username,
                role: String(user.role || ''),
                at: c.at || new Date().toISOString(),
                time: c.time || ''
            });
        });
        const merged = [...byCid.values()].sort((a, b) => String(a.at).localeCompare(String(b.at)));
        fs.writeFileSync(reviewFull, JSON.stringify({
            model: path.basename(modelFull),
            savedBy: user.fullName || user.username,
            savedAt: new Date().toISOString(),
            comments: merged
        }, null, 2), 'utf8');

        res.json({ success: true, message: 'Đã lưu đánh giá: ' + path.basename(reviewFull), comments: merged });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

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
// 10. TÍCH HỢP DỊCH VỤ CHỮ KÝ SỐ TỪ XA VNPT SMARTCA (CSC & OAUTH2 API v1.1)
// ===============================================================
const VNPT_SMARTCA_BASE_URL = process.env.VNPT_SMARTCA_BASE_URL.replace(/\/+$/, '');
const VNPT_SMARTCA_CLIENT_ID = process.env.VNPT_SMARTCA_CLIENT_ID;
const VNPT_SMARTCA_CLIENT_SECRET = process.env.VNPT_SMARTCA_CLIENT_SECRET;

const SIGNATURES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'signatures.json');

if (!fs.existsSync(SIGNATURES_FILE_PATH)) {
    fs.writeFileSync(SIGNATURES_FILE_PATH, JSON.stringify({}, null, 2), 'utf8');
}

// Hàm băm file CDE chuẩn SHA-256 dạng Base64
function hashCdeFile(filePath) {
    try {
        const cleanPath = String(filePath || '').replace(/^database\/bim-vdc\/?/, '');
        const fullPath = path.resolve(ROOT_DIR, cleanPath);
        const rootResolved = path.resolve(ROOT_DIR);

        // Phải nằm TRONG ROOT_DIR (so sánh kèm dấu phân cách để tránh trùng tiền tố thư mục)
        if (!fullPath.startsWith(rootResolved + path.sep) || !fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
            return { error: 'Không tìm thấy tệp tin cần ký trên hệ thống CDE!', status: 404 };
        }

        const fileBuffer = fs.readFileSync(fullPath);
        const hashBuf = crypto.createHash('sha256').update(fileBuffer).digest();
        const hashBase64 = hashBuf.toString('base64');
        const fileName = path.basename(fullPath);
        const relPath = path.relative(rootResolved, fullPath).split(path.sep).join('/');

        return { fileName, hashBase64, relPath };
    } catch (err) {
        return { error: 'Lỗi xử lý băm tệp tin: ' + err.message, status: 500 };
    }
}

// Quyền KÝ SỐ file: yêu cầu quyền ghi (FULL CONTROL / READ & WRITE) trên khu vực (01_WIP...04_ARCHIVE) chứa file,
// tính theo đường dẫn ĐÃ CHUẨN HÓA trên đĩa (không tin chuỗi filePath do client gửi).
function canUserSignFile(user, relPath) {
    return canUserWriteReview(user, getContainerFromPath(relPath));
}

// Lưu giao dịch ký (tranId -> file, hash, dữ liệu PDF đang chờ nhúng chữ ký, người yêu cầu)
// để gettraninfo không phải tin dữ liệu từ client. PDF đã chuẩn bị vùng chữ ký nằm trong thư mục sign_pending.
const SIGN_TX_FILE_PATH = path.join(BASE_DATABASE_DIR, 'sign_transactions.json');
const SIGN_PENDING_DIR = path.join(BASE_DATABASE_DIR, 'sign_pending');
const SIGN_TX_TTL_MS = 24 * 60 * 60 * 1000;
if (!fs.existsSync(SIGN_PENDING_DIR)) fs.mkdirSync(SIGN_PENDING_DIR, { recursive: true });

function readSignTx() {
    try { return fs.existsSync(SIGN_TX_FILE_PATH) ? JSON.parse(fs.readFileSync(SIGN_TX_FILE_PATH, 'utf8') || '{}') : {}; }
    catch (e) { return {}; }
}
function writeSignTx(db) {
    const tmp = SIGN_TX_FILE_PATH + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
    fs.renameSync(tmp, SIGN_TX_FILE_PATH);
}
function removePendingFile(tx) {
    try { if (tx && tx.pendingFile) fs.rmSync(path.join(SIGN_PENDING_DIR, path.basename(tx.pendingFile)), { force: true }); } catch (e) { }
}
function saveSignTx(tranId, info) {
    try {
        const db = readSignTx();
        const now = Date.now();
        Object.keys(db).forEach(k => {
            if (now - (db[k].createdAt || 0) > SIGN_TX_TTL_MS) { removePendingFile(db[k]); delete db[k]; }
        });
        db[tranId] = { ...info, createdAt: now };
        writeSignTx(db);
    } catch (e) { console.error('Lỗi lưu giao dịch ký:', e); }
}
function updateSignTx(tranId, patch) {
    try {
        const db = readSignTx();
        if (db[tranId]) { db[tranId] = { ...db[tranId], ...patch }; writeSignTx(db); }
    } catch (e) { console.error('Lỗi cập nhật giao dịch ký:', e); }
}

function readSignaturesDB() {
    try {
        if (fs.existsSync(SIGNATURES_FILE_PATH)) {
            return JSON.parse(fs.readFileSync(SIGNATURES_FILE_PATH, 'utf8') || '{}');
        }
    } catch (e) {
        console.error('Lỗi đọc signatures.json:', e);
    }
    return {};
}

// Ghi nhận MỘT lượt ký. Một tệp có thể có nhiều người ký nên lưu danh sách `signatures`;
// signedBy / signedAt luôn là của lượt ký gần nhất (mir.html đang đọc 2 trường này để hiện huy hiệu "✓ Đã ký").
function addSignatureRecord(filePath, entry) {
    try {
        const db = readSignaturesDB();
        const key = normRecallKey(filePath);
        const old = db[key] || {};
        const signatures = Array.isArray(old.signatures) ? old.signatures : [];
        signatures.push(entry);
        db[key] = {
            filePath: key,
            fileName: path.basename(filePath),
            signatures,
            signatureCount: signatures.length,
            signedBy: entry.signedBy,
            signedAt: entry.signedAt
        };
        const tmp = SIGNATURES_FILE_PATH + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
        fs.renameSync(tmp, SIGNATURES_FILE_PATH);
    } catch (e) {
        console.error('Lỗi lưu bản ghi chữ ký VNPT:', e);
    }
}

function requireCdeAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) {
            return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });
        }
        const payload = jwt.verify(token, JWT_SECRET);
        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user || user.status === 'Inactive') {
            return res.status(401).json({ success: false, error: 'Tài khoản không hợp lệ hoặc đã bị khóa!' });
        }
        req.authUser = user;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn!' });
    }
}

// 10.1. API Đăng nhập / Lấy Access Token VNPT SmartCA (OAuth2)
app.post('/api/vnpt/token', requireCdeAuth, async (req, res) => {
    try {
        const { username, password } = req.body;
        const params = new URLSearchParams();
        params.append('grant_type', password ? 'password' : 'client_credentials');
        params.append('client_id', VNPT_SMARTCA_CLIENT_ID);
        params.append('client_secret', VNPT_SMARTCA_CLIENT_SECRET);
        if (username) params.append('username', username);
        if (password) params.append('password', password);
        params.append('scope', 'sign offline_access openid profile email');

        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/auth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params
        });

        const data = await response.json();
        if (!response.ok) {
            return res.status(response.status).json({ success: false, error: data.error_description || data.error || 'Lỗi xác thực VNPT SmartCA Token' });
        }
        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.2. API Lấy danh sách Chứng thư số (List credential)
app.post('/api/vnpt/credentials/list', requireCdeAuth, async (req, res) => {
    try {
        const accessToken = req.body && req.body.access_token;
        if (!accessToken) return res.status(400).json({ success: false, error: 'Thiếu access_token VNPT SmartCA, vui lòng xác thực lại tài khoản SmartCA!' });
        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/list`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
            body: JSON.stringify({})
        });
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Lỗi lấy danh sách CTS VNPT' });
        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.3. API Lấy thông tin chi tiết Chứng thư số (Credential Info)
app.post('/api/vnpt/credentials/info', requireCdeAuth, async (req, res) => {
    try {
        const accessToken = req.body && req.body.access_token;
        if (!accessToken) return res.status(400).json({ success: false, error: 'Thiếu access_token VNPT SmartCA, vui lòng xác thực lại tài khoản SmartCA!' });
        const { credentialId, certificates, certInfo, authInfo } = req.body;

        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/info`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
            body: JSON.stringify({
                credentialId: credentialId,
                certificates: certificates || 'chain',
                certInfo: certInfo !== undefined ? certInfo : true,
                authInfo: authInfo !== undefined ? authInfo : true
            })
        });
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Lỗi lấy thông tin CTS' });
        res.json({ success: true, ...data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.4. API Gửi yêu cầu ký Hash (SignHash) tới VNPT SmartCA
//  - PDF  : tạo sẵn vùng chữ ký trong PDF (cập nhật tăng dần, giữ nguyên các chữ ký trước đó), dựng "signed attributes"
//           PKCS#7 và gửi SHA-256 của chúng cho VNPT ký. Khi VNPT báo thành công, chữ ký được NHÚNG vào chính file PDF
//           (xem finalizeVnptSignature). Phải băm đúng đối tượng này thì Adobe/pdfsig mới xác thực được chữ ký.
//  - Khác : chỉ ký SHA-256 của tệp và ghi nhận trong signatures.json (không thể nhúng vào định dạng khác).
app.post('/api/vnpt/signature/signhash', requireCdeAuth, async (req, res) => {
    try {
        const accessToken = req.body && req.body.access_token;
        if (!accessToken) return res.status(400).json({ success: false, error: 'Thiếu access_token VNPT SmartCA, vui lòng xác thực lại tài khoản SmartCA!' });
        const { credentialId, filePath, description } = req.body;
        if (!credentialId) return res.status(400).json({ success: false, error: 'Thiếu credentialId (Chứng thư số) cần dùng để ký!' });

        const fileInfo = hashCdeFile(filePath);
        if (fileInfo.error) return res.status(fileInfo.status).json({ success: false, error: fileInfo.error });

        if (!canUserSignFile(req.authUser, fileInfo.relPath)) {
            return res.status(403).json({ success: false, error: 'Bạn không có quyền ký số tài liệu trong khu vực này của CDE!' });
        }

        const fullPath = path.resolve(ROOT_DIR, fileInfo.relPath);
        const isPdf = /\.pdf$/i.test(fileInfo.fileName);
        let hashToSign = fileInfo.hashBase64;
        let txExtra = { mode: 'record', hashBase64: fileInfo.hashBase64 };
        let preparedPdf = null;

        if (isPdf) {
            const pdfBuffer = fs.readFileSync(fullPath);

            // 1) Lấy chuỗi chứng thư của người ký (đồng thời VNPT xác nhận credential thuộc tài khoản trong access_token)
            const infoRes = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/info`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
                body: JSON.stringify({ credentialId, certificates: 'chain', certInfo: true, authInfo: false })
            });
            const infoData = await infoRes.json().catch(() => ({}));
            const info = (infoData && infoData.content && infoData.content.cert) ? infoData.content : infoData;
            if (!infoRes.ok || !info || !info.cert || !Array.isArray(info.cert.certificates) || !info.cert.certificates.length) {
                return res.status(infoRes.ok ? 502 : infoRes.status).json({ success: false, error: (infoData && infoData.message) || 'Không lấy được chứng thư số của thuê bao từ VNPT SmartCA để nhúng vào PDF!' });
            }
            if (info.cert.status && info.cert.status !== 'VALID') {
                return res.status(400).json({ success: false, error: `Chứng thư số không còn hiệu lực (trạng thái: ${info.cert.status}), không thể ký!` });
            }
            const chainDer = info.cert.certificates.map(smartcaPdf.b64ToDer);
            const leafDer = smartcaPdf.pickLeafCert(chainDer, info.cert.serialNumber);
            const signerName = smartcaPdf.certSubjectCN(leafDer) || req.authUser.fullName || req.authUser.username;

            // 2) Chuẩn bị PDF có vùng chữ ký và dựng dữ liệu cần ký
            const signingTime = new Date(Math.floor(Date.now() / 1000) * 1000);
            let prep;
            try {
                prep = await smartcaPdf.preparePdf(pdfBuffer, {
                    signingTime,
                    name: signerName,
                    reason: 'Ký số xác nhận tài liệu trên CDE PV INCONS',
                    location: 'PV INCONS CDE',
                    // Con dấu chữ ký hiển thị ở trang đầu. Tắt bằng SIGNATURE_STAMP=off; font tiếng Việt: SIGNATURE_FONT_PATH=...ttf
                    stamp: process.env.SIGNATURE_STAMP === 'off'
                        ? false
                        : { serial: info.cert.serialNumber, fontPath: process.env.SIGNATURE_FONT_PATH }
                });
            } catch (prepErr) {
                return res.status(422).json({ success: false, error: 'Không thể chuẩn bị PDF để ký số: ' + prepErr.message });
            }
            const attrs = smartcaPdf.buildSignedAttrs({ contentDigest: prep.digest, certDer: leafDer, signingTime });
            hashToSign = smartcaPdf.sha256(attrs.toSign).toString('base64');
            preparedPdf = prep.prepared;

            txExtra = {
                mode: 'pdf-embed',
                hashBase64: smartcaPdf.sha256(pdfBuffer).toString('base64'), // hash tệp lúc yêu cầu: tệp đổi thì không nhúng
                contentsStart: prep.contentsStart,
                byteRange: prep.byteRange,
                contentDigestB64: prep.digest.toString('base64'),
                toSignB64: attrs.toSign.toString('base64'),
                implicitB64: attrs.implicit.toString('base64'),
                chainB64: chainDer.map(d => d.toString('base64')),
                leafB64: leafDer.toString('base64'),
                signerName,
                certSerial: info.cert.serialNumber || ''
            };
        }

        // notifyUrl do SERVER tạo (không nhận từ client), kèm token để xác thực callback từ VNPT
        const notifyUrl = process.env.SMARTCA_WEBHOOK_TOKEN
            ? `${String(process.env.PUBLIC_API_BASE_URL || '').replace(/\/+$/, '')}/api/smartca/callback?token=${encodeURIComponent(process.env.SMARTCA_WEBHOOK_TOKEN)}`
            : '';

        const refTranId = 'PVI-' + Date.now();
        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/signature/signhash`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
            body: JSON.stringify({
                credentialId: credentialId,
                refTranId: refTranId,
                ...(notifyUrl && process.env.PUBLIC_API_BASE_URL ? { notifyUrl } : {}),
                description: description || 'Ký số tài liệu CDE PV Incons qua VNPT SmartCA',
                datas: [
                    {
                        name: fileInfo.fileName,
                        hash: hashToSign
                    }
                ]
            })
        });

        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Lỗi yêu cầu ký SignHash VNPT' });

        if (data.code !== 0 || !data.content || !data.content.tranId) {
            return res.status(400).json({ success: false, error: data.message || data.codeDesc || 'VNPT SmartCA không tạo được giao dịch ký số' });
        }

        // Giữ bản PDF đã có vùng chữ ký để nhúng đúng vào đó khi VNPT trả chữ ký về
        let pendingFile = '';
        if (preparedPdf) {
            pendingFile = refTranId + '.pdf';
            fs.writeFileSync(path.join(SIGN_PENDING_DIR, pendingFile), preparedPdf);
        }
        saveSignTx(data.content.tranId, {
            filePath: fileInfo.relPath,
            username: req.authUser.username,
            pendingFile,
            ...txExtra
        });

        res.json({ success: true, ...data, filePath, fileName: fileInfo.fileName, mode: txExtra.mode });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Hoàn tất giao dịch ký khi VNPT báo tranStatus = 1: kiểm tra chữ ký, đóng gói PKCS#7 và nhúng vào PDF.
// Idempotent (frontend poll nhiều lần) và có khóa chống chạy song song cho cùng một giao dịch.
const signFinalizing = new Set();
async function finalizeVnptSignature(tranId, tx, content, user) {
    if (tx.done) return { ok: true, already: true, embedded: !!tx.embedded };
    if (signFinalizing.has(tranId)) {
        return { ok: false, status: 409, retry: true, error: 'Hệ thống đang nhúng chữ ký vào tệp, vui lòng chờ giây lát...' };
    }
    signFinalizing.add(tranId);
    try {
        // Tệp phải còn nguyên như lúc yêu cầu ký (hash hiện tại trùng hash đã dùng để tạo vùng chữ ký)
        const current = hashCdeFile(tx.filePath);
        if (current.error || current.hashBase64 !== tx.hashBase64) {
            return { ok: false, status: 409, error: 'Tệp tin đã bị thay đổi hoặc không còn tồn tại sau khi gửi yêu cầu ký, không thể ghi nhận chữ ký!' };
        }

        let embedded = false;
        if (tx.mode === 'pdf-embed') {
            const doc = content && Array.isArray(content.documents) ? content.documents[0] : null;
            if (!doc || !doc.sig) {
                return { ok: false, status: 502, error: 'VNPT SmartCA báo ký thành công nhưng không trả về chữ ký (documents[0].sig). Tệp chưa bị thay đổi, vui lòng liên hệ VNPT với mã giao dịch: ' + tranId };
            }
            const leafDer = Buffer.from(tx.leafB64, 'base64');
            const toSign = Buffer.from(tx.toSignB64, 'base64');
            const signature = smartcaPdf.decodeSignature(doc.sig, leafDer);
            // Chặn nhúng chữ ký sai (khác dữ liệu đã gửi / khác chứng thư) để không làm hỏng tài liệu
            if (!smartcaPdf.verifyRsaSignature(toSign, signature, leafDer)) {
                return { ok: false, status: 502, error: 'Chữ ký VNPT trả về không khớp dữ liệu đã gửi ký hoặc chứng thư số của người ký. Đã dừng nhúng, tệp chưa bị thay đổi. Mã giao dịch: ' + tranId };
            }

            const pendingPath = path.join(SIGN_PENDING_DIR, path.basename(tx.pendingFile || ''));
            if (!tx.pendingFile || !fs.existsSync(pendingPath)) {
                return { ok: false, status: 410, error: 'Không còn bản PDF chờ nhúng chữ ký (có thể máy chủ đã khởi động lại hoặc quá hạn). Vui lòng ký lại.' };
            }
            const cms = smartcaPdf.buildCms({
                chainDer: tx.chainB64.map(b => Buffer.from(b, 'base64')),
                signerCertDer: leafDer,
                implicitAttrs: Buffer.from(tx.implicitB64, 'base64'),
                signature
            });
            const signedPdf = smartcaPdf.embedCms(fs.readFileSync(pendingPath), tx.contentsStart, cms);

            // Soát lại: phần PDF được ký phải đúng bằng digest đã đưa vào signed attributes
            const check = smartcaPdf.rangeDigest(signedPdf, tx.byteRange).toString('base64');
            if (check !== tx.contentDigestB64) {
                return { ok: false, status: 500, error: 'Kiểm tra sau nhúng không đạt (digest không khớp), tệp chưa bị thay đổi. Mã giao dịch: ' + tranId };
            }

            // Ghi nguyên tử: ghi file tạm rồi đổi tên đè lên tệp gốc
            const tmpOut = path.join(SIGN_PENDING_DIR, path.basename(tx.pendingFile) + '.out');
            fs.writeFileSync(tmpOut, signedPdf);
            try {
                fs.renameSync(tmpOut, path.resolve(ROOT_DIR, tx.filePath));
            } catch (renameErr) {
                // Khác ổ đĩa (EXDEV): sao chép rồi xóa tệp tạm
                fs.copyFileSync(tmpOut, path.resolve(ROOT_DIR, tx.filePath));
                fs.rmSync(tmpOut, { force: true });
            }
            embedded = true;
            console.log(`[PV INCONS] Đã nhúng chữ ký số PKCS#7 vào PDF: ${tx.filePath} (giao dịch ${tranId})`);
        }

        addSignatureRecord(tx.filePath, {
            tranId,
            signedBy: user ? (user.fullName || user.username) : 'Administrator',
            signerName: tx.signerName || '',
            certSerial: tx.certSerial || '',
            signedAt: new Date().toISOString(),
            embedded,
            mode: tx.mode
        });
        updateSignTx(tranId, { done: true, embedded });
        removePendingFile(tx);
        return { ok: true, embedded };
    } catch (err) {
        console.error('[PV INCONS] Lỗi hoàn tất ký số:', err);
        return { ok: false, status: 500, error: 'Không thể nhúng chữ ký vào tệp: ' + err.message };
    } finally {
        signFinalizing.delete(tranId);
    }
}

// 10.5. API Kiểm tra trạng thái giao dịch ký số (Get Transaction Info)
app.post('/api/vnpt/credentials/gettraninfo', requireCdeAuth, async (req, res) => {
    try {
        const accessToken = req.body && req.body.access_token;
        if (!accessToken) return res.status(400).json({ success: false, error: 'Thiếu access_token VNPT SmartCA, vui lòng xác thực lại tài khoản SmartCA!' });
        const { tranId } = req.body;
        const txInfo = readSignTx()[tranId];
        if (!txInfo || txInfo.username !== req.authUser.username) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy giao dịch ký số của bạn trên hệ thống CDE (hoặc đã quá 24 giờ).' });
        }

        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/gettraninfo`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
            body: JSON.stringify({ tranId: tranId })
        });

        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Lỗi kiểm tra trạng thái giao dịch' });

        // Mã trạng thái giao dịch theo tài liệu VNPT SmartCA v1.1 (mục 5.2.5)
        const TRAN_STATUS = {
            1: 'SUCCESS',
            4000: 'WAITING_FOR_SIGNER_CONFIRM',
            4001: 'EXPIRED',
            4002: 'SIGNER_REJECTED',
            4003: 'AUTHORIZE_KEY_FAILED',
            4004: 'SIGN_FAILED'
        };

        if (data.code !== 0 || !data.content) {
            return res.status(400).json({ success: false, error: data.message || data.codeDesc || 'Không lấy được trạng thái giao dịch ký số' });
        }

        const tranStatus = data.content.tranStatus;
        let embedded = false;
        // CHỈ ghi nhận / nhúng chữ ký khi giao dịch thành công (tranStatus = 1). 4000 là đang chờ người ký xác nhận.
        if (tranStatus === 1) {
            const result = await finalizeVnptSignature(tranId, txInfo, data.content, req.authUser);
            if (!result.ok) {
                return res.status(result.status || 500).json({ success: false, retry: !!result.retry, tranStatus, error: result.error });
            }
            embedded = !!result.embedded;
        }

        // Không trả nguyên data.content (có thể chứa dữ liệu tệp base64) về trình duyệt
        res.json({
            success: true,
            code: data.code,
            codeDesc: data.codeDesc,
            message: data.message,
            content: { tranId, tranStatus, tranStatusDesc: data.content.tranStatusDesc },
            tranStatus,
            tranStatusName: TRAN_STATUS[tranStatus] || 'UNKNOWN',
            embedded
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// (Đã gỡ API /api/vnpt/signature/embed: cho phép người dùng tự gửi chuỗi PKCS#7 bất kỳ để ghi vào PDF
//  trên server, không kiểm chứng được và không tạo ra chữ ký hợp lệ. Việc nhúng nay do finalizeVnptSignature đảm nhiệm.)

// 10.6. API NHẬN THÔNG BÁO (notifyUrl) TỪ VNPT SMARTCA - server to server, HTTP POST JSON {tranId, refTranId, status}
// Xác thực bằng SMARTCA_WEBHOOK_TOKEN gắn trong notifyUrl. Chỉ GHI NHẬN thông báo; việc lưu chữ ký vẫn do
// gettraninfo (tranStatus = 1) quyết định, vì dữ liệu callback không thể kiểm chứng độc lập.
function safeEqual(a, b) {
    const x = Buffer.from(String(a || ''));
    const y = Buffer.from(String(b || ''));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

app.post('/api/smartca/callback', (req, res) => {
    try {
        const expected = process.env.SMARTCA_WEBHOOK_TOKEN;
        if (!expected || !safeEqual(req.query.token, expected)) {
            return res.status(401).json({ success: false, error: 'Unauthorized' });
        }
        const { tranId, refTranId, status } = req.body || {};
        console.log('[VNPT SMARTCA NOTIFY]', JSON.stringify({ tranId, refTranId, status }));
        res.json({ success: true, received: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API Lấy danh sách chữ ký đã thực hiện (yêu cầu đăng nhập)
app.get('/api/vnpt/signatures', requireCdeAuth, (req, res) => {
    try {
        res.json(readSignaturesDB());
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 11. API QUẢN LÝ TẬP TIN & CDE (FILE SYSTEM & ISO 19650)
// ===============================================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const relPath = req.query.path || req.body.targetPath || '';
        const targetDir = path.join(ROOT_DIR, relPath.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
        cb(null, targetDir);
    },
    filename: (req, file, cb) => {
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage });

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE & Auth Backend Server đang hoạt động ổn định!' });
});

app.get('/api/files', (req, res) => {
    try {
        const subPath = (req.query.path || '').replace(/^database\/bim-vdc\/?/, '');
        const targetDir = path.join(ROOT_DIR, subPath);
        if (!fs.existsSync(targetDir)) return res.status(404).json({ error: 'Thư mục không tồn tại' });
        const items = fs.readdirSync(targetDir, { withFileTypes: true });
        res.json(items.map(item => ({
            name: item.name,
            isDirectory: item.isDirectory(),
            type: item.isDirectory() ? 'folder' : 'file',
            path: 'database/bim-vdc/' + path.join(subPath, item.name).replace(/\\/g, '/')
        })));
    } catch (error) { res.status(500).json({ error: error.message }); }
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

app.post('/api/upload', upload.single('file'), (req, res) => {
    res.json({ success: true, message: 'Tải lên tập tin thành công!' });
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
            return res.status(423).json({ success: false, error: 'Tệp đã bị thu hồi, không thể di chuyển/chuyển Gate! Hãy hủy thu hồi trước.' });
        }
        if (!fs.existsSync(destParent)) fs.mkdirSync(destParent, { recursive: true });
        fs.renameSync(srcFullPath, path.join(destParent, path.basename(srcFullPath)));
        const movedKey = path.posix.join(normRecallKey(targetDir), path.basename(srcFullPath));
        rekeyRecalls(sourcePath, movedKey);
        rekeyIssues(sourcePath, movedKey);
        res.json({ success: true, message: 'Di chuyển thành công!' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/copy', (req, res) => {
    try {
        const { sourcePath, targetDir } = req.body;
        const srcFullPath = path.join(ROOT_DIR, sourcePath.replace(/^database\/bim-vdc\/?/, ''));
        const destParent = path.join(ROOT_DIR, targetDir.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(srcFullPath)) return res.status(404).json({ success: false, error: 'Nguồn không tồn tại!' });
        if (!fs.existsSync(destParent)) fs.mkdirSync(destParent, { recursive: true });
        const destPath = path.join(destParent, path.basename(srcFullPath));
        if (fs.statSync(srcFullPath).isDirectory()) fs.cpSync(srcFullPath, destPath, { recursive: true });
        else fs.copyFileSync(srcFullPath, destPath);
        res.json({ success: true, message: 'Sao chép thành công!' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ===============================================================
// 12. HỆ THỐNG CHAT REALTIME (SSE API)
// ===============================================================
const CHAT_DATA_DIR = process.env.CHAT_DATA_DIR || path.join(__dirname, '..', 'CDE_CHAT_DATA');
const CHAT_LEGACY_FILE = path.join(BASE_DATABASE_DIR, 'chat.json');
let chatFilePath = path.join(CHAT_DATA_DIR, 'chat.json');
try {
    fs.mkdirSync(CHAT_DATA_DIR, { recursive: true });
    if (!fs.existsSync(chatFilePath) && fs.existsSync(CHAT_LEGACY_FILE)) {
        fs.copyFileSync(CHAT_LEGACY_FILE, chatFilePath);
    }
} catch (err) {
    chatFilePath = CHAT_LEGACY_FILE;
}

const CHAT_MAX_MESSAGES = 1000;
let chatMessages = [];
try {
    const parsed = JSON.parse(fs.readFileSync(chatFilePath, 'utf8'));
    if (Array.isArray(parsed)) chatMessages = parsed.slice(-CHAT_MAX_MESSAGES);
} catch (e) { }

function saveChatMessages() {
    try {
        const tmp = chatFilePath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(chatMessages));
        fs.renameSync(tmp, chatFilePath);
    } catch (e) { }
}

function findChatUser(username) {
    if (!username || typeof username !== 'string') return null;
    try {
        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8'));
        const u = users.find(x => x.username === username);
        if (!u) return null;
        return {
            username: u.username,
            fullName: u.fullName || u.username,
            role: (u.role || '').toString().toUpperCase(),
            groups: Array.isArray(u.groups) ? u.groups.map(g => String(g).toLowerCase()) : []
        };
    } catch (e) {
        return null;
    }
}

const chatClients = new Set();

function chatSend(res, event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function chatBroadcast(event, data, room) {
    for (const c of chatClients) {
        if (room && c.room !== room) continue;
        try { chatSend(c.res, event, data); } catch (e) { }
    }
}

function chatOnlineList(room) {
    const map = new Map();
    for (const c of chatClients) {
        if (room && c.room !== room) continue;
        map.set(c.user.username, { username: c.user.username, fullName: c.user.fullName, role: c.user.role });
    }
    return Array.from(map.values());
}

app.get('/api/chat/stream', (req, res) => {
    const user = findChatUser(req.query.username);
    if (!user) return res.status(403).json({ success: false, message: 'Unauthorized' });

    const room = req.query.room === 'site' ? 'site' : 'general';

    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });
    res.write('retry: 3000\n\n');

    const client = { res, user, room };
    chatClients.add(client);

    chatSend(res, 'presence', chatOnlineList(room));
    chatBroadcast('presence', chatOnlineList(room), room);

    const keepAliveTimer = setInterval(() => {
        try { res.write(': keepalive\n\n'); } catch (e) { }
    }, 25000);

    req.on('close', () => {
        clearInterval(keepAliveTimer);
        chatClients.delete(client);
        chatBroadcast('presence', chatOnlineList(room), room);
    });
});

app.get('/api/chat/history', (req, res) => {
    const room = req.query.room === 'site' ? 'site' : 'general';
    const list = chatMessages.filter(m => (m.room || 'general') === room);
    res.json({ success: true, messages: list.slice(-100) });
});

app.post('/api/chat/send', (req, res) => {
    const { username, text, room: reqRoom } = req.body;
    const user = findChatUser(username);
    if (!user || !text) return res.status(400).json({ success: false, message: 'Invalid data' });

    const room = reqRoom === 'site' ? 'site' : 'general';
    const msg = {
        id: Date.now().toString(36) + Math.random().toString(36).substring(2, 7),
        username: user.username,
        fullName: user.fullName,
        role: user.role,
        text: text.trim(),
        ts: Date.now(),
        room
    };

    chatMessages.push(msg);
    if (chatMessages.length > CHAT_MAX_MESSAGES) chatMessages.shift();
    saveChatMessages();

    chatBroadcast('chat', msg, room);
    res.json({ success: true, message: msg });
});

// ===============================================================
// 13. STATIC SERVE & KHỞI ĐỘNG SERVER
// ===============================================================
app.use('/files', express.static(ROOT_DIR));

app.use('/vendor/three', express.static(path.join(__dirname, 'node_modules', 'three')));
app.use('/vendor/web-ifc', express.static(path.join(__dirname, 'node_modules', 'web-ifc')));
['three', 'web-ifc'].forEach(m => {
    if (!fs.existsSync(path.join(__dirname, 'node_modules', m))) {
        console.warn(`⚠️ Thiếu thư viện "${m}" cho Xem 3D. Chạy: npm i three@0.160.0 web-ifc@0.0.57`);
    }
});
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 PV INCONS Server đã khởi động hoàn chỉnh tại cổng ${PORT}`);
});