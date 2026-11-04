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
    on: {
      error: (err, req, res) => {
        if (!res.headersSent) {
          res.status(500).send('Không thể kết nối tới Revit Server IIS service nội bộ!');
        }
      }
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

        const token = jwt.sign(tokenPayload, JWT_SECRET, {
            expiresIn: '12h',
            jwtid: crypto.randomBytes(16).toString('hex')
        });

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

function cleanVp(v) {
    const ok3 = a => Array.isArray(a) && a.length === 3 && a.every(Number.isFinite);
    if (!v || !ok3(v.p) || !ok3(v.t)) return null;
    return { p: v.p, t: v.t, u: ok3(v.u) ? v.u : [0, 1, 0], f: Number.isFinite(v.f) ? v.f : 45 };
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
                status: String(c.status || 'Open').slice(0, 40),
                prio: String(c.prio || 'Normal').slice(0, 40),
                vp: cleanVp(c.vp),
                shot: (typeof c.shot === 'string' && c.shot.length < 250000 && /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(c.shot)) ? c.shot : '',
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
const VNPT_AUTH_SESSIONS = new Map();
const VNPT_SESSION_REFRESHES = new Map();

function getCdeSessionKey(req) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) throw new Error('Không xác định được phiên đăng nhập CDE.');
    return crypto.createHash('sha256').update(token).digest('hex');
}

function storeVnptAuthSession(req, tokenData, credentialIds, retainSession = true) {
    const sessionKey = getCdeSessionKey(req);
    const cdePayload = jwt.decode((req.headers.authorization || '').slice(7).trim());
    const cdeExpiresAt = cdePayload && cdePayload.exp
        ? cdePayload.exp * 1000
        : Date.now() + 12 * 60 * 60 * 1000;
    for (const [key, session] of VNPT_AUTH_SESSIONS) {
        if (session.expiresAt <= Date.now()) VNPT_AUTH_SESSIONS.delete(key);
    }
    VNPT_AUTH_SESSIONS.set(sessionKey, {
        username: req.authUser.username,
        credentialIds,
        retainSession,
        cdeExpiresAt,
        expiresAt: retainSession ? cdeExpiresAt : Math.min(cdeExpiresAt, Date.now() + 15 * 60 * 1000),
        credentialsEncrypted: encryptSignCredentials({
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token || '',
            expiresAt: Number(tokenData.expires_in) > 0
                ? Date.now() + Number(tokenData.expires_in) * 1000
                : 0
        })
    });
}

async function getVnptAuthSession(req, forceRefresh = false) {
    const sessionKey = getCdeSessionKey(req);
    let session = VNPT_AUTH_SESSIONS.get(sessionKey);
    if (!session || session.username !== req.authUser.username || session.expiresAt <= Date.now()) {
        VNPT_AUTH_SESSIONS.delete(sessionKey);
        const error = new Error('Chưa có phiên VNPT SmartCA. Vui lòng xác thực tài khoản để tiếp tục.');
        error.status = 401;
        throw error;
    }

    let credentials = decryptSignCredentials(session.credentialsEncrypted);
    if (credentials.refreshToken && (forceRefresh || (credentials.expiresAt && credentials.expiresAt <= Date.now() + 30000))) {
        let refreshTask = VNPT_SESSION_REFRESHES.get(sessionKey);
        if (!refreshTask) {
            const previousCredentials = credentials;
            refreshTask = (async () => {
                const params = new URLSearchParams({
                    grant_type: 'refresh_token',
                    client_id: VNPT_SMARTCA_CLIENT_ID,
                    client_secret: VNPT_SMARTCA_CLIENT_SECRET,
                    refresh_token: previousCredentials.refreshToken,
                    scope: 'sign offline_access openid profile email'
                });
                const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/auth/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: params
                });
                const refreshed = await response.json().catch(() => ({}));
                if (!response.ok || !refreshed.access_token) {
                    throw new Error(refreshed.error_description || refreshed.error || 'Không thể làm mới phiên VNPT SmartCA. Vui lòng xác thực lại tài khoản.');
                }
                const latestSession = VNPT_AUTH_SESSIONS.get(sessionKey);
                if (!latestSession || latestSession.expiresAt <= Date.now()) {
                    throw new Error('Phiên đăng nhập CDE đã hết hạn. Vui lòng đăng nhập lại.');
                }
                const latestCredentials = decryptSignCredentials(latestSession.credentialsEncrypted);
                if (latestCredentials.refreshToken === previousCredentials.refreshToken) {
                    latestSession.credentialsEncrypted = encryptSignCredentials({
                        accessToken: refreshed.access_token,
                        refreshToken: refreshed.refresh_token || previousCredentials.refreshToken,
                        expiresAt: Number(refreshed.expires_in) > 0
                            ? Date.now() + Number(refreshed.expires_in) * 1000
                            : 0
                    });
                }
            })();
            VNPT_SESSION_REFRESHES.set(sessionKey, refreshTask);
        }
        try {
            await refreshTask;
        } finally {
            if (VNPT_SESSION_REFRESHES.get(sessionKey) === refreshTask) {
                VNPT_SESSION_REFRESHES.delete(sessionKey);
            }
        }
        session = VNPT_AUTH_SESSIONS.get(sessionKey);
        if (!session || session.expiresAt <= Date.now()) {
            throw new Error('Phiên đăng nhập CDE đã hết hạn. Vui lòng đăng nhập lại.');
        }
        credentials = decryptSignCredentials(session.credentialsEncrypted);
    }

    return {
        ...credentials,
        credentialIds: session.credentialIds,
        sessionKey,
        retainSession: session.retainSession
    };
}

async function requestVnptWithSession(req, endpoint, body) {
    let session = await getVnptAuthSession(req);
    let response = await fetch(`${VNPT_SMARTCA_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session.accessToken}` },
        body: JSON.stringify(body)
    });
    if (response.status === 401 || response.status === 403) {
        session = await getVnptAuthSession(req, true);
        response = await fetch(`${VNPT_SMARTCA_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session.accessToken}` },
            body: JSON.stringify(body)
        });
    }
    return { response, session };
}

function syncVnptSessionFromTransaction(tx, previousCredentials, refreshedCredentials) {
    if (!tx.vnptSessionKey) return;
    const session = VNPT_AUTH_SESSIONS.get(tx.vnptSessionKey);
    if (!session || session.expiresAt <= Date.now()) return;
    const sessionCredentials = decryptSignCredentials(session.credentialsEncrypted);
    if (sessionCredentials.refreshToken === previousCredentials.refreshToken) {
        session.credentialsEncrypted = encryptSignCredentials(refreshedCredentials);
    }
}

const SIGNATURES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'signatures.json');
const FILE_METADATA_FILE_PATH = path.join(BASE_DATABASE_DIR, 'file_metadata.json');

if (!fs.existsSync(SIGNATURES_FILE_PATH)) {
    fs.writeFileSync(SIGNATURES_FILE_PATH, JSON.stringify({}, null, 2), 'utf8');
}
if (!fs.existsSync(FILE_METADATA_FILE_PATH)) {
    fs.writeFileSync(FILE_METADATA_FILE_PATH, JSON.stringify({}, null, 2), 'utf8');
}

function readFileMetadataDB() {
    return JSON.parse(fs.readFileSync(FILE_METADATA_FILE_PATH, 'utf8') || '{}');
}

function writeFileMetadataDB(db) {
    const tmp = `${FILE_METADATA_FILE_PATH}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
        fs.renameSync(tmp, FILE_METADATA_FILE_PATH);
        return true;
    } catch (error) {
        try { fs.rmSync(tmp, { force: true }); } catch (cleanupError) { /* preserve the write error */ }
        console.error('Lỗi ghi file_metadata.json:', error);
        return false;
    }
}

function rekeyFileMetadata(oldPath, newPath) {
    const oldKey = normRecallKey(oldPath);
    const newKey = normRecallKey(newPath);
    const db = readFileMetadataDB();
    let changed = false;
    Object.keys(db).forEach(key => {
        if (key === oldKey || key.startsWith(oldKey + '/')) {
            db[newKey + key.slice(oldKey.length)] = db[key];
            delete db[key];
            changed = true;
        }
    });
    if (changed) writeFileMetadataDB(db);
}

function removeFileMetadata(itemPath) {
    const key = normRecallKey(itemPath);
    const db = readFileMetadataDB();
    let changed = false;
    Object.keys(db).forEach(existingKey => {
        if (existingKey === key || existingKey.startsWith(key + '/')) {
            delete db[existingKey];
            changed = true;
        }
    });
    if (changed) writeFileMetadataDB(db);
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
const SIGN_TX_ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
if (!fs.existsSync(SIGN_PENDING_DIR)) fs.mkdirSync(SIGN_PENDING_DIR, { recursive: true });

function readSignTx() {
    if (!fs.existsSync(SIGN_TX_FILE_PATH)) return {};
    return JSON.parse(fs.readFileSync(SIGN_TX_FILE_PATH, 'utf8') || '{}');
}
function encryptSignCredentials(credentials) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', SIGN_TX_ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(credentials), 'utf8'), cipher.final()]);
    return {
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        data: encrypted.toString('base64')
    };
}
function decryptSignCredentials(encrypted) {
    if (!encrypted || !encrypted.iv || !encrypted.tag || !encrypted.data) {
        throw new Error('Giao dịch không có thông tin xác thực VNPT đã mã hóa.');
    }
    const decipher = crypto.createDecipheriv('aes-256-gcm', SIGN_TX_ENCRYPTION_KEY, Buffer.from(encrypted.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
    return JSON.parse(Buffer.concat([
        decipher.update(Buffer.from(encrypted.data, 'base64')),
        decipher.final()
    ]).toString('utf8'));
}
function writeSignTx(db) {
    const tmp = `${SIGN_TX_FILE_PATH}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
        fs.renameSync(tmp, SIGN_TX_FILE_PATH);
    } catch (error) {
        try { fs.rmSync(tmp, { force: true }); } catch (cleanupError) { /* preserve the write error */ }
        throw error;
    }
}
function removePendingFile(tx) {
    if (!tx) return;
    for (const fileName of [tx.pendingFile, tx.finalOutput]) {
        if (!fileName) continue;
        try { fs.rmSync(path.join(SIGN_PENDING_DIR, path.basename(fileName)), { force: true }); } catch (e) { }
    }
}
function saveSignTx(tranId, info) {
    if (!tranId) throw new Error('Thiếu mã giao dịch VNPT.');
    const db = readSignTx();
    if (db[tranId]) throw new Error(`Mã giao dịch VNPT ${tranId} đã tồn tại.`);
    const now = Date.now();
    Object.keys(db).forEach(k => {
        if (now - (db[k].createdAt || 0) > SIGN_TX_TTL_MS) { removePendingFile(db[k]); delete db[k]; }
    });
    db[tranId] = { ...info, createdAt: now };
    writeSignTx(db);
}
function updateSignTx(tranId, patch) {
    const db = readSignTx();
    if (!db[tranId]) throw new Error(`Không tìm thấy giao dịch ký ${tranId} để cập nhật.`);
    db[tranId] = { ...db[tranId], ...patch };
    writeSignTx(db);
    return db[tranId];
}

function readSignaturesDB() {
    if (!fs.existsSync(SIGNATURES_FILE_PATH)) return {};
    return JSON.parse(fs.readFileSync(SIGNATURES_FILE_PATH, 'utf8') || '{}');
}

// Ghi nhận MỘT lượt ký. Một tệp có thể có nhiều người ký nên lưu danh sách `signatures`;
// signedBy / signedAt luôn là của lượt ký gần nhất (mir.html đang đọc 2 trường này để hiện huy hiệu "✓ Đã ký").
function addSignatureRecord(filePath, entry) {
    const db = readSignaturesDB();
    const key = normRecallKey(filePath);
    const old = db[key] || {};
    const signatures = Array.isArray(old.signatures) ? old.signatures : [];
    if (!signatures.some(signature => signature.tranId === entry.tranId)) {
        signatures.push(entry);
    }
    const latestSignature = signatures[signatures.length - 1];
    db[key] = {
        filePath: key,
        fileName: path.basename(filePath),
        signatures,
        signatureCount: signatures.length,
        signedBy: latestSignature.signedBy,
        signedAt: latestSignature.signedAt
    };
    const tmp = `${SIGNATURES_FILE_PATH}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
        fs.renameSync(tmp, SIGNATURES_FILE_PATH);
    } catch (e) {
        try { fs.rmSync(tmp, { force: true }); } catch (cleanupError) { /* preserve the write error */ }
        throw e;
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
        if (typeof username !== 'string' || !username.trim() || typeof password !== 'string' || !password) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập đầy đủ tài khoản và mật khẩu VNPT SmartCA.' });
        }
        const params = new URLSearchParams();
        params.append('grant_type', 'password');
        params.append('client_id', VNPT_SMARTCA_CLIENT_ID);
        params.append('client_secret', VNPT_SMARTCA_CLIENT_SECRET);
        params.append('username', username.trim());
        params.append('password', password);
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
        if (!data.access_token) {
            return res.status(502).json({ success: false, error: 'VNPT không trả về access token.' });
        }
        const credentialResponse = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/list`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${data.access_token}` },
            body: JSON.stringify({})
        });
        const credentialData = await credentialResponse.json().catch(() => ({}));
        if (!credentialResponse.ok || credentialData.code !== 0) {
            return res.status(credentialResponse.status || 502).json({
                success: false,
                error: credentialData.message || credentialData.error_description || 'Không lấy được danh sách chứng thư số VNPT.'
            });
        }
        const credentialIds = Array.isArray(credentialData.content) ? credentialData.content : [];
        if (credentialIds.length === 0) {
            return res.status(400).json({ success: false, error: 'Tài khoản VNPT chưa được cấp chứng thư số hoạt động.' });
        }
        storeVnptAuthSession(req, data, credentialIds, req.body.retain_session !== false);
        res.json({ success: true, content: credentialIds });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.2. API Lấy danh sách Chứng thư số (List credential)
app.post('/api/vnpt/credentials/list', requireCdeAuth, async (req, res) => {
    try {
        const session = await getVnptAuthSession(req);
        const accessToken = session.accessToken;
        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/list`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
            body: JSON.stringify({})
        });
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json({ success: false, error: data.message || 'Lỗi lấy danh sách CTS VNPT' });
        res.json({ success: true, ...data });
    } catch (error) {
        res.status(error.status || 500).json({ success: false, error: error.message });
    }
});

app.post('/api/vnpt/session', requireCdeAuth, async (req, res) => {
    try {
        const session = await getVnptAuthSession(req);
        if (!session.retainSession) {
            return res.status(401).json({ success: false, error: 'Phiên VNPT hiện tại không được lưu để dùng cho lần ký tiếp theo.' });
        }
        res.json({ success: true, content: session.credentialIds });
    } catch (error) {
        res.status(error.status || 500).json({ success: false, error: error.message });
    }
});

app.post('/api/vnpt/session/retention', requireCdeAuth, (req, res) => {
    try {
        const sessionKey = getCdeSessionKey(req);
        const session = VNPT_AUTH_SESSIONS.get(sessionKey);
        if (!session || session.username !== req.authUser.username || session.expiresAt <= Date.now()) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy phiên VNPT đang hoạt động.' });
        }
        session.retainSession = req.body.retain_session === true;
        session.expiresAt = session.retainSession
            ? session.cdeExpiresAt
            : Math.min(session.cdeExpiresAt, Date.now() + 15 * 60 * 1000);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/vnpt/session/logout', requireCdeAuth, (req, res) => {
    try {
        const sessionKey = getCdeSessionKey(req);
        VNPT_AUTH_SESSIONS.delete(sessionKey);
        VNPT_SESSION_REFRESHES.delete(sessionKey);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.3. API Lấy thông tin chi tiết Chứng thư số (Credential Info)
app.post('/api/vnpt/credentials/info', requireCdeAuth, async (req, res) => {
    try {
        const session = await getVnptAuthSession(req);
        const accessToken = session.accessToken;
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
        res.status(error.status || 500).json({ success: false, error: error.message });
    }
});

// 10.4. API Gửi yêu cầu ký Hash (SignHash) tới VNPT SmartCA
//  - PDF  : tạo sẵn vùng chữ ký trong PDF (cập nhật tăng dần, giữ nguyên các chữ ký trước đó), dựng "signed attributes"
//           PKCS#7 và gửi SHA-256 của chúng cho VNPT ký. Khi VNPT báo thành công, chữ ký được NHÚNG vào chính file PDF
//           (xem finalizeVnptSignature). Phải băm đúng đối tượng này thì Adobe/pdfsig mới xác thực được chữ ký.
//  - Khác : chỉ ký SHA-256 của tệp và ghi nhận trong signatures.json (không thể nhúng vào định dạng khác).
app.post('/api/vnpt/signature/signhash', requireCdeAuth, async (req, res) => {
    try {
        const { credentialId, filePath, description, retain_session } = req.body;
        if (!credentialId) return res.status(400).json({ success: false, error: 'Thiếu credentialId (Chứng thư số) cần dùng để ký!' });
        const vnptSession = await getVnptAuthSession(req);
        if (typeof retain_session === 'boolean') {
            vnptSession.retainSession = retain_session;
            const sessionRecord = VNPT_AUTH_SESSIONS.get(vnptSession.sessionKey);
            if (sessionRecord) {
                sessionRecord.retainSession = retain_session;
                sessionRecord.expiresAt = retain_session
                    ? sessionRecord.cdeExpiresAt
                    : Math.min(sessionRecord.cdeExpiresAt, Date.now() + 15 * 60 * 1000);
            }
        }
        if (!vnptSession.credentialIds.includes(credentialId)) {
            return res.status(403).json({ success: false, error: 'Chứng thư số không thuộc phiên VNPT SmartCA đang hoạt động.' });
        }
        let accessToken = vnptSession.accessToken;

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
            let infoRes = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/info`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
                body: JSON.stringify({ credentialId, certificates: 'chain', certInfo: true, authInfo: false })
            });
            if (infoRes.status === 401 || infoRes.status === 403) {
                const refreshedSession = await getVnptAuthSession(req, true);
                accessToken = refreshedSession.accessToken;
                vnptSession.refreshToken = refreshedSession.refreshToken;
                vnptSession.expiresAt = refreshedSession.expiresAt;
                infoRes = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/info`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
                    body: JSON.stringify({ credentialId, certificates: 'chain', certInfo: true, authInfo: false })
                });
            }
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

        const refTranId = `PVI-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        let response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/signature/signhash`, {
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

        if (response.status === 401 || response.status === 403) {
            const refreshedSession = await getVnptAuthSession(req, true);
            accessToken = refreshedSession.accessToken;
            vnptSession.refreshToken = refreshedSession.refreshToken;
            vnptSession.expiresAt = refreshedSession.expiresAt;
            response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/signature/signhash`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
                body: JSON.stringify({
                    credentialId,
                    refTranId,
                    ...(notifyUrl && process.env.PUBLIC_API_BASE_URL ? { notifyUrl } : {}),
                    description: description || 'Ký số tài liệu CDE PV Incons qua VNPT SmartCA',
                    datas: [{ name: fileInfo.fileName, hash: hashToSign }]
                })
            });
        }
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
        try {
            saveSignTx(data.content.tranId, {
                filePath: fileInfo.relPath,
                username: req.authUser.username,
                signedBy: req.authUser.fullName || req.authUser.username,
                refTranId,
                pendingFile,
                credentialsEncrypted: encryptSignCredentials({
                    accessToken,
                    refreshToken: vnptSession.refreshToken,
                    expiresAt: vnptSession.expiresAt
                }),
                vnptSessionKey: vnptSession.sessionKey,
                ...txExtra
            });
        } catch (error) {
            removePendingFile({ pendingFile });
            console.error(`[PV INCONS] Không lưu được giao dịch VNPT ${data.content.tranId}:`, error);
            return res.status(500).json({
                success: false,
                tranId: data.content.tranId,
                error: `VNPT đã tạo giao dịch ${data.content.tranId} nhưng CDE không lưu được trạng thái giao dịch. Không gửi lại yêu cầu ký để tránh tạo giao dịch trùng; vui lòng báo quản trị viên.`
            });
        }

        if (!vnptSession.retainSession) {
            VNPT_AUTH_SESSIONS.delete(vnptSession.sessionKey);
        }
        scheduleSignTxReconciliation(data.content.tranId);
        res.json({ success: true, ...data, filePath, fileName: fileInfo.fileName, mode: txExtra.mode });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Hoàn tất giao dịch ký khi VNPT báo tranStatus = 1: kiểm tra chữ ký, đóng gói PKCS#7 và nhúng vào PDF.
// Idempotent (frontend poll, callback và worker có thể cùng kiểm tra).
const signFinalizing = new Set();
async function finalizeVnptSignature(tranId, tx, content, user) {
    if (tx.done) return { ok: true, already: true, embedded: !!tx.embedded };
    if (signFinalizing.has(tranId)) {
        return { ok: false, status: 409, retry: true, error: 'Hệ thống đang nhúng chữ ký vào tệp, vui lòng chờ giây lát...' };
    }
    signFinalizing.add(tranId);
    try {
        const finalOutput = tx.finalOutput || (tx.pendingFile ? `${path.basename(tx.pendingFile)}.signed` : '');
        const stagedOutputPath = finalOutput
            ? path.join(SIGN_PENDING_DIR, path.basename(finalOutput))
            : '';
        const stagedOutputExists = !!tx.finalizing && !!stagedOutputPath && fs.existsSync(stagedOutputPath);
        let embedded = !!tx.fileEmbedded;

        if (!tx.fileEmbedded && !stagedOutputExists) {
            const current = hashCdeFile(tx.filePath);
            if (current.error || current.hashBase64 !== tx.hashBase64) {
                return { ok: false, status: 409, error: 'Tệp tin đã bị thay đổi hoặc không còn tồn tại sau khi gửi yêu cầu ký, không thể ghi nhận chữ ký!' };
            }
        }

        if (tx.mode === 'pdf-embed') {
            if (!tx.fileEmbedded) {
                if (!stagedOutputExists) {
                    const doc = content && Array.isArray(content.documents) ? content.documents[0] : null;
                    if (!doc || !doc.sig) {
                        return { ok: false, status: 502, error: 'VNPT SmartCA báo ký thành công nhưng không trả về chữ ký (documents[0].sig). Tệp chưa bị thay đổi, vui lòng liên hệ VNPT với mã giao dịch: ' + tranId };
                    }
                    const leafDer = Buffer.from(tx.leafB64, 'base64');
                    const toSign = Buffer.from(tx.toSignB64, 'base64');
                    const signature = smartcaPdf.decodeSignature(doc.sig, leafDer);
                    if (!smartcaPdf.verifyRsaSignature(toSign, signature, leafDer)) {
                        return { ok: false, status: 502, error: 'Chữ ký VNPT trả về không khớp dữ liệu đã gửi ký hoặc chứng thư số của người ký. Đã dừng nhúng, tệp chưa bị thay đổi. Mã giao dịch: ' + tranId };
                    }

                    const pendingPath = path.join(SIGN_PENDING_DIR, path.basename(tx.pendingFile || ''));
                    if (!tx.pendingFile || !fs.existsSync(pendingPath)) {
                        return { ok: false, status: 410, error: 'Không còn bản PDF chờ nhúng chữ ký. Vui lòng ký lại.' };
                    }
                    const cms = smartcaPdf.buildCms({
                        chainDer: tx.chainB64.map(b => Buffer.from(b, 'base64')),
                        signerCertDer: leafDer,
                        implicitAttrs: Buffer.from(tx.implicitB64, 'base64'),
                        signature
                    });
                    const signedPdf = smartcaPdf.embedCms(fs.readFileSync(pendingPath), tx.contentsStart, cms);
                    const check = smartcaPdf.rangeDigest(signedPdf, tx.byteRange).toString('base64');
                    if (check !== tx.contentDigestB64) {
                        return { ok: false, status: 500, error: 'Kiểm tra sau nhúng không đạt (digest không khớp), tệp chưa bị thay đổi. Mã giao dịch: ' + tranId };
                    }

                    fs.writeFileSync(stagedOutputPath, signedPdf);
                    tx = updateSignTx(tranId, {
                        finalizing: true,
                        finalOutput,
                        signedAt: tx.signedAt || new Date().toISOString()
                    });
                }

                if (!tx.fileEmbedded) {
                    const targetPath = path.resolve(ROOT_DIR, tx.filePath);
                    const rootPath = path.resolve(ROOT_DIR);
                    if (!targetPath.startsWith(rootPath + path.sep)) {
                        return { ok: false, status: 400, error: 'Đường dẫn đích của tệp ký không hợp lệ.' };
                    }
                    const targetTempPath = `${targetPath}.sign-${crypto.randomBytes(6).toString('hex')}.tmp`;
                    fs.copyFileSync(stagedOutputPath, targetTempPath);
                    try {
                        fs.renameSync(targetTempPath, targetPath);
                    } catch (renameError) {
                        fs.copyFileSync(targetTempPath, targetPath);
                        fs.rmSync(targetTempPath, { force: true });
                    }
                    tx = updateSignTx(tranId, { fileEmbedded: true, embedded: true });
                    embedded = true;
                    console.log(`[PV INCONS] Đã nhúng chữ ký số PKCS#7 vào PDF: ${tx.filePath} (giao dịch ${tranId})`);
                }
            }
        }

        addSignatureRecord(tx.filePath, {
            tranId,
            signedBy: user ? (user.fullName || user.username) : 'Administrator',
            signerName: tx.signerName || '',
            certSerial: tx.certSerial || '',
            signedAt: tx.signedAt || new Date().toISOString(),
            embedded,
            mode: tx.mode
        });
        updateSignTx(tranId, { done: true, embedded, completedAt: Date.now() });
        removePendingFile(tx);
        if (finalOutput) fs.rmSync(stagedOutputPath, { force: true });
        return { ok: true, embedded };
    } catch (err) {
        console.error('[PV INCONS] Lỗi hoàn tất ký số:', err);
        return { ok: false, status: 500, error: 'Không thể nhúng chữ ký vào tệp: ' + err.message };
    } finally {
        signFinalizing.delete(tranId);
    }
}

async function getSignTransactionAccessToken(tranId, tx, forceRefresh = false) {
    const credentials = decryptSignCredentials(tx.credentialsEncrypted);
    if (!credentials.accessToken) throw new Error('Giao dịch thiếu access token VNPT.');

    if (credentials.refreshToken && (forceRefresh || (credentials.expiresAt && credentials.expiresAt <= Date.now() + 30000))) {
        const previousCredentials = { ...credentials };
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: VNPT_SMARTCA_CLIENT_ID,
            client_secret: VNPT_SMARTCA_CLIENT_SECRET,
            refresh_token: credentials.refreshToken,
            scope: 'sign offline_access openid profile email'
        });
        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/auth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params
        });
        const refreshed = await response.json().catch(() => ({}));
        if (!response.ok || !refreshed.access_token) {
            throw new Error(refreshed.error_description || refreshed.error || 'Không thể làm mới access token VNPT cho giao dịch ký.');
        }
        credentials.accessToken = refreshed.access_token;
        credentials.refreshToken = refreshed.refresh_token || credentials.refreshToken;
        credentials.expiresAt = Number(refreshed.expires_in) > 0
            ? Date.now() + Number(refreshed.expires_in) * 1000
            : 0;
        tx = updateSignTx(tranId, { credentialsEncrypted: encryptSignCredentials(credentials) });
        syncVnptSessionFromTransaction(tx, previousCredentials, credentials);
    }

    return credentials.accessToken;
}

async function pollAndFinalizeSignTransaction(tranId, tx, accessToken, scheduleRetry = false) {
    const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/csc/credentials/gettraninfo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
        body: JSON.stringify({ tranId })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        return { success: false, status: response.status, error: data.message || 'Lỗi kiểm tra trạng thái giao dịch' };
    }
    if (data.code !== 0 || !data.content) {
        return { success: false, status: 400, error: data.message || data.codeDesc || 'Không lấy được trạng thái giao dịch ký số' };
    }

    const tranStatus = data.content.tranStatus;
    let embedded = false;
    if (tranStatus === 1) {
        const result = await finalizeVnptSignature(tranId, tx, data.content, {
            username: tx.username,
            fullName: tx.signedBy || tx.username
        });
        if (!result.ok) {
            return { success: false, status: result.status || 500, retry: !!result.retry, tranStatus, error: result.error };
        }
        embedded = !!result.embedded;
    } else if (tranStatus === 4000 && scheduleRetry) {
        const attempts = (tx.reconcileAttempts || 0) + 1;
        const delay = Math.min(15000 * (2 ** Math.min(attempts - 1, 4)), 300000);
        updateSignTx(tranId, {
            reconcileAttempts: attempts,
            nextPollAt: Date.now() + delay
        });
    } else if ([4001, 4002, 4003, 4004].includes(tranStatus) && !tx.terminal) {
        updateSignTx(tranId, { terminal: true, terminalStatus: tranStatus, nextPollAt: 0 });
    }

    const TRAN_STATUS = {
        1: 'SUCCESS',
        4000: 'WAITING_FOR_SIGNER_CONFIRM',
        4001: 'EXPIRED',
        4002: 'SIGNER_REJECTED',
        4003: 'AUTHORIZE_KEY_FAILED',
        4004: 'SIGN_FAILED'
    };
    return {
        success: true,
        code: data.code,
        codeDesc: data.codeDesc,
        message: data.message,
        content: { tranId, tranStatus, tranStatusDesc: data.content.tranStatusDesc },
        tranStatus,
        tranStatusName: TRAN_STATUS[tranStatus] || 'UNKNOWN',
        embedded
    };
}

const signTxProcessing = new Set();
async function reconcileSignTransaction(tranId, force = false) {
    if (signTxProcessing.has(tranId)) return;
    signTxProcessing.add(tranId);
    try {
        const tx = readSignTx()[tranId];
        if (!tx || tx.done || tx.terminal) return;
        if (!force && tx.nextPollAt && tx.nextPollAt > Date.now()) return;
        let accessToken = await getSignTransactionAccessToken(tranId, tx);
        let result = await pollAndFinalizeSignTransaction(tranId, tx, accessToken, true);
        if (!result.success && [401, 403].includes(result.status)) {
            const latestTx = readSignTx()[tranId];
            accessToken = await getSignTransactionAccessToken(tranId, latestTx, true);
            result = await pollAndFinalizeSignTransaction(tranId, latestTx, accessToken, true);
        }
        if (!result.success) {
            console.warn(`[PV INCONS] Chưa thể hoàn tất giao dịch VNPT ${tranId}: ${result.error}`);
            const attempts = (tx.reconcileAttempts || 0) + 1;
            const delay = Math.min(15000 * (2 ** Math.min(attempts - 1, 4)), 300000);
            updateSignTx(tranId, {
                reconcileAttempts: attempts,
                nextPollAt: Date.now() + delay
            });
        }
    } catch (error) {
        console.error(`[PV INCONS] Lỗi rà soát giao dịch VNPT ${tranId}:`, error.message);
        try {
            const tx = readSignTx()[tranId];
            if (tx && !tx.done && !tx.terminal) {
                const attempts = (tx.reconcileAttempts || 0) + 1;
                const delay = Math.min(15000 * (2 ** Math.min(attempts - 1, 4)), 300000);
                updateSignTx(tranId, {
                    reconcileAttempts: attempts,
                    nextPollAt: Date.now() + delay
                });
            }
        } catch (persistError) {
            console.error(`[PV INCONS] Không lưu được lịch thử lại giao dịch ${tranId}:`, persistError.message);
        }
    } finally {
        signTxProcessing.delete(tranId);
    }
}

function scheduleSignTxReconciliation(tranId) {
    const timer = setTimeout(() => reconcileSignTransaction(tranId, true), 100);
    if (typeof timer.unref === 'function') timer.unref();
}

let signTxReconciliationRunning = false;
async function reconcilePendingSignTransactions() {
    if (signTxReconciliationRunning) return;
    signTxReconciliationRunning = true;
    try {
        const transactions = readSignTx();
        for (const [tranId, tx] of Object.entries(transactions)) {
            if (!tx.done && !tx.terminal
                && Date.now() - (tx.createdAt || 0) <= SIGN_TX_TTL_MS
                && (!tx.nextPollAt || tx.nextPollAt <= Date.now())) {
                await reconcileSignTransaction(tranId);
            }
        }
    } catch (error) {
        console.error('[PV INCONS] Không thể đọc danh sách giao dịch ký cần rà soát:', error.message);
    } finally {
        signTxReconciliationRunning = false;
    }
}

// 10.5. API Kiểm tra trạng thái giao dịch ký số (Get Transaction Info)
app.post('/api/vnpt/credentials/gettraninfo', requireCdeAuth, async (req, res) => {
    try {
        const accessToken = req.body && req.body.access_token;
        const { tranId } = req.body;
        let txInfo = readSignTx()[tranId];
        if (!txInfo || txInfo.username !== req.authUser.username) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy giao dịch ký số của bạn trên hệ thống CDE (hoặc đã quá 24 giờ).' });
        }
        if (!txInfo.credentialsEncrypted && accessToken) {
            txInfo = updateSignTx(tranId, {
                credentialsEncrypted: encryptSignCredentials({
                    accessToken,
                    refreshToken: typeof req.body.refresh_token === 'string' ? req.body.refresh_token : '',
                    expiresAt: Number(req.body.expires_in) > 0
                        ? Date.now() + Number(req.body.expires_in) * 1000
                        : 0
                })
            });
            scheduleSignTxReconciliation(tranId);
        }
        const transactionAccessToken = await getSignTransactionAccessToken(tranId, txInfo);
        const result = await pollAndFinalizeSignTransaction(tranId, txInfo, transactionAccessToken);
        if (!result.success) {
            return res.status(result.status || 500).json({
                success: false,
                retry: !!result.retry,
                tranStatus: result.tranStatus,
                error: result.error
            });
        }
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// (Đã gỡ API /api/vnpt/signature/embed: cho phép người dùng tự gửi chuỗi PKCS#7 bất kỳ để ghi vào PDF
//  trên server, không kiểm chứng được và không tạo ra chữ ký hợp lệ. Việc nhúng nay do finalizeVnptSignature đảm nhiệm.)

// 10.6. API NHẬN THÔNG BÁO (notifyUrl) TỪ VNPT SMARTCA - server to server, HTTP POST JSON {tranId, refTranId, status}
// Xác thực callback, sau đó worker tự xác minh trạng thái trực tiếp với VNPT trước khi ghi nhận chữ ký.
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
        if (!tranId) return res.status(400).json({ success: false, error: 'Thiếu tranId trong thông báo VNPT.' });
        const tx = readSignTx()[tranId];
        if (!tx) {
            return res.status(503).json({ success: false, error: 'Giao dịch chưa được lưu trên CDE; VNPT có thể gửi lại thông báo.' });
        }
        if (tx.refTranId && refTranId && !safeEqual(tx.refTranId, refTranId)) {
            return res.status(400).json({ success: false, error: 'refTranId không khớp giao dịch đã lưu.' });
        }
        console.log('[VNPT SMARTCA NOTIFY]', JSON.stringify({ tranId, refTranId, status }));
        scheduleSignTxReconciliation(tranId);
        res.status(202).json({ success: true, received: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const signTxReconciliationTimer = setInterval(reconcilePendingSignTransactions, 15000);
if (typeof signTxReconciliationTimer.unref === 'function') signTxReconciliationTimer.unref();
const signTxStartupTimer = setTimeout(reconcilePendingSignTransactions, 2000);
if (typeof signTxStartupTimer.unref === 'function') signTxStartupTimer.unref();

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
        const relPath = req.query.path || req.body.targetPath || req.body.targetFolder || '';
        const targetDir = path.join(ROOT_DIR, relPath.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
        cb(null, targetDir);
    },
    filename: (req, file, cb) => {
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const targetPath = req.query.path || req.body.targetPath || req.body.targetFolder || '';
        if (!canUserUploadInZone(req.authUser, getZoneFromPath(targetPath))) {
            return cb(new Error('Bạn không có quyền tải tệp lên khu vực này.'));
        }
        cb(null, true);
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE & Auth Backend Server đang hoạt động ổn định!' });
});

app.get('/api/files', (req, res) => {
    try {
        const subPath = (req.query.path || '').replace(/^database\/bim-vdc\/?/, '');
        const targetDir = path.join(ROOT_DIR, subPath);
        if (!fs.existsSync(targetDir)) return res.status(404).json({ error: 'Thư mục không tồn tại' });
        const metadataDB = readFileMetadataDB();
        const items = fs.readdirSync(targetDir, { withFileTypes: true });
        res.json(items.map(item => {
            const fullPath = path.join(targetDir, item.name);
            let size = 0;
            let stats = null;
            try {
                if (!item.isDirectory()) {
                    stats = fs.statSync(fullPath);
                    size = stats.size;
                }
            } catch (e) {
                // Bỏ qua lỗi nếu file đang bị khóa hoặc không đọc được stat
            }
            const itemPath = 'database/bim-vdc/' + path.join(subPath, item.name).replace(/\\/g, '/');
            const metadata = metadataDB[normRecallKey(itemPath)] || {};
            const fileUpdatedAt = stats ? stats.mtime.toISOString() : '';
            const metadataUpdatedAt = metadata.updatedAt || '';
            return {
                name: item.name,
                isDirectory: item.isDirectory(),
                type: item.isDirectory() ? 'folder' : 'file',
                size: size,
                path: itemPath,
                metadata: item.isDirectory() ? null : {
                    title: (metadata.title || '').toLocaleUpperCase('vi-VN'),
                    description: metadata.description || '',
                    author: metadata.author || '',
                    createdAt: metadata.createdAt || (stats ? stats.birthtime.toISOString() : ''),
                    updatedAt: metadataUpdatedAt && (!fileUpdatedAt || Date.parse(metadataUpdatedAt) > Date.parse(fileUpdatedAt))
                        ? metadataUpdatedAt
                        : fileUpdatedAt,
                    status: metadata.status || 'PENDING',
                    suitability: metadata.suitability || '',
                    discipline: metadata.discipline || ''
                }
            };
        }));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/file-metadata', requireCdeAuth, (req, res) => {
    try {
        const { filePath, title, description, status, suitability, discipline } = req.body || {};
        if (typeof filePath !== 'string' || !filePath.trim()) {
            return res.status(400).json({ success: false, error: 'Thiếu đường dẫn tệp.' });
        }
        if (title !== undefined && (typeof title !== 'string' || title.length > 2000)) {
            return res.status(400).json({ success: false, error: 'Tiêu đề tối đa 2000 ký tự.' });
        }
        if (typeof description !== 'string' || description.length > 2000) {
            return res.status(400).json({ success: false, error: 'Mô tả tối đa 2000 ký tự.' });
        }
        const normalizedPath = normRecallKey(filePath);
        const relativePath = normalizedPath.replace(/^database\/bim-vdc\/?/, '');
        const fullPath = path.resolve(ROOT_DIR, relativePath);
        const rootPath = path.resolve(ROOT_DIR);
        if (!fullPath.startsWith(rootPath + path.sep) || !fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy tệp cần cập nhật thông tin.' });
        }
        if (!canUserWriteReview(req.authUser, getContainerFromPath(normalizedPath))) {
            return res.status(403).json({ success: false, error: 'Bạn không có quyền cập nhật thông tin trong khu vực này.' });
        }
        const validStatuses = ['PENDING', 'APPROVED', 'REJECTED'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ success: false, error: 'Trạng thái duyệt không hợp lệ.' });
        }
        const validSuitabilities = ['S0', 'S1', 'S2', 'S3', 'S4', 'A1', 'A2'];
        if (suitability !== undefined && !validSuitabilities.includes(suitability)) {
            return res.status(400).json({ success: false, error: 'Suitability không hợp lệ.' });
        }
        const validDisciplines = ['ARC', 'STR', 'MEP', 'HVAC'];
        if (discipline !== undefined &&
            (typeof discipline !== 'string' || !discipline.trim() || discipline.length > 100 ||
                (!validDisciplines.includes(discipline) && discipline === 'CUSTOM'))) {
            return res.status(400).json({ success: false, error: 'Bộ môn không hợp lệ.' });
        }

        const db = readFileMetadataDB();
        const previous = db[normalizedPath] || {};
        const now = new Date().toISOString();
        const metadata = {
            title: title === undefined ? (previous.title || '').toLocaleUpperCase('vi-VN') : title.trim().toLocaleUpperCase('vi-VN'),
            description: description.trim(),
            author: previous.author || '',
            createdAt: previous.createdAt || fs.statSync(fullPath).birthtime.toISOString(),
            updatedAt: now,
            status,
            suitability: suitability || previous.suitability || '',
            discipline: typeof discipline === 'string' ? discipline.trim() : previous.discipline || ''
        };
        db[normalizedPath] = metadata;
        if (!writeFileMetadataDB(db)) {
            return res.status(500).json({ success: false, error: 'Không thể lưu thông tin tệp.' });
        }
        res.json({ success: true, metadata });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/cde-files', (req, res) => {
    try {
        const metadataDB = readFileMetadataDB();
        function walkDir(dir, fileList = []) {
            fs.readdirSync(dir, { withFileTypes: true }).forEach(file => {
                const fullPath = path.join(dir, file.name);
                const relPath = path.relative(BASE_DATABASE_DIR, fullPath).replace(/\\/g, '/');
                let size = 0;
                let stats = null;
                try {
                    if (!file.isDirectory()) {
                        stats = fs.statSync(fullPath);
                        size = stats.size;
                    }
                } catch (e) {
                    // Bỏ qua lỗi stat
                }
                const itemPath = 'database/' + relPath;
                const metadata = metadataDB[normRecallKey(itemPath)] || {};
                const fileUpdatedAt = stats ? stats.mtime.toISOString() : '';
                const metadataUpdatedAt = metadata.updatedAt || '';
                fileList.push({
                    name: file.name,
                    path: itemPath,
                    type: file.isDirectory() ? 'folder' : 'file',
                    size: size,
                    metadata: file.isDirectory() ? null : {
                        title: (metadata.title || '').toLocaleUpperCase('vi-VN'),
                        description: metadata.description || '',
                        author: metadata.author || '',
                        createdAt: metadata.createdAt || (stats ? stats.birthtime.toISOString() : ''),
                        updatedAt: metadataUpdatedAt && (!fileUpdatedAt || Date.parse(metadataUpdatedAt) > Date.parse(fileUpdatedAt))
                            ? metadataUpdatedAt
                            : fileUpdatedAt,
                        status: metadata.status || 'PENDING',
                        suitability: metadata.suitability || '',
                        discipline: metadata.discipline || ''
                    }
                });
                if (file.isDirectory()) walkDir(fullPath, fileList);
            });
            return fileList;
        }
        res.json(walkDir(ROOT_DIR));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/upload', requireCdeAuth, (req, res) => {
    upload.any()(req, res, error => {
        if (error) {
            return res.status(403).json({ success: false, error: error.message });
        }
        try {
            const files = req.files || [];
            if (!files.length) {
                return res.status(400).json({ success: false, error: 'Vui lòng chọn tệp cần tải lên.' });
            }
            const { title = '', description = '', status = 'PENDING', suitability = 'S0', discipline = 'ARC' } = req.body || {};
            const validStatuses = ['PENDING', 'APPROVED', 'REJECTED'];
            const validSuitabilities = ['S0', 'S1', 'S2', 'S3', 'S4', 'A1', 'A2'];
            const validDisciplines = ['ARC', 'STR', 'MEP', 'HVAC'];
            if (typeof title !== 'string' || title.length > 2000 ||
                typeof description !== 'string' || description.length > 2000 ||
                !validStatuses.includes(status) ||
                !validSuitabilities.includes(suitability) ||
                !validDisciplines.includes(discipline)) {
                files.forEach(file => fs.unlinkSync(file.path));
                return res.status(400).json({ success: false, error: 'Thông tin metadata tải lên không hợp lệ.' });
            }
            const metadataDB = readFileMetadataDB();
            const uploadedAt = new Date().toISOString();
            files.forEach(file => {
                const relativePath = path.relative(ROOT_DIR, file.path).replace(/\\/g, '/');
                const metadataPath = normRecallKey(`database/bim-vdc/${relativePath}`);
                const previous = metadataDB[metadataPath] || {};
                const stats = fs.statSync(file.path);
                metadataDB[metadataPath] = {
                    ...previous,
                    title: title.trim().toLocaleUpperCase('vi-VN'),
                    description: description.trim(),
                    author: req.authUser.fullName || req.authUser.username,
                    createdAt: previous.createdAt || stats.birthtime.toISOString(),
                    updatedAt: uploadedAt,
                    status,
                    suitability,
                    discipline
                };
            });
            if (!writeFileMetadataDB(metadataDB)) {
                return res.status(500).json({ success: false, error: 'Tệp đã tải lên nhưng không thể lưu thông tin tác giả.' });
            }
            res.json({ success: true, message: 'Tải lên tập tin thành công!' });
        } catch (uploadError) {
            res.status(500).json({ success: false, error: uploadError.message });
        }
    });
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
            rekeyFileMetadata(itemPath, renamedKey);
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
            removeFileMetadata(req.body.path);
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
        rekeyFileMetadata(sourcePath, movedKey);
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
// 13. API tạo mới dự án và tự động sinh 4 thư mục chuẩn ISO 19650
// ===============================================================

app.post('/api/create-project', (req, res) => {
    try {
        const { parentPath, projectName } = req.body;
        if (!projectName || !String(projectName).trim()) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập tên dự án mới!' });
        }

        const cleanParent = (parentPath || 'database/bim-vdc').replace(/^database\/bim-vdc\/?/, '');
        const projectRootPath = path.join(ROOT_DIR, cleanParent, projectName.trim());

        // Kiểm tra xem thư mục dự án đã tồn tại chưa
        if (fs.existsSync(projectRootPath)) {
            return res.status(400).json({ success: false, error: 'Dự án hoặc thư mục này đã tồn tại!' });
        }

        // Tạo thư mục gốc của dự án và 4 thư mục con chuẩn ISO 19650
        const isoSubFolders = ['01_WIP', '02_SHARED', '03_PUBLISHED', '04_ARCHIVE'];
        
        fs.mkdirSync(projectRootPath, { recursive: true });
        isoSubFolders.forEach(subFolder => {
            fs.mkdirSync(path.join(projectRootPath, subFolder), { recursive: true });
        });

        res.json({ 
            success: true, 
            message: `Đã tạo dự án "${projectName.trim()}" kèm 4 thư mục chuẩn ISO 19650 thành công!` 
        });
    } catch (error) { 
        res.status(500).json({ success: false, error: error.message }); 
    }
});

// ===============================================================
// 14. STATIC SERVE & KHỞI ĐỘNG SERVER
// ===============================================================
// ===============================================================
// 9B. DỮ LIỆU THI CÔNG THEO CẤU KIỆN (trạng thái / 4D / ảnh) - LƯU BỀN VỮNG
//     Khóa theo đường dẫn file mô hình + GlobalId. Quyền theo REVIEW_ZONE_ACCESS (ISO 19650).
// ===============================================================
const PROGRESS_FILE_PATH = path.join(BASE_DATABASE_DIR, 'element_progress.json');
const PROGRESS_AUDIT_PATH = path.join(BASE_DATABASE_DIR, 'element_progress_audit.json');
const PROG_ST = ['CHUA', 'DANG', 'HT', 'NT'];
const PROG_GID = /^[0-9A-Za-z_$]{22}$/;
const PROG_DATE = /^\d{4}-\d{2}-\d{2}$/;
const PROG_URL = /^(https:\/\/|\/(?!\/))[^\s"'<>]{1,500}$/;
let progressQueue = Promise.resolve();

function progAuth(req, res) {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
    if (!token) { res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' }); return null; }
    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); }
    catch (e) { res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn!' }); return null; }
    const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
    const user = users.find(u => u.username === payload.username);
    if (!user || user.status === 'Inactive') { res.status(401).json({ success: false, error: 'Tài khoản không tồn tại hoặc đã bị khóa!' }); return null; }
    return user;
}
function progModel(res, filePath) {
    const rel = String(filePath || '').replace(/\\/g, '/').replace(/^database\/bim-vdc\/?/, '').replace(/^\/+/, '');
    const full = path.resolve(ROOT_DIR, rel);
    if (!rel || !full.startsWith(ROOT_DIR + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
        res.status(400).json({ success: false, error: 'Đường dẫn mô hình không hợp lệ hoặc không tồn tại!' }); return null;
    }
    return { rel, container: getContainerFromPath(rel) };
}
function canUserReadModel(user, container) {
    const role = String(user.role || '').toUpperCase();
    const permission = String(user.permission || role).toUpperCase();
    if (permission === 'ADMIN' || role === 'ADMIN') return true;
    if (!container) return false;
    const level = (REVIEW_ZONE_ACCESS[permission] || REVIEW_ZONE_ACCESS[role] || {})[container];
    return !!level && level !== 'NO ACCESS';
}
function cleanProgItem(v) {
    if (!v || typeof v !== 'object') return null;
    return {
        st: PROG_ST.includes(v.st) ? v.st : '',
        start: PROG_DATE.test(v.start || '') ? v.start : '',
        end: PROG_DATE.test(v.end || '') ? v.end : '',
        note: String(v.note || '').slice(0, 500),
        photos: (Array.isArray(v.photos) ? v.photos : []).map(String).filter(u => PROG_URL.test(u)).slice(0, 20)
    };
}
function progRead(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8') || 'null') || fallback; } catch (e) { return fallback; } }
function progWrite(file, data) { const tmp = file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(data), 'utf8'); fs.renameSync(tmp, file); }

app.get('/api/progress', (req, res) => {
    try {
        const user = progAuth(req, res); if (!user) return;
        const m = progModel(res, req.query.file); if (!m) return;
        if (!canUserReadModel(user, m.container)) return res.status(403).json({ success: false, error: 'Bạn không có quyền xem dữ liệu thi công của thư mục này!' });
        const rec = progRead(PROGRESS_FILE_PATH, {})[m.rel] || { items: {} };
        res.json({ success: true, items: rec.items || {}, updatedAt: rec.updatedAt || null, canWrite: canUserWriteReview(user, m.container) });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/progress/save', (req, res) => {
    const user = progAuth(req, res); if (!user) return;
    const m = progModel(res, req.body && req.body.filePath); if (!m) return;
    if (!canUserWriteReview(user, m.container)) return res.status(403).json({ success: false, error: 'Bạn cần quyền Read & Write hoặc Full Control trên thư mục này để lưu dữ liệu thi công!' });
    const items = req.body.items;
    if (!items || typeof items !== 'object' || Array.isArray(items)) return res.status(400).json({ success: false, error: 'Thiếu dữ liệu!' });
    const keys = Object.keys(items);
    if (keys.length > 5000) return res.status(400).json({ success: false, error: 'Tối đa 5000 cấu kiện mỗi lần lưu!' });
    progressQueue = progressQueue.then(() => {
        const all = progRead(PROGRESS_FILE_PATH, {});
        const rec = all[m.rel] || { items: {} };
        const by = user.fullName || user.username, at = new Date().toISOString();
        let saved = 0, deleted = 0;
        for (const g of keys) {
            if (!PROG_GID.test(g)) continue;
            if (items[g] === null) { if (rec.items[g]) { delete rec.items[g]; deleted++; } continue; }
            const c = cleanProgItem(items[g]);
            if (c) { rec.items[g] = { ...c, by, at }; saved++; }
        }
        rec.updatedAt = at;
        all[m.rel] = rec;
        progWrite(PROGRESS_FILE_PATH, all);
        const log = progRead(PROGRESS_AUDIT_PATH, []);
        log.push({ at, user: user.username, name: by, file: m.rel, saved, deleted });
        progWrite(PROGRESS_AUDIT_PATH, log.slice(-5000));
        res.json({ success: true, saved, deleted });
    }).catch(error => { if (!res.headersSent) res.status(500).json({ success: false, error: error.message }); });
});

app.get('/api/progress/audit', (req, res) => {
    try {
        const user = progAuth(req, res); if (!user) return;
        const m = progModel(res, req.query.file); if (!m) return;
        if (!canUserWriteReview(user, m.container)) return res.status(403).json({ success: false, error: 'Không đủ quyền xem nhật ký!' });
        res.json({ success: true, log: progRead(PROGRESS_AUDIT_PATH, []).filter(x => x.file === m.rel).slice(-200).reverse() });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

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