require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const JWT_SECRET = process.env.JWT_SECRET || (() => {
    if (String(process.env.NODE_ENV || '').toLowerCase() === 'production') {
        console.error('❌ Thiếu JWT_SECRET trong .env (bắt buộc khi NODE_ENV=production). Server dừng để tránh dùng khóa mặc định.');
        process.exit(1);
    }
    console.warn('⚠️ Chưa đặt JWT_SECRET trong .env - đang dùng khóa mặc định (CHỈ dùng khi phát triển).');
    return 'PV_INCONS_SECRET_KEY_2026';
})();
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

const BASE_DATABASE_DIR = process.env.DATABASE_PATH || path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');
const ISSUES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'issues.json');
const RECALLS_FILE_PATH = path.join(BASE_DATABASE_DIR, 'recalls.json');

if (!fs.existsSync(path.dirname(USER_FILE_PATH))) {
    fs.mkdirSync(path.dirname(USER_FILE_PATH), { recursive: true });
}
if (!fs.existsSync(AVATAR_DIR)) {
    fs.mkdirSync(AVATAR_DIR, { recursive: true });
}
if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

if (!fs.existsSync(USER_FILE_PATH)) {
    const bootstrapPassword = process.env.ADMIN_DEFAULT_PASSWORD || crypto.randomBytes(9).toString('base64url');
    if (!process.env.ADMIN_DEFAULT_PASSWORD) {
        console.warn(`⚠️ Đã tạo tài khoản admin lần đầu. Mật khẩu tạm (chỉ hiển thị 1 lần, hãy đổi ngay): ${bootstrapPassword}`);
    }
    const defaultPasswordHash = bcrypt.hashSync(bootstrapPassword, 10);
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
// 3. PROXY CHO REVIT SERVER ADMINISTRATOR (Chuẩn hóa trả về JSON)
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
            console.error('[REVIT SERVER PROXY ERROR]:', err.message);
            res.status(500).json({
                success: false,
                error: 'Không thể kết nối tới Revit Server IIS service nội bộ!',
                details: err.message
            });
        }
    })
);

// ===============================================================
// 4. API XÁC THỰC & ĐĂNG NHẬP
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
        console.error('[LOGIN ERROR]:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

function requireCdeAuth(req, res, next) {
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
            return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn!' });
        }

        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user || user.status === 'Inactive') {
            return res.status(401).json({ success: false, error: 'Tài khoản không tồn tại hoặc đã bị khóa!' });
        }

        req.authUser = user;
        next();
    } catch (error) {
        console.error('[AUTH ERROR]:', error);
        res.status(500).json({ success: false, error: error.message });
    }
}

app.post('/api/change-password', requireCdeAuth, (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || !String(newPassword).trim()) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập mật khẩu mới!' });
        }

        const data = fs.readFileSync(USER_FILE_PATH, 'utf8');
        const users = JSON.parse(data || '[]');

        const userIndex = users.findIndex(u => u.username === req.authUser.username);
        if (userIndex === -1) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy tài khoản người dùng!' });
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
// 6. API ISSUES & QA-QC
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

function normRecallKey(p) {
    const rel = String(p || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/^database\/bim-vdc\/?/, '').replace(/\/+$/, '');
    return rel ? 'database/bim-vdc/' + rel : 'database/bim-vdc';
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
        return false;
    }
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
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ!' }); }

        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user) return res.status(401).json({ success: false, error: 'Tài khoản không tồn tại!' });

        if (!canUserUploadInZone(user, getZoneFromPath(req.body && req.body.filePath))) {
            return res.status(403).json({ success: false, error: 'Bạn không có quyền thực hiện trên thư mục này!' });
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

app.post('/api/review/save', requireCdeAuth, (req, res) => {
    try {
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
        if (!canUserWriteReview(req.authUser, container)) {
            return res.status(403).json({ success: false, error: 'Bạn không có quyền đánh giá trên thư mục này!' });
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
                author: req.authUser.fullName || req.authUser.username,
                username: req.authUser.username,
                role: String(req.authUser.role || ''),
                at: c.at || new Date().toISOString(),
                time: c.time || ''
            });
        });
        const merged = [...byCid.values()].sort((a, b) => String(a.at).localeCompare(String(b.at)));
        fs.writeFileSync(reviewFull, JSON.stringify({
            model: path.basename(modelFull),
            savedBy: req.authUser.fullName || req.authUser.username,
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
            return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file hoặc lý do!' });
        }
        const key = normRecallKey(filePath);
        const fullPath = path.join(ROOT_DIR, key.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(fullPath)) return res.status(404).json({ success: false, error: 'Tệp không tồn tại!' });

        const db = readRecallsDB();
        if (db[key]) return res.status(409).json({ success: false, error: 'Tệp này đã được thu hồi!' });

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
// 10. TÍCH HỢP VNPT SMARTCA (SP 769 - Tài liệu tích hợp v4.0, Mục 3)
//     Luồng: get_certificate -> sign (hash) -> chờ thuê bao xác nhận trên app
//            -> status (server tự kiểm tra hoặc nhận tín hiệu qua webhook)
// ===============================================================
const VNPT_SMARTCA_BASE_URL = (process.env.VNPT_SMARTCA_BASE_URL || 'https://rmgateway.vnptit.vn/sca/sp769').replace(/\/+$/, '');
const VNPT_SMARTCA_SP_ID = process.env.VNPT_SMARTCA_SP_ID || '';
const VNPT_SMARTCA_SP_PASSWORD = process.env.VNPT_SMARTCA_SP_PASSWORD || '';
const SMARTCA_WEBHOOK_TOKEN = process.env.SMARTCA_WEBHOOK_TOKEN || '';
const SMARTCA_TIMEOUT_MS = 15000;
const SMARTCA_TX_TTL_MS = (299 + 30) * 1000;
const SMARTCA_POLL_INTERVAL_MS = 3000;
const SMARTCA_SIGNABLE_EXT = /\.(pdf|ifc)$/i;
const SMARTCA_FAILED_MSG = /reject|cancel|denied|declin|expire|timeout|từ chối|hủy|huỷ|hết hạn/i;

if (!VNPT_SMARTCA_SP_ID || !VNPT_SMARTCA_SP_PASSWORD) {
    console.warn('⚠️ Thiếu VNPT_SMARTCA_SP_ID / VNPT_SMARTCA_SP_PASSWORD trong .env');
}

const SIGNATURES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'signatures.json');
const SMARTCA_TX_FILE_PATH = path.join(BASE_DATABASE_DIR, 'smartca_transactions.json');

function readJsonObject(filePath) {
    try {
        if (fs.existsSync(filePath)) return JSON.parse(fs.readFileSync(filePath, 'utf8') || '{}');
    } catch (err) {
        console.error('Lỗi đọc ' + path.basename(filePath) + ':', err);
    }
    return {};
}

function writeJsonObject(filePath, obj) {
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
    fs.renameSync(tmp, filePath);
}

if (!fs.existsSync(SIGNATURES_FILE_PATH)) writeJsonObject(SIGNATURES_FILE_PATH, {});
if (!fs.existsSync(SMARTCA_TX_FILE_PATH)) writeJsonObject(SMARTCA_TX_FILE_PATH, {});

const readSignaturesDB = () => readJsonObject(SIGNATURES_FILE_PATH);
const readSmartCaTxDB = () => readJsonObject(SMARTCA_TX_FILE_PATH);

function writeSmartCaTxDB(db) {
    const limit = Date.now() - 7 * 24 * 3600 * 1000;
    Object.keys(db).forEach(k => {
        const tx = db[k];
        if (tx && tx.state !== 'pending' && Date.parse(tx.completedAt || tx.createdAt || 0) < limit) delete db[k];
    });
    writeJsonObject(SMARTCA_TX_FILE_PATH, db);
}

// Định dạng time_stamp chuẩn YYYYMMddHHmmSS theo quy định VNPT SmartCA (Mục 3.3)
function smartcaTimestamp(date = new Date()) {
    const vn = new Date(date.getTime() + 7 * 3600 * 1000);
    const p = (n) => String(n).padStart(2, '0');
    return `${vn.getUTCFullYear()}${p(vn.getUTCMonth() + 1)}${p(vn.getUTCDate())}${p(vn.getUTCHours())}${p(vn.getUTCMinutes())}${p(vn.getUTCSeconds())}`;
}

function maskId(id) {
    const s = String(id || '');
    return s.length <= 4 ? s : '*'.repeat(s.length - 4) + s.slice(-4);
}

function isAdminUser(user) {
    return String(user.role || '').toUpperCase() === 'ADMIN' || String(user.permission || '').toUpperCase() === 'ADMIN';
}

async function smartcaPost(endpoint, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SMARTCA_TIMEOUT_MS);
    try {
        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(body),
            signal: controller.signal
        });
        const text = await response.text();
        let data;
        try { data = text ? JSON.parse(text) : {}; }
        catch (e) { data = { status_code: response.status, message: `Phản hồi không hợp lệ từ VNPT SmartCA (HTTP ${response.status})` }; }
        return { httpStatus: response.status, data };
    } finally {
        clearTimeout(timer);
    }
}

function smartcaCode(r) {
    const n = Number(r.data && r.data.status_code);
    return Number.isFinite(n) && n > 0 ? n : r.httpStatus;
}

function smartcaIsOk(r) {
    return r.httpStatus < 400 && smartcaCode(r) === 200;
}

function smartcaFail(res, r, fallbackMsg) {
    const code = smartcaCode(r);
    const msg = (r.data && r.data.message) || fallbackMsg;
    let http = 502;
    if (code === 400) http = 400;
    else if (code === 401) http = 400;
    else if (code === 403) http = 403;
    return res.status(http).json({ success: false, error: msg, smartca_status_code: code });
}

function resolveSmartCaUserId(authUser, requested) {
    const registered = String(authUser.smartcaUserId || authUser.cccd || authUser.idNumber || authUser.taxCode || '').trim();
    const input = String(requested || '').trim();
    if (registered) return { userId: registered };
    if (!input) return { status: 400, error: 'Thiếu thông tin CCCD/CMND/MST của thuê bao VNPT SmartCA!' };
    return { userId: input };
}

function resolveCdeFile(filePath) {
    const key = normRecallKey(filePath);
    const rel = key.replace(/^database\/bim-vdc\/?/, '');
    if (!rel) return { status: 400, error: 'Thiếu đường dẫn file cần ký!' };
    const root = path.resolve(ROOT_DIR);
    const fullPath = path.resolve(root, rel);
    if (!fullPath.startsWith(root + path.sep)) return { status: 400, error: 'Đường dẫn tệp không hợp lệ!' };
    let stat;
    try { stat = fs.statSync(fullPath); } catch (e) { stat = null; }
    if (!stat || !stat.isFile()) return { status: 404, error: 'Tệp tin không tồn tại trên hệ thống CDE!' };
    return { key, rel, fullPath, stat, fileName: path.basename(fullPath) };
}

function hashFileSha256(fullPath) {
    return new Promise((resolve, reject) => {
        const h = crypto.createHash('sha256');
        fs.createReadStream(fullPath)
            .on('error', reject)
            .on('data', chunk => h.update(chunk))
            .on('end', () => resolve(h.digest('hex')));
    });
}

function isCertUsable(cert) {
    if (!cert) return false;
    if (cert.cert_status && !/đang hoạt động|active/i.test(String(cert.cert_status))) return false;
    const now = Date.now();
    const to = Date.parse(cert.cert_valid_to || '');
    if (Number.isFinite(to) && to < now) return false;
    return true;
}

async function fetchSmartCaCertificates(userId, serialNumber) {
    const r = await smartcaPost('/v1/credentials/get_certificate', {
        sp_id: VNPT_SMARTCA_SP_ID,
        sp_password: VNPT_SMARTCA_SP_PASSWORD,
        user_id: userId,
        serial_number: serialNumber || '',
        transaction_id: crypto.randomUUID()
    });
    const raw = r.data && r.data.data ? r.data.data.user_certificates : null;
    const certs = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return { r, ok: smartcaIsOk(r), certs };
}

// 10.1 API Lấy danh sách Chứng thư số (Mục 3.2)
app.post('/api/smartca/credentials/get_certificate', requireCdeAuth, async (req, res) => {
    try {
        const idRes = resolveSmartCaUserId(req.authUser, req.body && req.body.userId);
        if (idRes.error) return res.status(idRes.status).json({ success: false, error: idRes.error });

        const { r, ok, certs } = await fetchSmartCaCertificates(idRes.userId, (req.body && req.body.serialNumber) || '');
        if (!ok) return smartcaFail(res, r, 'Không thể lấy danh sách chứng thư số từ VNPT SmartCA');
        if (!certs.length) return res.status(404).json({ success: false, error: 'Không tìm thấy chứng thư số nào của thuê bao này!' });

        const list = certs.map(c => ({
            service_type: c.service_type || '',
            service_name: c.service_name || '',
            serial_number: c.serial_number,
            cert_status: c.cert_status || '',
            cert_subject: c.cert_subject || '',
            cert_valid_from: c.cert_valid_from || '',
            cert_valid_to: c.cert_valid_to || '',
            usable: isCertUsable(c)
        }));
        res.json({ success: true, status_code: 200, message: 'Success', data: { user_certificates: list } });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.2 API Khởi tạo Yêu cầu Ký số (Mục 3.3)
app.post('/api/smartca/signatures/sign', requireCdeAuth, async (req, res) => {
    try {
        const { userId, serialNumber, filePath } = req.body || {};
        if (!filePath) return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file cần ký!' });
        if (!serialNumber) return res.status(400).json({ success: false, error: 'Vui lòng chọn chứng thư số để ký!' });

        const idRes = resolveSmartCaUserId(req.authUser, userId);
        if (idRes.error) return res.status(idRes.status).json({ success: false, error: idRes.error });

        const file = resolveCdeFile(filePath);
        if (file.error) return res.status(file.status).json({ success: false, error: file.error });

        const hashHex = await hashFileSha256(file.fullPath);
        const docId = 'CDE-' + hashHex.slice(0, 6).toUpperCase() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        const transactionId = crypto.randomUUID();

        const signR = await smartcaPost('/v1/signatures/sign', {
            sp_id: VNPT_SMARTCA_SP_ID,
            sp_password: VNPT_SMARTCA_SP_PASSWORD,
            user_id: idRes.userId,
            transaction_id: transactionId,
            transaction_desc: `PV INCONS CDE - Ky so ${file.fileName}`.slice(0, 200),
            serial_number: serialNumber,
            time_stamp: smartcaTimestamp(),
            sign_files: [{
                file_type: path.extname(file.fileName).replace('.', '').toLowerCase(),
                data_to_be_signed: hashHex,
                doc_id: docId,
                sign_type: 'hash'
            }]
        });

        const body = signR.data || {};
        const inner = body.data || {};
        const tranCode = inner.tran_code;
        if (!smartcaIsOk(signR) || !tranCode) {
            return smartcaFail(res, signR, 'Lỗi gửi yêu cầu ký số tới VNPT SmartCA');
        }

        const now = Date.now();
        const freshDb = readSmartCaTxDB();
        freshDb[tranCode] = {
            tranCode,
            transactionId,
            userId: idRes.userId,
            serialNumber,
            filePath: file.key,
            fileName: file.fileName,
            fileSize: file.stat.size,
            fileMtimeMs: file.stat.mtimeMs,
            hashAlgorithm: 'SHA-256',
            hashHex,
            docId,
            createdBy: req.authUser.username,
            createdByName: req.authUser.fullName || req.authUser.username,
            createdAt: new Date(now).toISOString(),
            expiresAt: now + SMARTCA_TX_TTL_MS,
            state: 'pending',
            message: body.message || 'sig_wait_for_user_confirm'
        };
        writeSmartCaTxDB(freshDb);

        res.json({
            success: true,
            message: body.message || 'sig_wait_for_user_confirm',
            tran_code: tranCode,
            transaction_id: transactionId,
            doc_id: docId,
            file_name: file.fileName,
            hash_sha256: hashHex,
            expires_in_seconds: Math.round(SMARTCA_TX_TTL_MS / 1000)
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.3 API Kiểm tra trạng thái Ký số (Mục 3.4)
app.post('/api/smartca/signatures/status', requireCdeAuth, async (req, res) => {
    try {
        const tranCode = String((req.body && req.body.tranCode) || '').trim();
        if (!tranCode) return res.status(400).json({ success: false, error: 'Thiếu mã giao dịch tranCode!' });

        let db = readSmartCaTxDB();
        let tx = db[tranCode];
        if (!tx) return res.status(404).json({ success: false, state: 'failed', error: 'Không tìm thấy giao dịch!' });

        if (tx.state === 'pending') {
            const r = await smartcaPost(`/v1/signatures/sign/${encodeURIComponent(tranCode)}/status`, {
                sp_id: VNPT_SMARTCA_SP_ID,
                sp_password: VNPT_SMARTCA_SP_PASSWORD
            });

            db = readSmartCaTxDB();
            tx = db[tranCode] || tx;
            const sigs = r.data && r.data.data && Array.isArray(r.data.data.signatures) ? r.data.data.signatures : [];
            const mine = sigs.find(s => s && s.doc_id === tx.docId && s.signature_value) || sigs.find(s => s && s.signature_value);

            if (smartcaIsOk(r) && mine) {
                tx.state = 'done';
                tx.completedAt = new Date().toISOString();
                tx.message = 'Ký số thành công';
                db[tranCode] = tx;

                // Lưu kết quả chữ ký số vào signatures.json
                const sigDb = readSignaturesDB();
                sigDb[tx.filePath] = {
                    filePath: tx.filePath,
                    fileName: tx.fileName,
                    docId: tx.docId,
                    transactionId: tx.transactionId,
                    tranCode: tx.tranCode,
                    subscriberIdMasked: maskId(tx.userId),
                    fileHash: tx.hashHex,
                    signatures: sigs,
                    signedBy: tx.createdByName,
                    signedAt: new Date().toISOString()
                };
                writeJsonObject(SIGNATURES_FILE_PATH, sigDb);
                writeSmartCaTxDB(db);

                return res.json({ success: true, state: 'done', doc_id: tx.docId, message: tx.message });
            }

            if (Date.now() > tx.expiresAt) {
                tx.state = 'failed';
                tx.error = 'Giao dịch đã hết hạn xác nhận trên App VNPT SmartCA.';
                db[tranCode] = tx;
                writeSmartCaTxDB(db);
                return res.json({ success: false, state: 'failed', error: tx.error });
            }
            return res.json({ success: true, state: 'pending', doc_id: tx.docId, message: 'Đang chờ thuê bao xác nhận trên ứng dụng VNPT SmartCA' });
        }

        if (tx.state === 'done') {
            return res.json({ success: true, state: 'done', doc_id: tx.docId, message: 'Ký số thành công' });
        }
        res.json({ success: false, state: 'failed', error: tx.error || 'Giao dịch thất bại' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Hàm khôi phục và kiểm tra các giao dịch dang dở khi khởi động lại server
function resumeSmartCaTransactions() {
    try {
        const db = readSmartCaTxDB();
        let changed = false;
        Object.values(db).forEach(tx => {
            if (tx.state !== 'pending') return;
            if (Date.now() > tx.expiresAt + 60000) {
                tx.state = 'failed';
                tx.completedAt = new Date().toISOString();
                tx.error = 'Giao dịch đã hết hạn (server khởi động lại).';
                changed = true;
            }
        });
        if (changed) writeSmartCaTxDB(db);
    } catch (e) {
        console.error('Lỗi khởi động SmartCA transactions:', e);
    }
}

resumeSmartCaTransactions();

// ===============================================================
// 11. API THƯ MỤC & FILE CDE (ISO 19650)
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
    res.json({ status: 'ok', message: 'CDE Backend Server đang hoạt động ổn định!' });
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
// 12. HỆ THỐNG CHAT REALTIME (SSE)
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
    console.log(`🚀 PV INCONS CDE Backend Server đang chạy tại cổng ${PORT}`);
});