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

// Linh hoạt đường dẫn: Nếu có biến môi trường DATABASE_PATH thì dùng (cho Production/VPS), ngược lại dùng thư mục database nội bộ (cho Local)
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
        // 1. Xác thực token từ header để biết chính xác ai đang đăng nhập
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

        // 2. Đọc file users.json
        const data = fs.readFileSync(USER_FILE_PATH, 'utf8');
        const users = JSON.parse(data || '[]');

        // 3. Tìm đúng user đang đăng nhập dựa vào username trong token
        const userIndex = users.findIndex(u => u.username === payload.username);
        if (userIndex === -1) {
            return res.status(404).json({ success: false, error: 'Không tìm thấy tài khoản người dùng trong hệ thống!' });
        }

        // 4. Hash mật khẩu mới bằng bcrypt
        const saltRounds = 10;
        const hashedNewPassword = bcrypt.hashSync(newPassword, saltRounds);

        // 5. Cập nhật passwordHash, giữ nguyên 100% các trường và dữ liệu khác
        users[userIndex] = {
            ...users[userIndex],
            passwordHash: hashedNewPassword
        };

        // 6. Ghi lại vào file users.json
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

// Issue được lưu theo ĐƯỜNG DẪN file. Khi file đổi tên / chuyển Gate (di chuyển container),
// phải chuyển khóa issue sang đường dẫn mới, nếu không issue cũ bị "mồ côi" và mất khỏi file.
function rekeyIssues(oldPath, newPath) {
    const oldKey = normRecallKey(oldPath);
    const newKey = normRecallKey(newPath);
    const db = readIssuesDB();
    let changed = false;
    Object.keys(db).forEach(k => {
        const nk = normRecallKey(k);
        if (nk === oldKey || nk.startsWith(oldKey + '/')) {
            const target = newKey + nk.slice(oldKey.length);
            db[target] = (db[target] || []).concat(db[k]); // nối tiếp nếu đích đã có issue
            if (target !== k) delete db[k];
            changed = true;
        }
    });
    if (changed) writeIssuesDB(db);
}

// Xóa file/thư mục: dọn luôn issue tương ứng
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
// Cấu trúc recalls.json: { "database/bim-vdc/...": { by, at, reason } }
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

// Chuẩn hóa mọi đường dẫn về dạng "database/bim-vdc/..."
function normRecallKey(p) {
    const rel = String(p || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/^database\/bim-vdc\/?/, '').replace(/\/+$/, '');
    return rel ? 'database/bim-vdc/' + rel : 'database/bim-vdc';
}

// Đổi tên/di chuyển: chuyển khóa thu hồi sang đường dẫn mới (gồm cả file con nếu là thư mục)
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

// Xóa file/thư mục: dọn luôn dữ liệu thu hồi tương ứng
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
// 8. Chỉ người có quyền TẢI FILE LÊN (UPLOAD / Read & Write) trên phân vùng của file mới được thu hồi / hủy thu hồi.
// Quy tắc này phải khớp checkActionPermission('UPLOAD', zone) trong assets/js/permission.js:
// ADMIN, MASTER: mọi phân vùng | DESIGNER: 01_WIP | CONTRACTOR: 03_PUBLISHED | MANAGEMENT, INTERNAL: không có.
// Server tự xác thực JWT và tra role/permission trong users.json, không tin dữ liệu từ trình duyệt.
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
    // Giống permission.js: ADMIN/MASTER ưu tiên, còn lại tra theo permission rồi tới role
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
// 9. API LƯU ĐÁNH GIÁ / Ý KIẾN PHỐI HỢP TỪ VIEWER 3D
// Chỉ người có quyền "Read & Write" hoặc "Full Control" trên phân vùng ISO 19650 của file mới được lưu.
// Ma trận quyền khớp với mir.html (roleMatrix). ADMIN luôn được phép.
// Kết quả lưu cạnh file mô hình: <tên-file>.review.json (gộp theo cid để không ghi đè ý kiến người khác).
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
        // 1. Xác thực JWT, tra quyền trong users.json (không tin dữ liệu từ trình duyệt)
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });
        let payload;
        try { payload = jwt.verify(token, JWT_SECRET); }
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn, vui lòng đăng nhập lại!' }); }

        const users = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
        const user = users.find(u => u.username === payload.username);
        if (!user || user.status === 'Inactive') return res.status(401).json({ success: false, error: 'Tài khoản không tồn tại hoặc đã bị khóa!' });

        // 2. Kiểm tra đường dẫn file (chống path traversal) và quyền theo phân vùng
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

        // 3. Gộp với bản đã lưu (theo cid) rồi ghi file
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
            if (byCid.has(c.cid)) return; // ý kiến đã lưu: giữ nguyên, không cho sửa tác giả/nội dung
            byCid.set(c.cid, {
                cid: String(c.cid).slice(0, 80),
                globalId: String(c.globalId).slice(0, 80),
                name: String(c.name || '').slice(0, 300),
                text: c.text.slice(0, 5000),
                // Ý kiến mới luôn gắn với tài khoản đang đăng nhập (không tin tên do trình duyệt gửi lên)
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
// 10. TÍCH HỢP DỊCH VỤ CHỮ KÝ SỐ TỪ XA VIETTEL MYSIGN API (CHUẨN CSC & LƯU PHIÊN TỰ ĐỘNG KÝ)
// ===============================================================
const VIETTEL_MYSIGN_BASE_URL = process.env.VIETTEL_MYSIGN_BASE_URL || 'https://remotesigning.viettel.vn/vtss/service/ras';
const VIETTEL_MYSIGN_CLIENT_ID = process.env.VIETTEL_MYSIGN_CLIENT_ID || 'adss_client';
const VIETTEL_MYSIGN_CLIENT_SECRET = process.env.VIETTEL_MYSIGN_CLIENT_SECRET || 'your_client_secret';
const VIETTEL_MYSIGN_PROFILE_ID = process.env.VIETTEL_MYSIGN_PROFILE_ID || 'ADSS RAS Profile 001';

// 10.1. API Login lấy access_token từ Viettel MySign
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

// 10.2. API Lấy danh sách Chứng thư số (Credentials/List)
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

// 10.3. API Lấy thông tin chi tiết Chứng thư số (Credentials/Info)
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

// 10.4. API Gửi yêu cầu ủy quyền ký tới Mobile/App (Credentials/Authorize)
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

// 10.5. API Gửi yêu cầu sinh chữ ký mã băm (SignHash)
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

// 10.6. API Lấy cấu hình thời gian lưu phiên tối đa (Credentials/extendConfig)
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

// 10.7. API Đăng ký sử dụng chức năng lưu phiên / tự động ký (Register/Extension)
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

// 10.8. API Gửi yêu cầu sinh chữ ký lưu phiên tự động (Credentials/extendTransaction)
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

// 10.9. API Kiểm tra trạng thái lưu phiên ký (Timecheck)
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

// 10.10. API Hủy đăng ký chức năng lưu phiên (Deletion/Extension)
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

    // Gửi danh sách online ngay khi kết nối thành công
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

// Thư viện cho trang Xem 3D (viewer-ifc.html), cài bằng: npm i three@0.160.0 web-ifc@0.0.57
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