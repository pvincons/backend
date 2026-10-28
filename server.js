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
const BASE_DATABASE_DIR = path.join(__dirname, 'database');
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

// Khởi tạo tài khoản master mặc định nếu chưa có
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
            status: "Đang triển khai",
            groups: ["site"]
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
// 6b. API THU HỒI FILE (RECALL API)
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

// Chỉ người có quyền TẢI FILE LÊN (UPLOAD / Read & Write) trên phân vùng của file mới được thu hồi / hủy thu hồi.
// Quy tắc này phải khớp checkActionPermission('UPLOAD', zone) trong assets/js/permission.js:
//   ADMIN, MASTER: mọi phân vùng | DESIGNER: 01_WIP | CONTRACTOR: 03_PUBLISHED | MANAGEMENT, INTERNAL: không có.
// Server tự xác thực JWT và tra role/permission trong users.json, không tin dữ liệu từ trình duyệt.
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
// 7. API QUẢN LÝ TẬP TIN & CDE (FILE SYSTEM & ISO 19650)
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
// 8. HỆ THỐNG CHAT REALTIME (SSE API)
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
// 9. STATIC SERVE & KHỞI ĐỘNG SERVER
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