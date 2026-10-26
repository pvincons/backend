require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

app.set('trust proxy', true);
// Giới hạn CORS bằng biến môi trường CORS_ORIGIN (vd: https://cde.example.com,http://localhost:5500). Bỏ trống = cho phép tất cả.
app.use(cors(process.env.CORS_ORIGIN
    ? { origin: process.env.CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean) }
    : undefined));
app.use(express.json());

// ---- Cấu hình xác thực ----
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    console.warn('⚠️ Chưa đặt JWT_SECRET trong .env — đang dùng khóa tạm ngẫu nhiên, mọi phiên đăng nhập sẽ mất khi server khởi động lại!');
} else if (JWT_SECRET.length < 32) {
    console.warn('⚠️ JWT_SECRET quá ngắn (< 32 ký tự), nên dùng chuỗi ngẫu nhiên dài hơn.');
}
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';
const JWT_ISSUER = 'pv-incons-cde';
const USER_FILE_PATH = path.join(__dirname, 'assets', 'data', 'users.json');

// Middleware ghi log request thời gian thực
app.use((req, res, next) => {
    const safeUrl = req.url.replace(/([?&]token=)[^&]*/gi, '$1***'); // không ghi token vào log
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${safeUrl}`);
    next();
});

// ===============================================================
// 1. NHÓM XÁC THỰC (AUTHENTICATION & USERS)
// ===============================================================
const dirPath = path.dirname(USER_FILE_PATH);
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
}

if (!fs.existsSync(USER_FILE_PATH)) {
    const initialPassword = crypto.randomBytes(9).toString('base64url');
    const defaultPasswordHash = bcrypt.hashSync(initialPassword, 10);
    const defaultUsers = [
        {
            username: "admin",
            passwordHash: defaultPasswordHash,
            role: "ADMIN",
            fullName: "TRẦN HOÀNG PHƯỚC",
            position: "Giám đốc",
            company: "PV INCONS CO.LTD",
            status: "Đang triển khai"
        }
    ];
    fs.writeFileSync(USER_FILE_PATH, JSON.stringify(defaultUsers, null, 2), 'utf8');
    console.log(`🔑 Đã tạo users.json mới. Tài khoản: admin | Mật khẩu ban đầu: ${initialPassword} (hãy đổi ngay)`);
}

// ---------- Đọc users.json (có cache theo thời gian sửa file) ----------
let usersCache = { mtimeMs: 0, list: [] };
function loadUsers() {
    try {
        const st = fs.statSync(USER_FILE_PATH);
        if (st.mtimeMs !== usersCache.mtimeMs) {
            const parsed = JSON.parse(fs.readFileSync(USER_FILE_PATH, 'utf8') || '[]');
            usersCache = { mtimeMs: st.mtimeMs, list: Array.isArray(parsed) ? parsed : [] };
        }
    } catch (err) {
        console.error('Lỗi đọc users.json:', err.message);
    }
    return usersCache.list;
}

function normalizeUsername(v) {
    return typeof v === 'string' ? v.trim().toLowerCase().slice(0, 100) : '';
}

function findUser(username) {
    const key = normalizeUsername(username);
    if (!key) return null;
    return loadUsers().find(u => typeof u.username === 'string' && u.username.trim().toLowerCase() === key) || null;
}

// Tài khoản bị vô hiệu hóa: đặt "disabled": true, "active": false hoặc status chứa các từ khóa dưới đây
const INACTIVE_KEYWORDS = ['ngừng', 'nghỉ việc', 'khóa', 'vô hiệu', 'disabled', 'inactive', 'locked'];
function isActive(user) {
    if (user.disabled === true || user.active === false) return false;
    const status = String(user.status || '').toLowerCase();
    return !INACTIVE_KEYWORDS.some(k => status.includes(k));
}

// Hồ sơ trả về client: đầy đủ trường nhưng KHÔNG có passwordHash
function publicUser(user) {
    const { passwordHash, ...rest } = user;
    return { ...rest, role: String(rest.role || '').toUpperCase() };
}

// ---------- Chống dò mật khẩu (giới hạn số lần sai) ----------
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_PER_IP_USER = 5;   // sai 5 lần từ cùng IP + cùng tài khoản
const LOGIN_MAX_PER_USER = 15;     // sai 15 lần vào cùng tài khoản (kể cả đổi IP)
const loginFails = new Map();

function lockRemainingMs(rules) {
    const now = Date.now();
    let wait = 0;
    for (const { key, max } of rules) {
        const s = loginFails.get(key);
        if (!s) continue;
        if (now - s.first > LOGIN_WINDOW_MS) { loginFails.delete(key); continue; }
        if (s.count >= max) wait = Math.max(wait, LOGIN_WINDOW_MS - (now - s.first));
    }
    return wait;
}
function recordFail(rules) {
    const now = Date.now();
    for (const { key } of rules) {
        const s = loginFails.get(key);
        if (!s || now - s.first > LOGIN_WINDOW_MS) loginFails.set(key, { count: 1, first: now });
        else s.count++;
    }
}
function clearFails(rules) {
    for (const { key } of rules) loginFails.delete(key);
}
setInterval(() => {
    const now = Date.now();
    for (const [k, s] of loginFails) if (now - s.first > LOGIN_WINDOW_MS) loginFails.delete(k);
}, 10 * 60 * 1000).unref();

// Hash giả để thời gian phản hồi giống nhau dù tài khoản có tồn tại hay không
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(8).toString('hex'), 10);

// ---------- Middleware xác thực ----------
function extractToken(req) {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (m) return m[1].trim();
    // EventSource (SSE chat) không gửi được header nên chỉ riêng route này nhận token qua query
    if (req.path === '/chat/stream' && typeof req.query.token === 'string') return req.query.token;
    return null;
}

function requireAuth(req, res, next) {
    const token = extractToken(req);
    if (!token) {
        return res.status(401).json({ success: false, code: 'NO_TOKEN', error: 'Bạn chưa đăng nhập!' });
    }

    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: JWT_ISSUER });
    } catch (err) {
        const expired = err.name === 'TokenExpiredError';
        return res.status(401).json({
            success: false,
            code: expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID',
            error: expired ? 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại!' : 'Phiên đăng nhập không hợp lệ!'
        });
    }

    // Role và trạng thái luôn lấy từ users.json hiện tại (đổi role / khóa tài khoản có hiệu lực ngay)
    const user = findUser(payload.username);
    if (!user || !isActive(user)) {
        return res.status(401).json({ success: false, code: 'ACCOUNT_INVALID', error: 'Tài khoản không còn hiệu lực!' });
    }

    req.user = publicUser(user);
    next();
}

// Dùng khi cần giới hạn theo vai trò, ví dụ: app.post('/api/delete', requireRole('MASTER'), ...) — ADMIN luôn được qua
function requireRole(...roles) {
    return (req, res, next) => {
        if (req.user && (req.user.role === 'ADMIN' || roles.includes(req.user.role))) return next();
        res.status(403).json({ success: false, code: 'FORBIDDEN', error: 'Bạn không có quyền thực hiện thao tác này!' });
    };
}

// ---------- API công khai: đăng nhập & kiểm tra sức khỏe ----------
app.post('/api/auth/login', async (req, res) => {
    try {
        const body = req.body || {};
        const uname = normalizeUsername(body.username);
        const password = typeof body.password === 'string' ? body.password : '';

        if (!uname || !password) {
            return res.status(400).json({ success: false, error: 'Vui lòng nhập đầy đủ tài khoản và mật khẩu!' });
        }

        const rules = [
            { key: `ip:${req.ip}|${uname}`, max: LOGIN_MAX_PER_IP_USER },
            { key: `user:${uname}`, max: LOGIN_MAX_PER_USER }
        ];
        const wait = lockRemainingMs(rules);
        if (wait > 0) {
            res.set('Retry-After', String(Math.ceil(wait / 1000)));
            return res.status(429).json({
                success: false,
                error: `Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau ${Math.ceil(wait / 60000)} phút!`
            });
        }

        const user = findUser(uname);
        const hash = user && typeof user.passwordHash === 'string' ? user.passwordHash : DUMMY_HASH;
        let passOk = false;
        try {
            passOk = password.length <= 128 && await bcrypt.compare(password, hash);
        } catch (err) {
            console.error(`Hash không hợp lệ của tài khoản "${uname}":`, err.message);
        }

        if (!user || !passOk) {
            recordFail(rules);
            return res.status(401).json({ success: false, error: 'Tài khoản hoặc mật khẩu không chính xác!' });
        }

        if (!isActive(user)) {
            return res.status(403).json({ success: false, error: 'Tài khoản đã bị vô hiệu hóa, vui lòng liên hệ quản trị viên!' });
        }

        clearFails(rules);

        const info = publicUser(user);
        const token = jwt.sign(
            { username: user.username, fullName: user.fullName, role: info.role, position: user.position, company: user.company },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: JWT_EXPIRES_IN, issuer: JWT_ISSUER }
        );

        res.json({ success: true, message: 'Đăng nhập thành công!', token, user: info });
    } catch (error) {
        console.error('Lỗi đăng nhập:', error);
        res.status(500).json({ success: false, error: 'Lỗi hệ thống, vui lòng thử lại sau!' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE Unified Backend Server đang hoạt động ổn định!' });
});

// ---------- TỪ ĐÂY TRỞ XUỐNG: mọi API /api/* đều yêu cầu token hợp lệ ----------
app.use('/api', requireAuth);

// Client dùng để xác minh phiên và lấy hồ sơ mới nhất
app.get('/api/auth/me', (req, res) => {
    res.json({ success: true, user: req.user });
});

// ===============================================================
// 2. NHÓM PROXY & TIỆN ÍCH HỆ THỐNG
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
// 3. NHÓM QUẢN LÝ DỰ ÁN & TẬP TIN CDE (FILE SYSTEM & ISO 19650)
// ===============================================================
const BASE_DATABASE_DIR = path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');

if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const relPath = req.query.path || req.body.targetPath || '';
        const targetDir = path.join(ROOT_DIR, relPath.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
        }
        cb(null, targetDir);
    },
    filename: (req, file, cb) => {
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage });

app.get('/api/files', (req, res) => {
    try {
        const subPath = req.query.path || '';
        const cleanSubPath = subPath.replace(/^database\/bim-vdc\/?/, '');
        const targetDir = path.join(ROOT_DIR, cleanSubPath);

        if (!fs.existsSync(targetDir)) {
            return res.status(404).json({ error: 'Thư mục không tồn tại' });
        }

        const items = fs.readdirSync(targetDir, { withFileTypes: true });
        const result = items.map(item => {
            const itemRelPath = path.join(cleanSubPath, item.name);
            return {
                name: item.name,
                isDirectory: item.isDirectory(),
                type: item.isDirectory() ? 'folder' : 'file',
                path: 'database/bim-vdc/' + itemRelPath.replace(/\\/g, '/')
            };
        });

        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/cde-files', (req, res) => {
    try {
        function walkDir(dir, fileList = []) {
            const files = fs.readdirSync(dir, { withFileTypes: true });
            files.forEach(file => {
                const fullPath = path.join(dir, file.name);
                const relPath = path.relative(BASE_DATABASE_DIR, fullPath);
                if (file.isDirectory()) {
                    fileList.push({
                        name: file.name,
                        path: 'database/' + relPath.replace(/\\/g, '/'),
                        type: 'folder'
                    });
                    walkDir(fullPath, fileList);
                } else {
                    fileList.push({
                        name: file.name,
                        path: 'database/' + relPath.replace(/\\/g, '/'),
                        type: 'file'
                    });
                }
            });
            return fileList;
        }
        const allItems = walkDir(ROOT_DIR);
        res.json(allItems);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        res.json({ success: true, message: 'Tải lên tập tin thành công!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/create-folder', (req, res) => {
    try {
        const { parentPath, folderName } = req.body;
        const cleanParent = (parentPath || 'database/bim-vdc').replace(/^database\/bim-vdc\/?/, '');
        const targetDir = path.join(ROOT_DIR, cleanParent, folderName);

        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
            res.json({ success: true, message: 'Tạo thư mục thành công!' });
        } else {
            res.status(400).json({ success: false, error: 'Thư mục đã tồn tại!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/rename', (req, res) => {
    try {
        const { path: itemPath, newName } = req.body;
        const cleanPath = itemPath.replace(/^database\/bim-vdc\/?/, '');
        const oldFullPath = path.join(ROOT_DIR, cleanPath);
        const parentDir = path.dirname(oldFullPath);
        const newFullPath = path.join(parentDir, newName);

        if (fs.existsSync(oldFullPath)) {
            fs.renameSync(oldFullPath, newFullPath);
            res.json({ success: true, message: 'Đổi tên thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Đường dẫn không tồn tại!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/delete', (req, res) => {
    try {
        const { path: itemPath } = req.body;
        const cleanPath = itemPath.replace(/^database\/bim-vdc\/?/, '');
        const fullPath = path.join(ROOT_DIR, cleanPath);

        if (fs.existsSync(fullPath)) {
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                fs.rmSync(fullPath, { recursive: true, force: true });
            } else {
                fs.unlinkSync(fullPath);
            }
            res.json({ success: true, message: 'Xóa thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Đường dẫn không tồn tại!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/move', (req, res) => {
    try {
        const { sourcePath, targetDir } = req.body;
        const cleanSource = sourcePath.replace(/^database\/bim-vdc\/?/, '');
        const cleanTarget = targetDir.replace(/^database\/bim-vdc\/?/, '');
        
        const srcFullPath = path.join(ROOT_DIR, cleanSource);
        const fileName = path.basename(srcFullPath);
        const targetParentDir = path.join(ROOT_DIR, cleanTarget);
        const destFullPath = path.join(targetParentDir, fileName);

        if (!fs.existsSync(srcFullPath)) {
            return res.status(404).json({ success: false, error: 'Đường dẫn nguồn không tồn tại!' });
        }

        if (!fs.existsSync(targetParentDir)) {
            fs.mkdirSync(targetParentDir, { recursive: true });
        }

        fs.renameSync(srcFullPath, destFullPath);
        res.json({ success: true, message: 'Di chuyển file thành công!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/copy', (req, res) => {
    try {
        const { sourcePath, targetDir } = req.body;
        const cleanSource = sourcePath.replace(/^database\/bim-vdc\/?/, '');
        const cleanTarget = targetDir.replace(/^database\/bim-vdc\/?/, '');
        
        const srcFullPath = path.join(ROOT_DIR, cleanSource);
        const fileName = path.basename(srcFullPath);
        const targetParentDir = path.join(ROOT_DIR, cleanTarget);
        const destFullPath = path.join(targetParentDir, fileName);

        if (!fs.existsSync(srcFullPath)) {
            return res.status(404).json({ success: false, error: 'Đường dẫn nguồn không tồn tại!' });
        }

        if (!fs.existsSync(targetParentDir)) {
            fs.mkdirSync(targetParentDir, { recursive: true });
        }

        const stat = fs.statSync(srcFullPath);
        if (stat.isDirectory()) {
            fs.cpSync(srcFullPath, destFullPath, { recursive: true });
        } else {
            fs.copyFileSync(srcFullPath, destFullPath);
        }
        res.json({ success: true, message: 'Sao chép file thành công!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 4. NHÓM QUẢN LÝ ISSUES / QA-QC TẬP TRUNG
// ===============================================================
const ISSUES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'issues.json');

function readIssuesDB() {
    try {
        if (fs.existsSync(ISSUES_FILE_PATH)) {
            const data = fs.readFileSync(ISSUES_FILE_PATH, 'utf8');
            return JSON.parse(data || '{}');
        }
    } catch (err) {
        console.error('Lỗi đọc file issues.json:', err);
    }
    return {};
}

function writeIssuesDB(dbData) {
    try {
        fs.writeFileSync(ISSUES_FILE_PATH, JSON.stringify(dbData, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Lỗi ghi file issues.json:', err);
        return false;
    }
}

app.get('/api/issues', (req, res) => {
    try {
        const issues = readIssuesDB();
        res.json(issues);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/issues/add', (req, res) => {
    try {
        const { filePath, text, author } = req.body;
        if (!filePath || !text) {
            return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file hoặc nội dung issue!' });
        }

        const db = readIssuesDB();
        if (!db[filePath]) {
            db[filePath] = [];
        }

        const newIssue = {
            text: text.trim(),
            time: new Date().toLocaleString('vi-VN'),
            author: author || 'Phương Vy'
        };

        db[filePath].push(newIssue);

        if (writeIssuesDB(db)) {
            res.json({ success: true, message: 'Đã lưu Issue thành công!', issues: db[filePath] });
        } else {
            res.status(500).json({ success: false, error: 'Không thể ghi file issues.json trên server' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/issues/delete', (req, res) => {
    try {
        const { filePath, index } = req.body;
        const db = readIssuesDB();

        if (db[filePath] && typeof db[filePath][index] !== 'undefined') {
            db[filePath].splice(index, 1);
            if (db[filePath].length === 0) {
                delete db[filePath];
            }
            writeIssuesDB(db);
            return res.json({ success: true, message: 'Đã xóa Issue thành công!', issues: db[filePath] || [] });
        }

        res.status(404).json({ success: false, error: 'Không tìm thấy Issue cần xóa!' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================================================
// 5. NHÓM CHAT NHÓM REALTIME (SSE)
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
const CHAT_MAX_TEXT = 2000;
const CHAT_RATE_COUNT = 10;
const CHAT_RATE_WINDOW_MS = 10000;
const CHAT_KEEPALIVE_MS = 25000;

let chatMessages = [];
try {
    const parsed = JSON.parse(fs.readFileSync(chatFilePath, 'utf8'));
    if (Array.isArray(parsed)) chatMessages = parsed.slice(-CHAT_MAX_MESSAGES);
} catch (err) {}

function saveChatMessages() {
    try {
        const tmp = chatFilePath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(chatMessages));
        fs.renameSync(tmp, chatFilePath);
    } catch (err) {}
}

// Danh tính chat lấy từ token đã xác thực (req.user), KHÔNG tin username do client gửi
function toChatUser(u) {
    if (!u) return null;
    return {
        username: u.username,
        fullName: u.fullName || u.username,
        role: (u.role || '').toString().toUpperCase(),
        groups: Array.isArray(u.groups) ? u.groups.map(g => String(g).toLowerCase()) : []
    };
}

const CHAT_SITE_ROLES = ['ADMIN', 'MASTER'];
function chatRoomOf(v) { return v === 'site' ? 'site' : 'general'; }
function canJoinChatRoom(user, room) {
    return room !== 'site' || CHAT_SITE_ROLES.includes(user.role) || (user.groups || []).includes('site');
}

const chatClients = new Set();

function chatSend(res, event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function chatBroadcast(event, data, room) {
    for (const c of chatClients) {
        if (room && c.room !== room) continue;
        try { chatSend(c.res, event, data); } catch (err) {}
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

const chatSendLog = new Map();
function isChatRateLimited(username) {
    const now = Date.now();
    const arr = (chatSendLog.get(username) || []).filter(t => now - t < CHAT_RATE_WINDOW_MS);
    if (arr.length >= CHAT_RATE_COUNT) { chatSendLog.set(username, arr); return true; }
    arr.push(now);
    chatSendLog.set(username, arr);
    return false;
}

app.get('/api/chat/stream', (req, res) => {
    const user = toChatUser(req.user);
    if (!user) return res.status(403).json({ success: false, message: 'Tài khoản không hợp lệ' });
    const room = chatRoomOf(req.query.room);
    if (!canJoinChatRoom(user, room)) return res.status(403).json({ success: false, message: 'Bạn không thuộc nhóm Site' });

    res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
        'Access-Control-Allow-Origin': req.headers.origin || '*'
    });
    res.write('retry: 3000\n\n');

    const client = { res, user, room };
    chatClients.add(client);
    chatSend(res, 'presence', chatOnlineList(room));
    chatBroadcast('presence', chatOnlineList(room), room);

    const timer = setInterval(() => {
        try { res.write(': keepalive\n\n'); } catch (err) {}
    }, CHAT_KEEPALIVE_MS);

    req.on('close', () => {
        clearInterval(timer);
        chatClients.delete(client);
        chatBroadcast('presence', chatOnlineList(room), room);
    });
});

app.get('/api/chat/history', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, CHAT_MAX_MESSAGES);
    const room = chatRoomOf(req.query.room);
    if (room !== 'general') {
        const user = toChatUser(req.user);
        if (!user) return res.status(403).json({ success: false, message: 'Tài khoản không hợp lệ' });
        if (!canJoinChatRoom(user, room)) return res.status(403).json({ success: false, message: 'Bạn không thuộc nhóm Site' });
    }
    const list = chatMessages.filter(m => (m.room || 'general') === room);
    res.json({ success: true, messages: list.slice(-limit) });
});

app.post('/api/chat/send', (req, res) => {
    const body = req.body || {};
    const user = toChatUser(req.user);
    if (!user) return res.status(403).json({ success: false, message: 'Tài khoản không hợp lệ' });

    const room = chatRoomOf(body.room);
    if (!canJoinChatRoom(user, room)) return res.status(403).json({ success: false, message: 'Bạn không thuộc nhóm Site' });

    const text = (typeof body.text === 'string' ? body.text : '').trim();
    if (!text) return res.status(400).json({ success: false, message: 'Tin nhắn trống' });
    if (text.length > CHAT_MAX_TEXT) {
        return res.status(400).json({ success: false, message: `Tin nhắn tối đa ${CHAT_MAX_TEXT} ký tự` });
    }
    if (isChatRateLimited(user.username)) {
        return res.status(429).json({ success: false, message: 'Bạn gửi quá nhanh, vui lòng chậm lại' });
    }

    const msg = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
        username: user.username,
        fullName: user.fullName,
        role: user.role,
        text,
        ts: Date.now(),
        room
    };
    chatMessages.push(msg);
    if (chatMessages.length > CHAT_MAX_MESSAGES) chatMessages = chatMessages.slice(-CHAT_MAX_MESSAGES);
    saveChatMessages();
    chatBroadcast('chat', msg, room);

    res.json({ success: true, message: msg });
});

// ===============================================================
// 6. NHÓM UPLOAD AVATAR TÀI KHOẢN
// ===============================================================
app.post('/api/upload-avatar', (req, res) => {
    try {
        const { fileName, image } = req.body;
        if (!fileName || !image) {
            return res.status(400).json({ success: false, error: 'Thiếu tên file hoặc dữ liệu ảnh!' });
        }

        const safeName = path.basename(String(fileName));
        if (typeof image !== 'string' || !/^[\p{L}\p{N}_.\- ]+\.(png|jpe?g|gif|webp)$/iu.test(safeName)) {
            return res.status(400).json({ success: false, error: 'Tên file hoặc định dạng ảnh không hợp lệ!' });
        }

        const avatarDir = path.join(__dirname, 'assets', 'data', 'avatar');
        if (!fs.existsSync(avatarDir)) {
            fs.mkdirSync(avatarDir, { recursive: true });
        }

        // Tách chuỗi Base64 để lưu file nhị phân
        const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
        const filePath = path.join(avatarDir, safeName);

        fs.writeFileSync(filePath, Buffer.from(base64Data, 'base64'));
        console.log(`[AVATAR UPLOAD] Đã lưu thành công: ${safeName}`);

        res.json({ 
            success: true, 
            message: 'Tải lên avatar thành công!', 
            path: `assets/data/avatar/${safeName}` 
        });
    } catch (error) {
        console.error('Lỗi upload avatar:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Static serve thư mục chứa database file
app.use('/files', express.static(ROOT_DIR));

// ===============================================================
// KHỞI CHẠY SERVER TỔNG HỢP
// ===============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 CDE Unified Server (Auth + Project Operations) đang chạy qua HTTP tại cổng ${PORT}`);
});