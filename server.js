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

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'PV_INCONS_SECRET_KEY_2026';
const USER_FILE_PATH = path.join(__dirname, 'assets', 'data', 'users.json');

// Middleware ghi log request thời gian thực
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
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
    const defaultPasswordHash = bcrypt.hashSync("123456", 10);
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

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE Unified Backend Server đang hoạt động ổn định!' });
});

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
    } catch (err) {
        return null;
    }
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
    const user = findChatUser(req.query.username);
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
        const user = findChatUser(req.query.username);
        if (!user) return res.status(403).json({ success: false, message: 'Tài khoản không hợp lệ' });
        if (!canJoinChatRoom(user, room)) return res.status(403).json({ success: false, message: 'Bạn không thuộc nhóm Site' });
    }
    const list = chatMessages.filter(m => (m.room || 'general') === room);
    res.json({ success: true, messages: list.slice(-limit) });
});

app.post('/api/chat/send', (req, res) => {
    const body = req.body || {};
    const user = findChatUser(body.username);
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

        const avatarDir = path.join(__dirname, 'assets', 'data', 'avatar');
        if (!fs.existsSync(avatarDir)) {
            fs.mkdirSync(avatarDir, { recursive: true });
        }

        // Tách chuỗi Base64 để lưu file nhị phân
        const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
        const filePath = path.join(avatarDir, fileName);

        fs.writeFileSync(filePath, Buffer.from(base64Data, 'base64'));
        console.log(`[AVATAR UPLOAD] Đã lưu thành công: ${fileName}`);

        res.json({ 
            success: true, 
            message: 'Tải lên avatar thành công!', 
            path: `assets/data/avatar/${fileName}` 
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