const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

app.set('trust proxy', true);

app.use(cors());
app.use(express.json());

// Middleware ghi log request thời gian thực
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// ===============================================================
// PROXY CHO REVIT SERVER ADMINISTRATOR
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

const BASE_DATABASE_DIR = path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');
const ISSUES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'issues.json');

if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

// Hàm hỗ trợ đọc file issues.json an toàn
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

// Hàm hỗ trợ ghi file issues.json an toàn
function writeIssuesDB(dbData) {
    try {
        fs.writeFileSync(ISSUES_FILE_PATH, JSON.stringify(dbData, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Lỗi ghi file issues.json:', err);
        return false;
    }
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

// ===============================================================
// API HEALTH CHECK
// ===============================================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE Backend Server đang hoạt động ổn định!' });
});

// ===============================================================
// API QUẢN LÝ ISSUES / QA-QC TẬP TRUNG TRÊN SERVER
// ===============================================================
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
// API QUẢN LÝ TẬP TIN & CDE (FILE SYSTEM & ISO 19650 GATES)
// ===============================================================
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
        console.log(`[REAL-TIME SYNC] Đã di chuyển file: ${cleanSource} ➔ ${cleanTarget}`);
        res.json({ success: true, message: 'Di chuyển file thành công!' });
    } catch (error) {
        console.error('Lỗi di chuyển file:', error);
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
// CHAT NHÓM REALTIME (SSE)
//   GET  /api/chat/stream?username=...   Kênh realtime: sự kiện chat | presence
//   GET  /api/chat/history?limit=100     Lịch sử tin nhắn
//   POST /api/chat/send {username,text}  Gửi tin nhắn
// Lịch sử lưu ngoài thư mục dự án (xem CHAT_DATA_DIR), người dùng lấy từ assets/data/users.json
// ===============================================================
// Lịch sử chat lưu NGOÀI thư mục dự án để Live Server (VS Code) không tự tải lại trang
// mỗi khi có tin nhắn mới. Có thể đổi nơi lưu bằng biến môi trường CHAT_DATA_DIR.
const CHAT_DATA_DIR = process.env.CHAT_DATA_DIR || path.join(__dirname, '..', 'CDE_CHAT_DATA');
const CHAT_LEGACY_FILE = path.join(BASE_DATABASE_DIR, 'chat.json'); // vị trí cũ (bản trước)
let chatFilePath = path.join(CHAT_DATA_DIR, 'chat.json');
try {
    fs.mkdirSync(CHAT_DATA_DIR, { recursive: true });
    // Chuyển lịch sử cũ sang vị trí mới (nếu có)
    if (!fs.existsSync(chatFilePath) && fs.existsSync(CHAT_LEGACY_FILE)) {
        fs.copyFileSync(CHAT_LEGACY_FILE, chatFilePath);
    }
} catch (err) {
    console.warn('Không tạo được thư mục lưu chat, dùng tạm database/chat.json:', err.message);
    chatFilePath = CHAT_LEGACY_FILE;
}
console.log('💬 Lịch sử chat lưu tại:', chatFilePath);
const CHAT_USERS_FILE = path.join(__dirname, 'assets', 'data', 'users.json');
const CHAT_MAX_MESSAGES = 1000;
const CHAT_MAX_TEXT = 2000;
const CHAT_RATE_COUNT = 10;        // tối đa 10 tin ...
const CHAT_RATE_WINDOW_MS = 10000; // ... trong 10 giây
const CHAT_KEEPALIVE_MS = 25000;

let chatMessages = [];
try {
    const parsed = JSON.parse(fs.readFileSync(chatFilePath, 'utf8'));
    if (Array.isArray(parsed)) chatMessages = parsed.slice(-CHAT_MAX_MESSAGES);
} catch (err) { /* chưa có file → bắt đầu rỗng */ }

function saveChatMessages() {
    try {
        const tmp = chatFilePath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(chatMessages));
        fs.renameSync(tmp, chatFilePath);
    } catch (err) {
        console.error('Lỗi ghi file chat.json:', err.message);
    }
}

// Chỉ lấy các trường công khai của user, KHÔNG bao giờ trả mật khẩu
function findChatUser(username) {
    if (!username || typeof username !== 'string') return null;
    try {
        const users = JSON.parse(fs.readFileSync(CHAT_USERS_FILE, 'utf8'));
        const u = users.find(x => x.username === username);
        if (!u) return null;
        return {
            username: u.username,
            fullName: u.fullName || u.username,
            role: (u.role || '').toString().toUpperCase(),
            groups: Array.isArray(u.groups) ? u.groups.map(g => String(g).toLowerCase()) : [] // vd: ["site"]
        };
    } catch (err) {
        console.error('Chat không đọc được users.json:', err.message);
        return null;
    }
}

// --- Phòng chat: 'general' (chat chung, mặc định) và 'site' (nhóm nhân sự công trường) ---
// Vào được nhóm Site: role ADMIN/MASTER, hoặc trong users.json có "groups": ["site"].
const CHAT_SITE_ROLES = ['ADMIN', 'MASTER'];
function chatRoomOf(v) { return v === 'site' ? 'site' : 'general'; }
function canJoinChatRoom(user, room) {
    return room !== 'site' || CHAT_SITE_ROLES.includes(user.role) || (user.groups || []).includes('site');
}

const chatClients = new Set(); // { res, user, room }

function chatSend(res, event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function chatBroadcast(event, data, room) {
    for (const c of chatClients) {
        if (room && c.room !== room) continue;
        try { chatSend(c.res, event, data); } catch (err) { /* kết nối đã đóng */ }
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

const chatSendLog = new Map(); // username → [timestamps]
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
        'X-Accel-Buffering': 'no', // tắt buffer khi chạy sau nginx
        'Access-Control-Allow-Origin': req.headers.origin || '*'
    });
    res.write('retry: 3000\n\n');

    const client = { res, user, room };
    chatClients.add(client);
    chatSend(res, 'presence', chatOnlineList(room));
    chatBroadcast('presence', chatOnlineList(room), room);

    const timer = setInterval(() => {
        try { res.write(': keepalive\n\n'); } catch (err) { /* ignore */ }
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
    if (room !== 'general') { // phòng riêng: bắt buộc xác thực tài khoản + kiểm tra nhóm
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

// Static serve thư mục chứa database file để client có thể truy cập trực tiếp khi cần
app.use('/files', express.static(ROOT_DIR));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌐 CDE Server (Tối ưu Backend Tác Vụ) đang chạy qua HTTP tại cổng ${PORT}`);
});