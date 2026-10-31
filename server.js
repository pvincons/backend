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
// 2. KHỞI TẠO CÁC THƯ MỤC & HÀM TIỆN ÍCH JSON
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
if (!fs.existsSync(BASE_DATABASE_DIR)) {
    fs.mkdirSync(BASE_DATABASE_DIR, { recursive: true });
}

// Bổ sung hàm tiện ích đọc/ghi JSON an toàn
function readJsonObject(filePath, defaultVal = {}) {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            return JSON.parse(data || JSON.stringify(defaultVal));
        }
    } catch (err) {
        console.error(`Lỗi đọc file JSON (${filePath}):`, err);
    }
    return defaultVal;
}

function writeJsonObject(filePath, objData) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(objData, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error(`Lỗi ghi file JSON (${filePath}):`, err);
        return false;
    }
}

// Hàm hỗ trợ kiểm tra file CDE và băm SHA-256 phục vụ ký số
function resolveCdeFile(filePath) {
    const rel = String(filePath || '').replace(/\\/g, '/').replace(/^database\/bim-vdc\/?/, '');
    const fullPath = path.resolve(ROOT_DIR, rel);
    if (!fullPath.startsWith(ROOT_DIR)) {
        return { error: 'Đường dẫn tệp không hợp lệ!', status: 400 };
    }
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
        return { error: 'Không tìm thấy tệp tin trên hệ thống!', status: 404 };
    }
    return {
        fullPath,
        key: 'database/bim-vdc/' + rel,
        fileName: path.basename(fullPath)
    };
}

async function hashFileSha256(filePath) {
    const fileBuffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(fileBuffer).digest('hex');
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
// 3. PROXY CHO REVIT SERVER ADMINISTRATOR
// ===============================================================
app.use(
    '/RevitServerAdmin2027',
    createProxyMiddleware({
        target: 'https://localhost',
        changeOrigin: true,
        secure: false,
        pathRewrite: { '^/RevitServerAdmin2027': '/RevitServerAdmin2027' },
        onError: (err, req, res) => {
            console.error('[REVIT SERVER PROXY ERROR]:', err.message);
            res.status(500).json({ success: false, error: 'Không thể kết nối tới Revit Server IIS service nội bộ!', details: err.message });
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

        res.json({ success: true, message: 'Đăng nhập thành công!', token: token, user: tokenPayload });
    } catch (error) {
        console.error('[LOGIN ERROR]:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

function requireCdeAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        if (!token) return res.status(401).json({ success: false, error: 'Bạn chưa đăng nhập hoặc phiên đã hết hạn!' });

        let payload;
        try { payload = jwt.verify(token, JWT_SECRET); }
        catch (e) { return res.status(401).json({ success: false, error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn!' }); }

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

// ===============================================================
// 10. TÍCH HỢP VNPT SMARTCA (CSC Standard & OAuth2 - Tài liệu v1.1)
// ===============================================================
const VNPT_SMARTCA_BASE_URL = (process.env.VNPT_SMARTCA_BASE_URL || 'https://rmgateway.vnptit.vn').replace(/\/+$/, '');
const VNPT_SMARTCA_CLIENT_ID = process.env.VNPT_SMARTCA_CLIENT_ID || '';
const VNPT_SMARTCA_CLIENT_SECRET = process.env.VNPT_SMARTCA_CLIENT_SECRET || '';

const SIGNATURES_FILE_PATH = path.join(BASE_DATABASE_DIR, 'signatures.json');
const SMARTCA_TX_FILE_PATH = path.join(BASE_DATABASE_DIR, 'smartca_transactions.json');

if (!fs.existsSync(SIGNATURES_FILE_PATH)) writeJsonObject(SIGNATURES_FILE_PATH, {});
if (!fs.existsSync(SMARTCA_TX_FILE_PATH)) writeJsonObject(SMARTCA_TX_FILE_PATH, {});

const readSignaturesDB = () => readJsonObject(SIGNATURES_FILE_PATH);
const readSmartCaTxDB = () => readJsonObject(SMARTCA_TX_FILE_PATH);

async function getSmartCaAccessToken() {
    try {
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_id', VNPT_SMARTCA_CLIENT_ID);
        params.append('client_secret', VNPT_SMARTCA_CLIENT_SECRET);
        params.append('scope', 'email offline_access openid profile sign');

        const response = await fetch(`${VNPT_SMARTCA_BASE_URL}/auth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });
        const data = await response.json();
        if (response.ok && data.access_token) {
            return data.access_token;
        }
        console.error('[SmartCA Token Error]:', data);
        return null;
    } catch (err) {
        console.error('[SmartCA Token Exception]:', err.message);
        return null;
    }
}

async function smartCaApiCall(endpoint, payloadOrParams, method = 'POST') {
    const token = await getSmartCaAccessToken();
    if (!token) throw new Error('Không thể lấy OAuth2 Access Token từ VNPT SmartCA Authentication Service!');

    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    let url = `${VNPT_SMARTCA_BASE_URL}${endpoint}`;
    const options = { method, headers };

    if (method === 'POST') {
        options.body = JSON.stringify(payloadOrParams);
    }

    const response = await fetch(url, options);
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { message: text }; }
    return { httpStatus: response.status, data };
}

// 10.1 API Lấy danh sách Credential[cite: 16]
app.post('/api/smartca/credentials/list', requireCdeAuth, async (req, res) => {
    try {
        const r = await smartCaApiCall('/csc/credentials/list', {});
        if (r.httpStatus >= 400) {
            return res.status(r.httpStatus).json({ success: false, error: r.data.message || 'Lỗi lấy danh sách credential' });
        }
        res.json({ success: true, content: r.data.content || r.data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.2 API Lấy thông tin chi tiết Credential[cite: 16]
app.post('/api/smartca/credentials/info', requireCdeAuth, async (req, res) => {
    try {
        const { credentialId, certificates = 'chain', certInfo = true, authInfo = true } = req.body;
        if (!credentialId) return res.status(400).json({ success: false, error: 'Thiếu credentialId!' });

        const r = await smartCaApiCall('/csc/credentials/info', { credentialId, certificates, certInfo, authInfo });
        if (r.httpStatus >= 400) {
            return res.status(r.httpStatus).json({ success: false, error: r.data.message || 'Lỗi lấy thông tin credential' });
        }
        res.json({ success: true, content: r.data.content || r.data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.3 API Gửi yêu cầu ký Hash[cite: 18]
app.post('/api/smartca/signatures/signhash', requireCdeAuth, async (req, res) => {
    try {
        const { credentialId, refTranId, description, filePath } = req.body;
        if (!credentialId || !filePath) return res.status(400).json({ success: false, error: 'Thiếu thông tin credentialId hoặc filePath!' });

        const file = resolveCdeFile(filePath);
        if (file.error) return res.status(file.status).json({ success: false, error: file.error });

        const hashHex = await hashFileSha256(file.fullPath);
        const base64Hash = Buffer.from(hashHex, 'hex').toString('base64');
        const tranIdOut = crypto.randomUUID();

        const payload = {
            credentialId,
            refTranId: refTranId || tranIdOut,
            description: description || `CDE Signhash ${file.fileName}`,
            datas: [{ name: file.fileName, hash: base64Hash }]
        };

        const r = await smartCaApiCall('/csc/signature/signhash', payload);
        if (r.httpStatus >= 400 || (r.data.code && r.data.code !== 0)) {
            return res.status(r.httpStatus >= 400 ? r.httpStatus : 400).json({ success: false, error: r.data.message || 'Lỗi yêu cầu ký hash SmartCA' });
        }

        const content = r.data.content || {};
        const tranId = content.tranId || tranIdOut;

        const db = readSmartCaTxDB();
        db[tranId] = {
            tranId,
            credentialId,
            filePath: file.key,
            fileName: file.fileName,
            hashHex,
            createdAt: new Date().toISOString(),
            state: 'pending'
        };
        writeJsonObject(SMARTCA_TX_FILE_PATH, db);

        res.json({ success: true, content: { tranId, message: r.data.message || 'Chờ người dùng xác nhận' } });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10.4 API Kiểm tra trạng thái giao dịch ký số[cite: 20]
app.post('/api/smartca/signatures/gettraninfo', requireCdeAuth, async (req, res) => {
    try {
        const { tranId } = req.body;
        if (!tranId) return res.status(400).json({ success: false, error: 'Thiếu tranId!' });

        const r = await smartCaApiCall('/csc/credentials/gettraninfo', { tranId });
        if (r.httpStatus >= 400) {
            return res.status(r.httpStatus).json({ success: false, error: r.data.message || 'Lỗi kiểm tra trạng thái giao dịch' });
        }

        const content = r.data.content || {};
        if (content.tranStatus === 1 || content.tranStatusDesc === 'SUCCESS') {
            const db = readSmartCaTxDB();
            if (db[tranId]) {
                db[tranId].state = 'done';
                writeJsonObject(SMARTCA_TX_FILE_PATH, db);

                const sigDb = readSignaturesDB();
                sigDb[db[tranId].filePath] = {
                    filePath: db[tranId].filePath,
                    fileName: db[tranId].fileName,
                    tranId,
                    signedBy: req.authUser.fullName || req.authUser.username,
                    signedAt: new Date().toISOString(),
                    documents: content.documents || []
                };
                writeJsonObject(SIGNATURES_FILE_PATH, sigDb);
            }
        }

        res.json({ success: true, content });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// API xuất file gói chữ ký .json
app.get('/api/smartca/signatures/export', requireCdeAuth, (req, res) => {
    try {
        const filePath = req.query.path;
        if (!filePath) return res.status(400).json({ success: false, error: 'Thiếu đường dẫn file!' });
        const sigDb = readSignaturesDB();
        const sig = sigDb[filePath] || sigDb['database/bim-vdc/' + filePath.replace(/^database\/bim-vdc\/?/, '')];
        if (!sig) return res.status(404).json({ success: false, error: 'Không tìm thấy thông tin chữ ký cho tệp này!' });
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}.smartca-signature.json"`);
        res.send(JSON.stringify(sig, null, 2));
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Lấy danh sách signatures tổng hợp
app.get('/api/smartca/signatures', requireCdeAuth, (req, res) => {
    try {
        res.json(readSignaturesDB());
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

function resumeSmartCaTransactions() {
    try {
        const db = readSmartCaTxDB();
        let changed = false;
        Object.values(db).forEach(tx => {
            if (tx.state !== 'pending') return;
            if (Date.now() > (tx.createdAt ? new Date(tx.createdAt).getTime() + 300000 : 0)) {
                tx.state = 'failed';
                tx.error = 'Giao dịch đã quá hạn (server khởi động lại).';
                changed = true;
            }
        });
        if (changed) writeJsonObject(SMARTCA_TX_FILE_PATH, db);
    } catch (e) {
        console.error('Lỗi resume transactions:', e);
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

app.get('/api/cde-files', (req, res) => {
    try {
        function walkDir(dir, fileList = []) {
            if (!fs.existsSync(dir)) return fileList;
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

app.post('/api/upload', upload.array('files'), (req, res) => {
    res.json({ success: true, message: 'Tải lên tập tin thành công!' });
});

app.post('/api/delete', (req, res) => {
    try {
        const fullPath = path.join(ROOT_DIR, req.body.path.replace(/^database\/bim-vdc\/?/, ''));
        if (fs.existsSync(fullPath)) {
            fs.rmSync(fullPath, { recursive: true, force: true });
            res.json({ success: true, message: 'Xóa thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Không tồn tại!' });
        }
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/rename', (req, res) => {
    try {
        const { path: itemPath, newName } = req.body;
        const oldFullPath = path.join(ROOT_DIR, itemPath.replace(/^database\/bim-vdc\/?/, ''));
        if (fs.existsSync(oldFullPath)) {
            fs.renameSync(oldFullPath, path.join(path.dirname(oldFullPath), newName));
            res.json({ success: true, message: 'Đổi tên thành công!' });
        } else {
            res.status(404).json({ success: false, error: 'Đường dẫn không tồn tại!' });
        }
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/move', (req, res) => {
    try {
        const { sourcePath, targetDir } = req.body;
        const srcFullPath = path.join(ROOT_DIR, sourcePath.replace(/^database\/bim-vdc\/?/, ''));
        const destParent = path.join(ROOT_DIR, targetDir.replace(/^database\/bim-vdc\/?/, ''));
        if (!fs.existsSync(srcFullPath)) return res.status(404).json({ success: false, error: 'Nguồn không tồn tại!' });
        if (!fs.existsSync(destParent)) fs.mkdirSync(destParent, { recursive: true });
        fs.renameSync(srcFullPath, path.join(destParent, path.basename(srcFullPath)));
        res.json({ success: true, message: 'Di chuyển thành công!' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.get('/api/issues', (req, res) => {
    try { res.json(readJsonObject(ISSUES_FILE_PATH, {})); } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/api/issues/add', (req, res) => {
    try {
        const { filePath, text, author } = req.body;
        if (!filePath || !text) return res.status(400).json({ success: false, error: 'Thiếu thông tin!' });
        const db = readJsonObject(ISSUES_FILE_PATH, {});
        if (!db[filePath]) db[filePath] = [];
        db[filePath].push({ text: text.trim(), time: new Date().toLocaleString('vi-VN'), author: author || 'Phước' });
        writeJsonObject(ISSUES_FILE_PATH, db);
        res.json({ success: true, message: 'Đã lưu Issue!', issues: db[filePath] });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.get('/api/recalls', (req, res) => {
    try { res.json(readJsonObject(RECALLS_FILE_PATH, {})); } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// ===============================================================
// 12. STATIC SERVE & KHỞI ĐỘNG SERVER
// ===============================================================
app.use('/files', express.static(ROOT_DIR));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 PV INCONS CDE Backend Server đang chạy tại cổng ${PORT}`);
});