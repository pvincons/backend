const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const multer = require('multer');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken'); // Thêm JWT để xác thực Token
const { createProxyMiddleware } = require('http-proxy-middleware'); // Thêm Proxy Middleware

const app = express();

// Khóa bí mật dùng cho Token (đồng bộ với hệ thống Auth của bạn)
const JWT_SECRET = process.env.JWT_SECRET || 'PV_INCONS_SECRET_KEY_2026';

// Cấu hình tin tưởng Proxy
app.set('trust proxy', true);

app.use(cors());
app.use(express.json());

// Console log giám sát yêu cầu từ Frontend
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// ===============================================================
// MIDDLEWARE XÁC THỰC BẢO MẬT (AUTH GUARD)
// ===============================================================
function verifyAuthToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];

    if (!token && req.query && req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        return res.status(403).send(`
            <html lang="vi">
            <head><title>403 Forbidden - Truy cập bị từ chối</title></head>
            <body style="background:#0f172a; color:#fff; font-family:sans-serif; text-align:center; padding-top:100px;">
                <h1 style="color:#f43f5e;">403 FORBIDDEN</h1>
                <p>Bạn không có quyền truy cập trực tiếp vào Revit Server Administrator!</p>
                <p>Vui lòng đăng nhập vào hệ thống <b>BIM - VDC CDE Workspace</b> trước khi mở tính năng này.</p>
                <a href="/" style="color:#3b82f6; text-decoration:none; font-weight:bold;"> Quay về trang đăng nhập</a>
            </body>
            </html>
        `);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).send('Xác thực thất bại! Token đã hết hạn hoặc không hợp lệ.');
        }
        req.user = user;
        next();
    });
}

// ===============================================================
// PROXY BẢO MẬT CHO REVIT SERVER ADMINISTRATOR
// ===============================================================
app.use(
    '/RevitServerAdmin2027',
    verifyAuthToken,
    createProxyMiddleware({
        target: 'http://127.0.0.1:808', // Cổng nội bộ Revit Server / IIS của bạn
        changeOrigin: true,
        pathRewrite: {
            '^/RevitServerAdmin2027': '/RevitServerAdmin2027',
        },
        onError: (err, req, res) => {
            res.status(500).send('Không thể kết nối tới Revit Server IIS service nội bộ!');
        }
    })
);

// Đường dẫn thư mục gốc CDE
const BASE_DATABASE_DIR = path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');

// Đảm bảo thư mục database tồn tại
if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

// Cấu hình Multer để upload file
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const relPath = req.query.path || '';
        const targetDir = path.join(ROOT_DIR, relPath);
        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
        }
        cb(null, targetDir);
    },
    filename: (req, file, cb) => {
        // Giữ nguyên tên tiếng Việt có dấu
        cb(null, Buffer.from(file.originalname, 'latin1').toString('utf8'));
    }
});
const upload = multer({ storage: storage });

// ===============================================================
// API CDE - QUẢN LÝ DỮ LIỆU TẬP TRUNG
// ===============================================================

// 1. API Kiểm tra kết nối Server từ Frontend
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'CDE Backend Server đang hoạt động ổn định!' });
});

// 2. API Lấy danh sách file và thư mục
app.get('/api/files', (req, res) => {
    try {
        const subPath = req.query.path || '';
        const targetDir = path.join(ROOT_DIR, subPath);

        if (!fs.existsSync(targetDir)) {
            return res.status(404).json({ error: 'Thư mục không tồn tại' });
        }

        const items = fs.readdirSync(targetDir, { withFileTypes: true });
        const result = items.map(item => {
            const itemPath = path.join(subPath, item.name);
            return {
                name: item.name,
                isDirectory: item.isDirectory(),
                path: itemPath.replace(/\\/g, '/')
            };
        });

        res.json({ success: true, data: result });
    } catch (error) {
        console.error('Lỗi đọc thư mục:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 3. API Upload file lên thư mục
app.post('/api/upload', upload.array('files'), (req, res) => {
    try {
        res.json({ success: true, message: 'Tải lên tập tin thành công!' });
    } catch (error) {
        console.error('Lỗi upload:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Khởi động Server HTTP thuần trên cổng 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌐 CDE Server đang chạy qua HTTP tại cổng ${PORT}`);
});