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
    // Lấy token từ Header, Cookie, hoặc URL Query Param
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

    // Kiểm tra tính hợp lệ của Token
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).send('Xác thực thất bại! Token đã hết hạn hoặc không hợp lệ.');
        }
        req.user = user;
        next();
    });
}

// ===============================================================
// PROXY BẢO MẬT CHO REVIT SERVER ADMINISTRATOR 2027
// ===============================================================
// Điều hướng an toàn request /RevitServerAdmin2027 về cổng nội bộ IIS
app.use(
    '/RevitServerAdmin2027',
    verifyAuthToken, // Khóa bảo mật: Phải đăng nhập mới qua được lớp này
    createProxyMiddleware({
        target: 'http://127.0.0.1:8080', // Cổng nội bộ IIS chạy Revit Server Admin
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

// ... (Giữ nguyên toàn bộ phần cấu hình Multer, API file operations hiện tại) ...