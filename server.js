const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { exec } = require('child_process');

const app = express();
app.use(cors());
app.use(express.json());

// Console log giám sát yêu cầu từ Frontend
app.use((req, res, next) => {
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    next();
});

// Đường dẫn thư mục gốc CDE
const BASE_DATABASE_DIR = path.join(__dirname, 'database');
const ROOT_DIR = path.join(BASE_DATABASE_DIR, 'bim-vdc');

// Tự động khởi tạo thư mục gốc nếu chưa có
if (!fs.existsSync(ROOT_DIR)) {
    fs.mkdirSync(ROOT_DIR, { recursive: true });
}

// Hàm chuẩn hóa đường dẫn tuyệt đối an toàn (chống Path Traversal)
function getAbsolutePath(relPath) {
    if (!relPath || relPath === 'database/bim-vdc' || relPath === 'bim-vdc' || relPath === '/') {
        return ROOT_DIR;
    }
    let cleaned = String(relPath)
        .replace(/^database\/bim-vdc\/?/, '')
        .replace(/^bim-vdc\/?/, '')
        .replace(/^\//, '');
    const absolute = path.normalize(path.join(ROOT_DIR, cleaned));
    
    if (!absolute.startsWith(ROOT_DIR)) {
        return ROOT_DIR;
    }
    return absolute;
}

// Phân loại bộ môn theo đuôi file hoặc tên file
function parseDiscipline(fileName) {
    const parts = fileName.split('-');
    if (parts.length >= 2) {
        const originator = parts[1].toUpperCase();
        if (['ARC', 'STR', 'MEP', 'CIV'].includes(originator)) return originator;
    }
    const ext = path.extname(fileName).toLowerCase();
    if (['.rvt', '.rte', '.rfa'].includes(ext)) return 'ARC';
    if (['.dwg', '.dxf'].includes(ext)) return 'CAD';
    if (['.pdf', '.doc', '.docx', '.xlsx'].includes(ext)) return 'DOC';
    if (['.nwd', '.ifc'].includes(ext)) return 'BIM';
    return 'GEN';
}

// Cấu hình Multer Upload File
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const targetPath = getAbsolutePath(req.body.targetPath || req.body.folder || req.body.path);
        if (!fs.existsSync(targetPath)) {
            fs.mkdirSync(targetPath, { recursive: true });
        }
        cb(null, targetPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });

// Chuẩn hóa Object dữ liệu trả về cho Frontend
function createItemObject(dirPath, item) {
    const fullPath = path.join(dirPath, item.name);
    const isDir = item.isDirectory();
    const stats = fs.existsSync(fullPath) ? fs.statSync(fullPath) : { size: 0, mtime: new Date() };
    const ext = path.extname(item.name).toLowerCase();
    
    const relFromRoot = path.relative(__dirname, fullPath).replace(/\\/g, '/');
    const relFromBim = path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/');

    return {
        name: item.name,
        fileName: item.name,
        title: item.name,
        type: isDir ? 'folder' : 'file',
        loai: isDir ? 'Folder' : (ext.replace('.', '').toUpperCase() || 'File'),
        extension: ext,
        discipline: parseDiscipline(item.name),
        container: '01_WIP',
        suitability: 'S0',
        revision: 'P01.01',
        path: relFromRoot,
        relativePath: relFromRoot,
        relPath: relFromRoot,
        relFromBim: relFromBim,
        size: isDir ? 0 : stats.size,
        updatedAt: stats.mtime
    };
}

// Quét toàn bộ tệp tin đệ quy
function getAllFilesRecursive(dir) {
    let results = [];
    if (!fs.existsSync(dir)) return results;
    
    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of items) {
        const fullPath = path.join(dir, item.name);
        results.push(createItemObject(dir, item));
        if (item.isDirectory()) {
            results = results.concat(getAllFilesRecursive(fullPath));
        }
    }
    return results;
}

// ===============================================================
// 1. DANH SÁCH TỆP TIN & DỰ ÁN
// ===============================================================

const handleGetFiles = (req, res) => {
    try {
        const reqPath = req.query.path || req.query.folder || req.query.dir || 'database/bim-vdc';
        const targetDir = getAbsolutePath(reqPath);

        if (!fs.existsSync(targetDir)) {
            return res.json([]);
        }

        const items = fs.readdirSync(targetDir, { withFileTypes: true });
        const list = items.map(item => createItemObject(targetDir, item));
        res.json(list);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

app.get(['/api/files', '/api/list', '/api/database'], handleGetFiles);

app.get('/api/cde-files', (req, res) => {
    if (!req.query.path && !req.query.folder && !req.query.dir) {
        return res.json(getAllFilesRecursive(ROOT_DIR));
    }
    return handleGetFiles(req, res);
});

// API Danh sách dự án gốc
app.get('/api/projects', (req, res) => {
    try {
        if (!fs.existsSync(ROOT_DIR)) return res.json([]);
        const items = fs.readdirSync(ROOT_DIR, { withFileTypes: true });
        const subDirs = items.filter(item => item.isDirectory()).map(item => createItemObject(ROOT_DIR, item));
        res.json(subDirs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===============================================================
// 2. CÁC THAO TÁC QUẢN LÝ DỮ LIỆU
// ===============================================================

// API Đổi tên Tệp tin / Thư mục
app.post(['/api/rename', '/api/files/rename'], (req, res) => {
    const { path: itemPath, oldPath, newName } = req.body;
    const targetPath = itemPath || oldPath;

    if (!targetPath || !newName) {
        return res.status(400).json({ error: 'Cần truyền đường dẫn cũ và tên mới' });
    }

    try {
        const absOldPath = getAbsolutePath(targetPath);
        if (!fs.existsSync(absOldPath)) {
            return res.status(404).json({ error: 'Không tìm thấy tệp hoặc thư mục cần đổi tên' });
        }

        const parentDir = path.dirname(absOldPath);
        const absNewPath = path.join(parentDir, newName);

        if (fs.existsSync(absNewPath)) {
            return res.status(400).json({ error: 'Tên mới đã tồn tại trên thư mục này' });
        }

        fs.renameSync(absOldPath, absNewPath);

        const newRelPath = path.relative(__dirname, absNewPath).replace(/\\/g, '/');
        res.json({ success: true, message: 'Đổi tên thành công', newPath: newRelPath });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Xóa Tệp tin / Thư mục
app.post(['/api/delete', '/api/files/delete'], (req, res) => {
    const { path: itemPath, targetPath } = req.body;
    const itemToDelete = itemPath || targetPath;

    if (!itemToDelete) {
        return res.status(400).json({ error: 'Cần chỉ định tệp hoặc thư mục cần xóa' });
    }

    try {
        const absPath = getAbsolutePath(itemToDelete);

        if (absPath === ROOT_DIR) {
            return res.status(403).json({ error: 'Không thể xóa thư mục gốc dự án' });
        }

        if (!fs.existsSync(absPath)) {
            return res.status(404).json({ error: 'Tệp hoặc thư mục không tồn tại' });
        }

        fs.rmSync(absPath, { recursive: true, force: true });
        res.json({ success: true, message: 'Xóa thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Sao chép (Copy)
app.post(['/api/copy', '/api/files/copy'], (req, res) => {
    const { sourcePath, targetDir } = req.body;

    if (!sourcePath || !targetDir) {
        return res.status(400).json({ error: 'Cần tham số sourcePath và targetDir' });
    }

    try {
        const absSource = getAbsolutePath(sourcePath);
        const absTargetFolder = getAbsolutePath(targetDir);

        if (!fs.existsSync(absSource)) {
            return res.status(404).json({ error: 'Tệp/Thư mục nguồn không tồn tại' });
        }

        if (!fs.existsSync(absTargetFolder)) {
            fs.mkdirSync(absTargetFolder, { recursive: true });
        }

        const fileName = path.basename(absSource);
        let absDest = path.join(absTargetFolder, fileName);

        if (fs.existsSync(absDest)) {
            const ext = path.extname(fileName);
            const nameWithoutExt = path.basename(fileName, ext);
            absDest = path.join(absTargetFolder, `${nameWithoutExt}_Copy${ext}`);
        }

        fs.cpSync(absSource, absDest, { recursive: true });
        res.json({ success: true, message: 'Sao chép thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Di chuyển (Move)
app.post(['/api/move', '/api/files/move'], (req, res) => {
    const { sourcePath, targetDir } = req.body;

    if (!sourcePath || !targetDir) {
        return res.status(400).json({ error: 'Cần tham số sourcePath và targetDir' });
    }

    try {
        const absSource = getAbsolutePath(sourcePath);
        const absTargetFolder = getAbsolutePath(targetDir);

        if (!fs.existsSync(absSource)) {
            return res.status(404).json({ error: 'Tệp/Thư mục nguồn không tồn tại' });
        }

        if (!fs.existsSync(absTargetFolder)) {
            fs.mkdirSync(absTargetFolder, { recursive: true });
        }

        const fileName = path.basename(absSource);
        const absDest = path.join(absTargetFolder, fileName);

        if (fs.existsSync(absDest)) {
            return res.status(400).json({ error: 'Thư mục đích đã tồn tại tệp trùng tên' });
        }

        try {
            fs.renameSync(absSource, absDest);
        } catch (e) {
            fs.cpSync(absSource, absDest, { recursive: true });
            fs.rmSync(absSource, { recursive: true, force: true });
        }

        res.json({ success: true, message: 'Di chuyển thành công' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Mở file bằng ứng dụng chuyên dụng trực tiếp trên máy chủ VPS
app.post(['/api/open-local', '/api/files/open', '/api/open'], (req, res) => {
    const { path: itemPath } = req.body;
    if (!itemPath) return res.status(400).json({ error: 'Cần truyền đường dẫn tệp tin' });

    try {
        const absPath = getAbsolutePath(itemPath);
        if (!fs.existsSync(absPath)) {
            return res.status(404).json({ error: 'Tệp tin không tồn tại trên hệ thống' });
        }

        let command = '';
        if (process.platform === 'win32') {
            const winPath = path.normalize(absPath).replace(/\//g, '\\');
            command = `start "" "${winPath}"`;
        } else if (process.platform === 'darwin') {
            command = `open "${absPath}"`;
        } else {
            command = `xdg-open "${absPath}"`;
        }

        console.log(`[EXEC COMMAND ON SERVER]: ${command}`);

        exec(command, (err) => {
            if (err) {
                console.error('Lỗi khi kích hoạt phần mềm mở tệp trên Server:', err);
                return res.status(500).json({ error: 'Không thể mở tệp trên Server: ' + err.message });
            }
            res.json({ success: true, message: 'Đã phát lệnh mở tệp trên hệ thống Server thành công' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Tạo thư mục mới
app.post('/api/create-folder', (req, res) => {
    const { parentPath, folderName } = req.body;
    if (!folderName) return res.status(400).json({ error: 'Tên thư mục không hợp lệ' });

    const parentDir = getAbsolutePath(parentPath);
    const targetDir = path.join(parentDir, folderName);

    try {
        if (!fs.existsSync(targetDir)) {
            fs.mkdirSync(targetDir, { recursive: true });
            return res.json({ success: true, path: targetDir });
        }
        res.status(400).json({ error: 'Thư mục đã tồn tại' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API Upload Tệp tin
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Chưa chọn tệp tin' });
    res.json({ success: true, file: req.file });
});

app.use(express.static(__dirname));

// Phục vụ tĩnh trực tiếp từ thư mục ROOT_DIR (database/bim-vdc)
app.use('/files', express.static(ROOT_DIR));
app.use('/database/bim-vdc', express.static(ROOT_DIR));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CDE Server sẵn sàng tại http://localhost:${PORT}`));