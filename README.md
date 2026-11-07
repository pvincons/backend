# backend

Quy trình chuẩn khi triển khai (Deployment):
Đẩy mã nguồn lên server: Gồm toàn bộ source code của dự án, bắt buộc phải có package.json và package-lock.json. (không tải folder node_modules)
Cài đặt trên server: Kết nối vào terminal của server và chạy lệnh:
Nếu dùng package-lock.json: Chạy lệnh npm ci (lệnh này giúp cài đặt chính xác 100% các phiên bản gói như lúc bạn code ở máy local, rất an toàn cho môi trường production).
Hoặc chạy lệnh: npm install (hoặc npm install --production nếu bạn muốn bỏ qua các thư viện chỉ dùng cho việc dev/test).

Dữ liệu tài khoản, thông báo và ảnh đại diện nằm trong thư mục `database/` và chạy cùng backend `server.js` (đổi vị trí bằng biến môi trường `DATABASE_PATH`):
- `database/users.json`: danh sách tài khoản (bắt buộc phải có, thiếu hoặc hỏng thì backend không khởi động).
- `database/notifications.json`: thông báo hệ thống (tự tạo file rỗng nếu chưa có).
- `database/avatar/`: ảnh đại diện, tên file dạng `<username>_avatar.<png|jpg|webp|gif>`.

Không còn đồng bộ từ GitHub, biến môi trường `USERS_JSON_URL` không còn được sử dụng.

API liên quan:
- `GET /api/notifications` (cần đăng nhập): thông báo đang bật, dùng cho chuông thông báo.
- `POST /api/upload-avatar` (cần đăng nhập): lưu ảnh của chính tài khoản đang đăng nhập và cập nhật `avatarLink` trong `users.json`.
- `GET /api/avatar/<file>`: phục vụ ảnh đại diện.
- `GET/PUT /api/admin/users` và `GET/PUT /api/admin/notifications` (chỉ ADMIN): dùng cho Super Admin Portal (`admin/index.html`). Mỗi lần ghi `users.json` backend giữ bản sao lưu gần nhất ở `database/users.json.bak`.

Khi nâng cấp từ cấu trúc cũ, lần chạy đầu tiên backend tự chuyển `users-cache.json`, `assets/data/notifications.json` và `assets/data/avatar/*` sang `database/` nếu file đích chưa tồn tại.

Đổi mật khẩu hoặc cập nhật tài khoản thực hiện qua trang quản trị (Super Admin Portal); API `/api/change-password` vẫn từ chối đổi trực tiếp.