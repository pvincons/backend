# backend

Quy trình chuẩn khi triển khai (Deployment):
Đẩy mã nguồn lên server: Gồm toàn bộ source code của dự án, bắt buộc phải có package.json và package-lock.json. (không tải folder node_modules)
Cài đặt trên server: Kết nối vào terminal của server và chạy lệnh:
Nếu dùng package-lock.json: Chạy lệnh npm ci (lệnh này giúp cài đặt chính xác 100% các phiên bản gói như lúc bạn code ở máy local, rất an toàn cho môi trường production).
Hoặc chạy lệnh: npm install (hoặc npm install --production nếu bạn muốn bỏ qua các thư viện chỉ dùng cho việc dev/test).

Mặc định backend đọc `http://localhost:5500/assets/data/users.json`, kể cả khi `NODE_ENV=production`. Trên server production, cần đặt biến môi trường `USERS_JSON_URL=https://pvincons.cloud/assets/data/users.json` (hoặc URL public chính xác của file frontend). Backend làm mới cache nội bộ mỗi 30 giây. Khi URL chưa tải được lúc khởi động, backend sẽ báo lỗi và không chạy. Thay đổi tài khoản/mật khẩu thực hiện qua trang quản trị để xuất bản lên repo frontend; API đổi mật khẩu và đổi tên thư mục gốc project không ghi vào cache backend.