# backend

Quy trình chuẩn khi triển khai (Deployment):
Đẩy mã nguồn lên server: Gồm toàn bộ source code của dự án, bắt buộc phải có package.json và package-lock.json. (không tải folder node_modules)
Cài đặt trên server: Kết nối vào terminal của server và chạy lệnh:
Nếu dùng package-lock.json: Chạy lệnh npm ci (lệnh này giúp cài đặt chính xác 100% các phiên bản gói như lúc bạn code ở máy local, rất an toàn cho môi trường production).
Hoặc chạy lệnh: npm install (hoặc npm install --production nếu bạn muốn bỏ qua các thư viện chỉ dùng cho việc dev/test).