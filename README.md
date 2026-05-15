# TOTP Vault — Static (GitHub Pages)

Phiên bản tĩnh của TOTP Vault, đã gỡ toàn bộ phụ thuộc WordPress/PHP. Toàn bộ logic sinh mã chạy **client-side** (RFC 6238, HMAC-SHA1) — không gửi secret đi đâu hết.

## Cấu trúc

```
totp-vault/
├── index.html
├── assets/
│   ├── css/main.css
│   └── js/totp-generator.js
├── .nojekyll
└── README.md
```

## Deploy lên GitHub Pages

1. Tạo repo mới trên GitHub (ví dụ `totp-vault`).
2. Push toàn bộ thư mục này lên branch `main`:

   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/<username>/totp-vault.git
   git push -u origin main
   ```

3. Vào repo → **Settings** → **Pages** → mục **Build and deployment**:
   - **Source:** Deploy from a branch
   - **Branch:** `main` / `/ (root)` → **Save**

4. Đợi 1–2 phút, truy cập: `https://<username>.github.io/totp-vault/`

> File `.nojekyll` đã có sẵn để GitHub không xử lý Jekyll (giữ nguyên tên file/thư mục bắt đầu bằng `_` nếu sau này có).

## Chạy local (không cần server)

Mở thẳng `index.html` bằng browser cũng được. Nếu muốn dùng server tĩnh:

```bash
python3 -m http.server 8080
# rồi mở http://localhost:8080
```

## Lưu ý bảo mật

- **HTTPS bắt buộc** để dùng `crypto.subtle` (Web Crypto API). GitHub Pages mặc định HTTPS nên không vấn đề.
- Trên HTTP/`file://` code vẫn chạy được nhờ fallback SHA-1 thuần JS, nhưng `navigator.clipboard` sẽ không hoạt động → user phải paste/copy thủ công.
- Secret không bao giờ rời browser. Không có analytics, không có request mạng nào ngoài tải font Google.

## Tuỳ biến nhanh

- Đổi số chữ số mã: sửa `data-digits="6"` (cho phép 6–8) trong `index.html`.
- Đổi chu kỳ làm mới: sửa `data-period="30"` (cho phép 15–120 giây).
- Đổi màu chủ đạo: sửa biến `--accent` và `--accent-2` ở đầu `assets/css/main.css`.
