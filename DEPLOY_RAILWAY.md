# Deploy GitHub → Railway

## 1. Push ke GitHub

```bash
git init
git add .
git commit -m "Initial RentBook Apartemen"
git branch -M main
git remote add origin https://github.com/USERNAME/rentbook-apartemen.git
git push -u origin main
```

## 2. Railway

- Buat project baru di Railway.
- Pilih **Deploy from GitHub repo** dan pilih repository ini.
- Tambahkan **PostgreSQL** sebagai database service.
- Pada service aplikasi, tambahkan variables:

```text
NODE_ENV=production
DATABASE_URL=${{Postgres.DATABASE_URL}}
SESSION_SECRET=GANTI_DENGAN_RANDOM_STRING_PANJANG
ADMIN_EMAIL=admin@domain-anda.com
ADMIN_PASSWORD=PASSWORD_AWAL_MINIMAL_10_KARAKTER
```

- Deploy service aplikasi.
- Pada Settings → Networking, generate public domain.

Railway menyediakan `DATABASE_URL` dari service PostgreSQL dan Node app akan dijalankan melalui service aplikasi. Railway juga mendukung deploy langsung dari GitHub dan otomatis mendeteksi aplikasi Node.js. 

## 3. Login awal

Gunakan nilai `ADMIN_EMAIL` dan `ADMIN_PASSWORD` yang Anda masukkan di Railway.

Setelah login, buka **Pengaturan** dan ganti password.

## 4. Data

Semua data bisnis disimpan di PostgreSQL:

- apartemen
- unit
- penyewa
- kontrak sewa
- pembayaran
- pengeluaran
- audit log

Session login juga disimpan di PostgreSQL, bukan hanya di memory server.
