# CC-ATTACK-2025 (Browser-Like v5.0)

**CC-ATTACK-2025 v5.0 (Browser-Like)** adalah alat stress testing Layer 7 (HTTP/S) yang dikembangkan untuk **tujuan edukasi dan pengujian ketahanan server**. Versi ini adalah upgrade dari CC-ATTACK sebelumnya dengan simulasi browser yang lebih realistis, fingerprint TLS, adaptive payload, multi-threading, dan monitoring RPS real-time. Tool ini dibuat oleh anak bangsa Indonesia untuk memperbarui versi lama yang tidak lagi diupdate.

---

## 🚨 Peringatan

- Gunakan HANYA pada server milik sendiri atau dengan izin resmi.  
- Dilarang menyerang server tanpa izin.  
- Script memblokir domain `.gov`, `.mil`, `.edu`, dan `.int`.  
- Pengembang tidak bertanggung jawab atas penyalahgunaan.

---

## ✨ Fitur Utama

- **Ultra-realistic browser simulation:** header dan fingerprinting browser Chrome, Firefox, Edge.  
- **TLS spoofing** untuk koneksi lebih realistis.  
- **Multi-method support:** GET (cc), POST, HEAD.  
- **Adaptive POST data & timing acak** antar request untuk mensimulasikan pengguna asli.  
- **Multi-threaded dengan monitoring RPS real-time.**  
- **Proxy management dan checker built-in.**

---

## 🛠️ Instalasi

```
git clone https://github.com/username/CC-ATTACK-2025.git
cd CC-ATTACK-2025
pip install requests PySocks
```

## 🚀 Cara Penggunaan

Jalankan script:
```
python cc2025.py
```

Ikuti menu interaktif:

Mode: cc, post, head, check

Target URL: URL server yang diuji (contoh: https://test.server.com
)

Proxy Type: socks4, socks5, http, all

Threads: jumlah worker simultan

Requests/conn: jumlah request per koneksi

Boost Mode: y/n untuk TCP_NODELAY

Tips: gunakan mode check dulu untuk memastikan proxy berfungsi.

##  📊 Statistik Real-time

Terminal menampilkan:

TOTAL RPS: jumlah request sukses per detik

Working Proxies: jumlah proxy aktif

Top RPS Proxies: 10 proxy paling aktif

Tekan Ctrl+C untuk menghentikan.

## 💡 Tips Pengujian Aman

Mulai dengan thread & request kecil, tingkatkan bertahap

Gunakan mode check untuk verifikasi proxy

Catat latency dan RPS untuk evaluasi performa server

Hentikan segera jika server target tidak responsif

## 📃 Lisensi

Untuk tujuan edukasi dan pengujian keamanan/ketahanan.
Lihat LICENSE untuk detail hak & batasan.

Coded by L330n123
