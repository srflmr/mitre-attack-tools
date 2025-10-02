# Panduan Penggunaan: MITRE ATT&CK Enterprise Data Extractor

Halo Tim,

Dokumen ini menjelaskan cara menggunakan `mitre_tool.py`, sebuah skrip internal yang kita buat untuk membantu ekstraksi data dari framework **MITRE ATT&CK Enterprise**.

Tujuan utama tools ini adalah untuk mempercepat proses pengumpulan data teknik dan sub-teknik berdasarkan versi dan taktik tertentu, dan langsung menyajikannya dalam format CSV yang mudah diolah. Ini sangat berguna untuk analisis, pembuatan laporan, atau perencanaan simulasi serangan.

---

## 1. Konsep Dasar & Prasyarat

Sebelum mulai, pastikan kamu sudah paham beberapa hal dasar:

- **Virtual Environment**: Kita menggunakan `uv` untuk membuat virtual environment (`.venv`). Tujuannya adalah untuk mengisolasi dependensi proyek kita agar tidak bentrok dengan proyek Python lain di sistem kamu. Anggap saja ini seperti "ruangan bersih" khusus untuk proyek ini.
- **Dependensi**: Tools ini bergantung pada library `mitreattack-python`. Semua dependensi yang dibutuhkan akan terinstal di dalam virtual environment tersebut.
- **Prasyarat Sistem**:
  - `python3` sudah terinstal.
  - `uv` sudah terinstal (jika belum, `pip install uv`).

---

## 2. Setup Awal (Hanya dilakukan sekali)

Langkah ini hanya perlu kamu lakukan sekali saat pertama kali akan menggunakan tools ini di komputermu.

### a. Buat Virtual Environment
Buka terminal di direktori root proyek (`/home/amar/project/personal/mitre_attack_tools`), lalu jalankan:
```bash
uv venv
```
Perintah ini akan membuat direktori baru bernama `.venv`.

### b. Instal Dependensi
Selanjutnya, kita perlu menginstal library yang dibutuhkan ke dalam "ruangan bersih" yang baru kita buat.
```bash
uv pip install mitreattack-python
```

---

## 3. Cara Penggunaan Sehari-hari

Setiap kali kamu perlu menggunakan tools ini, ikuti langkah-langkah berikut.

### Langkah 1: Aktifkan Virtual Environment
Di sesi terminal yang baru, kamu **wajib** mengaktifkan virtual environment terlebih dahulu.

```bash
source .venv/bin/activate
```
**Tips**: Kamu akan tahu venv sudah aktif jika prompt terminalmu diawali dengan `(.venv)`. Jika kamu lupa melakukan ini, kamu akan mendapat error `ModuleNotFoundError`.

### Langkah 2: Jalankan Skrip
Setelah venv aktif, jalankan skrip utama kita.
```bash
python3 mitre_tool.py
```

### Langkah 3: Ikuti Proses Interaktif
Skrip akan memandumu melalui beberapa pilihan:

1.  **Pilih Versi ATT&CK (Enterprise)**: Menu pertama akan meminta Anda memilih versi matriks Enterprise ATT&CK yang ingin digunakan, mulai dari v14.0 hingga yang terbaru. Ketik angkanya dan tekan `Enter`.

2.  **Pilih Taktik**: Setelah data versi tersebut dimuat, Anda akan diminta memilih satu atau beberapa taktik.
    -   Untuk memilih **satu** taktik, cukup ketik nomornya (misal: `3` untuk Initial Access).
    -   Untuk memilih **beberapa** taktik, ketik nomor-nomornya dipisahkan dengan **koma** (misal: `1, 3, 5` untuk Reconnaissance, Initial Access, dan Execution).

3.  **Tentukan Nama File**: Skrip akan menyarankan nama file default yang deskriptif, yang kini juga menyertakan versi ATT&CK yang dipilih (contoh: `enterprise_attack_v16_1_reconnaissance.csv`).
    -   Tekan `Enter` untuk menerima nama default.
    -   Atau, ketik nama file kustom lalu tekan `Enter`.

### Langkah 4: Selesai!
Skrip akan membuat file CSV di direktori proyek dengan data yang kamu minta. Kamu akan melihat pesan sukses beserta path absolut ke file tersebut.

---

## 4. Contoh Output CSV

File CSV yang dihasilkan akan memiliki struktur seperti ini, siap untuk dianalisis lebih lanjut:

| Tactic          | ID      | Technique/Sub-technique      | Type          |
|-----------------|---------|------------------------------|---------------|
| Initial Access  | T1566   | Phishing                     | Technique     |
| Initial Access  | T1566.001 | Spearphishing Attachment     | Sub-technique |
| Initial Access  | T1566.002 | Spearphishing Link           | Sub-technique |
| ...             | ...     | ...                          | ...           |


---

## 5. Troubleshooting

- **`ModuleNotFoundError: No module named 'mitreattack'`**: Kamu lupa menjalankan `source .venv/bin/activate`. Hentikan skrip, aktifkan venv, lalu jalankan lagi.
- **`command not found: uv`**: `uv` belum terinstal secara global. Jalankan `pip install uv`.
- **Keluar dari Virtual Environment**: Jika sudah selesai bekerja, kamu bisa menonaktifkan venv dengan mengetik `deactivate`.

Semoga panduan ini jelas. Jangan ragu untuk bertanya jika ada yang kurang dipahami.

Selamat bekerja!