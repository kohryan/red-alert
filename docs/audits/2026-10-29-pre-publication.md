# Audit pra-publikasi Red Alert — 29 Oktober 2026

**Pertanyaan:** apakah isi repo siap dipush tanpa eksperimen dan informasi confidential, dengan dokumentasi penggunaan yang dapat dicoba?

**Status:** review statis terarah dan verifikasi lokal; bukan sertifikasi keamanan atau audit seluruh kemungkinan perilaku runtime.

**Identitas:** working tree sebelum commit pertama. Pada awal audit tidak ada commit, file tracked, atau remote. Hasil ini mencakup source yang akan menjadi snapshot awal, bukan riwayat remote.

**Lingkungan:** macOS, Python 3.12.3, Git 2.40.1. Self-test memakai fixture sintetis dan server loopback. Tidak ada sampel investigasi yang dijalankan, pemindaian situs eksternal, atau koneksi model saat audit. Operasi GitHub untuk publikasi dilakukan terpisah dengan otorisasi pemilik repo.

## Cakupan dan threat model

| Komponen | Aset/batas kepercayaan | Entry point dan kontrol yang diperiksa |
| --- | --- | --- |
| Git dan folder lokal | Credential, izin investigasi, data target → GitHub | Inventaris file, `.gitignore`, baseline, daftar file staged, scan pola secret. |
| Console | Browser → workstation/data lokal | GET/POST di `webapp/server.py`; Host/Origin, JSON, panjang body, konfirmasi otorisasi. |
| HTTP client | Spesifikasi/respons target → jaringan, trust store, memori | Header credential, redirect host, batas byte, TLS, gzip di `pipeline/client.py` dan `pipeline/tls.py`. |
| Triage | Nama/path artefak → interpreter Python | Pemanggilan helper di `scripts/re/triage.sh`. |
| Workflow | Kontributor → runner CI | Permission read-only, checkout dengan SHA, kredensial tidak dipersist, suite tes yang dijalankan. |
| Fixture dan dokumentasi | Konteks operator → contoh yang dibagikan | Spec target asli dipindah ke `labs/`; contoh publik memakai localhost/data sintetis. |

Aktor relevan: halaman web asing yang mencoba mengakses console, target yang menyajikan respons berbahaya, operator yang tidak sengaja memasukkan output ke Git, dan kontribusi yang menyebabkan regresi. Source/spec lokal diasumsikan ditinjau operator.

Di luar cakupan: eksploitasi produksi, sandbox binary, uji browser secara menyeluruh, fuzzing parser, analisis setiap fungsi/22 ribu baris source secara manual, dependency/OS CVE di luar manifest yang dikenali, serta model lokal/remote. Kontrol yang dibaca statis tidak dinyatakan telah melindungi deployment produksi.

## Temuan dan remediasi

### F-01 — Path artefak dapat berubah menjadi source Python

**Severity:** Medium. **Epistemic:** observed (interpolasi source sebelum perbaikan); derived (risiko injeksi dari batas string). **Confidence:** High. **Category:** injection. **Status:** diperbaiki.

**What / evidence:** blok dump string sebelumnya memasukkan `SCRIPT_DIR`, path target, dan output langsung ke literal `python3 -c`. Petik pada path dapat memutus literal Python. Lokasi hasil perbaikan: `scripts/re/triage.sh:56`, memakai heredoc berquote dan `sys.argv`, sehingga path diperlakukan sebagai data.

**Coverage / precondition:** blok ekstraksi string pada triage; operator memilih path yang berisi karakter khusus, termasuk nama file yang berasal dari pihak lain.

**Impact / exploitability:** kegagalan triage pada nama file sah dan jalur menuju eksekusi kode jika path dibuat sebagai payload. Payload eksekusi tidak dijalankan; verifikasi menggunakan nama file dan folder bertanda petik.

**Remediation / regression test:** path dikirim sebagai argumen; `test_triage_script` memproses `sample's data.bin` dan `analyst's output` sampai output terbuat.

**Unknown:** eksploitasi kode arbitrer tidak didemonstrasikan; ini tidak menyatakan parser binary lain sudah diaudit lengkap.

### F-02 — Sertifikat target dapat memperluas trust dan memicu request di luar scope

**Severity:** Medium. **Epistemic:** observed untuk alur kode; inferred untuk dampak trust yang bergantung rantai sertifikat/OpenSSL. **Confidence:** High. **Category:** TLS/scope. **Status:** diperbaiki.

**What / evidence:** pada kegagalan issuer, implementasi sebelumnya membuka koneksi TLS tanpa verifikasi, membaca URL issuer dari sertifikat target, mengambilnya menggunakan `urlopen`, lalu memuat hasil ke trust store. Jalur ini tidak memakai HTTP client beraudit. Hasil perbaikan: `pipeline/client.py:394` dan `pipeline/tls.py:95`; helper AIA otomatis telah dihapus dan `_perform` hanya memakai context tepercaya operator/platform.

**Coverage / precondition:** fallback TLS HTTP client saat sertifikat tidak dapat diverifikasi; target mengontrol sertifikat/URL issuer dan operator mencoba mengoleksinya.

**Impact / exploitability:** request ke alamat di luar target dan kemungkinan perubahan keputusan trust. Tidak ada server bermusuhan atau bypass rantai TLS yang diuji secara live.

**Remediation / regression test:** gagal tertutup tanpa mengambil issuer dari target. `test_tls_failure_does_not_expand_trust` memverifikasi error diteruskan, satu upaya `_open`, dan tidak ada koneksi tambahan untuk discovery issuer.

**Unknown:** perilaku seluruh trust store/versi OpenSSL tidak diuji. Operator perlu memperbaiki chain target atau menyediakan CA bundle yang diverifikasi independen.

### F-03 — Request browser asing dapat memicu operasi console lokal

**Severity:** Medium. **Epistemic:** observed untuk jalur HTTP dan hasil tes loopback; inferred untuk skenario browser lintas origin. **Confidence:** High. **Category:** request origin/DoS. **Status:** diperbaiki pada batas yang diuji.

**What / evidence:** handler sebelumnya menerima JSON pada POST tanpa validasi Host, Origin atau Content-Type. `bool(payload["authorized"])` juga menerima string nonkosong. Lokasi perbaikan: `webapp/server.py:267` (Host/Origin), `webapp/server.py:559` (JSON/body), `webapp/server.py:601` dan `webapp/server.py:626` (boolean otorisasi harus `true`).

**Coverage / precondition:** GET/POST console; console sedang berjalan saat operator mengunjungi konten asing. Sebelumnya panjang body negatif/malformed juga dapat mencapai read/error tanpa validasi.

**Impact / exploitability:** jalur menuju pemicu collection/recon/agent dari request yang bukan tindakan operator; Host asing juga membuka risiko rebinding. Eksploitasi end-to-end menggunakan browser tidak dilakukan.

**Remediation / regression test:** batasi authority ke server, Origin ke origin yang sama, POST ke JSON, validasi Content-Length dan tolak transfer encoding yang tidak didukung. `test_server_rejects_foreign_requests` menguji penolakan serta memastikan request yang ditolak tidak mencapai action sintetis; direct local JSON dan origin yang sesuai tetap diterima.

**Unknown:** belum ada login/session; proses lokal tepercaya tetap dapat memanggil API. Console hanya untuk loopback, bukan layanan publik, reverse proxy, atau shared network. Pembatasan Host tidak menggantikan autentikasi.

### F-04 — Batas byte diperiksa setelah gzip terdekompresi seluruhnya

**Severity:** Medium. **Epistemic:** observed untuk kode dan tes sintetis; inferred untuk kehabisan memori skala besar. **Confidence:** High. **Category:** resource exhaustion. **Status:** diperbaiki pada jalur gzip HTTP client.

**What / evidence:** `_open` sebelumnya memakai `gzip.decompress(payload)` sebelum mengecek ukuran hasil; input terkompresi kecil dapat mengalokasikan hasil besar. `pipeline/client.py:437` kini menggunakan `gzip.GzipFile.read(max_bytes + 1)` dan menolak hasil yang melewati ceiling.

**Coverage / precondition:** respons HTTP dengan `Content-Encoding: gzip` dari target yang dikoleksi.

**Impact / exploitability:** potensi konsumsi memori berlebih pada workstation. Payload sangat besar tidak dijalankan.

**Remediation / regression test:** batasi pembacaan hasil dekompresi. `test_gzip_response_respects_decompressed_limit` menerima respons 100 byte dan menolak 8.192 byte dengan ceiling 1.024 byte.

**Unknown:** bukan audit lengkap seluruh kompresi/archive/parser; batas CPU dan memori OS tetap diperlukan untuk target bermusuhan.

### F-05 — Target matrix mengasumsikan izin situs publik

**Severity:** Low. **Epistemic:** observed. **Confidence:** High. **Category:** authorization workflow. **Status:** diperbaiki pada CLI/Make.

**What / evidence:** skrip target matrix sebelumnya dapat berjalan tanpa konfirmasi operator dan meneruskan `authorized=True`. `scripts/re/selftest_targets.py:86` kini mewajibkan `--authorized` dan pemilihan `--only` yang dikenal; Make mewajibkan `AUTHORIZED=1` dan `ONLY`.

**Coverage / precondition:** menjalankan skrip matrix secara langsung; daftar situs publik bukan bukti izin.

**Impact / exploitability:** request ke banyak target di luar scope operator tanpa tindakan konfirmasi. Matrix tidak dijalankan selama audit.

**Remediation / regression test:** explicit opt-in dan seleksi target; `test_target_matrix_requires_explicit_permission` menguji empat kombinasi tidak lengkap dan memverifikasi exit 2 sebelum network.

**Unknown:** flag tidak memverifikasi dokumen izin; tanggung jawab pembuktian izin tetap pada operator.

### F-06 — Eksperimen dapat terpublikasi dan CI melewatkan tes webapp

**Severity:** Low. **Epistemic:** observed. **Confidence:** High. **Category:** repository hygiene/CI. **Status:** diperbaiki.

**What / evidence:** ignore awal hanya melindungi subfolder `labs/*/work` dan `samples`; konfigurasi/hasil lain masih bisa masuk staging. CI hanya menjalankan suite tooling. Kontrol akhir: `.gitignore:27` mengecualikan seluruh `labs/`, `.env*`, output, credential/key, dump dan cache; `.github/workflows/security.yml:36` menjalankan `make test` termasuk webapp. CODEOWNERS memakai pemilik repo yang nyata. Pin checkout v4.2.2 diperbaiki menjadi `11bd71901bbe5b1630ceea73d27597364c9af683`, diverifikasi melalui GitHub API resmi `repos/actions/checkout/git/ref/tags/v4.2.2`.

**Coverage / precondition:** publikasi commit awal dan kontribusi berikutnya; operator melakukan staging menyeluruh atau regresi webapp terjadi.

**Impact / exploitability:** risiko data target/izin terpublikasi dan regresi tidak dideteksi CI. Tidak ada riwayat commit sebelumnya yang harus dibersihkan saat audit dimulai.

**Remediation / regression test:** gunakan contoh sintetis di `examples/`, simpan spec target asli di `labs/`, cek daftar staged/aturan ignore, dan jalankan kedua suite. Dokumen ini tidak menyertakan hasil investigasi target asli.

**Unknown:** pola ignore dan scanner tidak dapat mengenali setiap jenis data confidential; staging paksa dapat melewati ignore.

## Verifikasi dan hasil negatif terbatas

- **observed:** `make test` lulus pada mesin audit: 98 pemeriksaan tooling dan 358 pemeriksaan webapp sebelum penambahan regresi gzip. Regresi terarah berikutnya: 16 lulus, 0 gagal. Suite tooling terakhir setelah penambahan gzip: **100 lulus, 0 gagal**.
- **observed:** `make baseline` awal memindai 2.423 file teks dan menghasilkan nol pattern hit. Cakupan scanner mengecualikan binary, format tertentu, direktori tooling tertentu, dan baris panjang; ini bukan bukti universal ketiadaan secret atau data pribadi.
- **observed:** sebelum staging awal, baseline belum dapat memeriksa hygiene file tracked karena Git belum berisi file. Baseline final setelah staging: **123 file tracked, 2.426 file dipindai, 0 temuan hygiene/pola secret**.
- **observed:** inventaris source publishable pada saat review tidak memiliki baris lebih dari 4.000 karakter yang dilewati scanner. Contoh credential dalam HAR memakai placeholder `REDACTED` dan tidak direplay.
- **observed:** core Python memakai standard library; hanya `certifi` di-probe secara opsional. Tidak ada manifest dependency aplikasi yang memicu audit CVE di baseline; nol check dependency tidak berarti bebas kerentanan.
- **observed:** 20/20 probe path environment, labs, output, credential, capture dan dump diabaikan Git. Snapshot awal berisi 123 file; tidak ada file dari `labs/` atau output/credential yang diblokir oleh publication gate.
- **observed:** smoke test contoh README berhasil pada fixture loopback: 20/137 item (parsial), dataset JSON, run record, audit dan PDF valid.
- **unknown:** runtime model, perilaku seluruh engine analisis eksternal, dan pemindaian target sungguhan tidak diuji.

Perintah reproduksi lokal:

```bash
make test
make baseline
python3 scripts/re/check_links.py
python3 -m webapp validate examples/collection-spec.example.json
python3 -m webapp plan examples/collection-spec.example.json
python3 -m pipeline run examples/pipeline-spec.example.json --dry-run
git diff --cached --check
git ls-files
```

## Prioritas lanjutan

1. **Do now (selesai):** keluarkan eksperimen/izin/output dari commit, tutup interpolasi path, TLS fallback, origin console, gzip, dan opt-in target matrix; dokumentasikan penggunaan dan jalankan tes.
2. **Do next:** bila console ingin diakses banyak pengguna, desain autentikasi, otorisasi job/dataset, batas concurrency/timeout, dan deployment tersendiri terlebih dahulu. Pemakaian console jaringan tidak tercakup audit ini.
3. **Backlog:** fuzz parser/arsip, uji lintas versi Python/OpenSSL, audit redirect/locality endpoint model, dan tinjau ulang dependency/CVE ketika dependency baru ditambahkan. Scanner dapat melewati format, baris panjang, placeholder, atau suppression; review manual staged tetap wajib.
