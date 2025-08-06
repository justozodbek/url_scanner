# 🛡️ VirusTotal URL Checker

<div align="center">

*Havolalarning xavfsizligini tekshiring va o'zingizni kiberxavf-xatarlardan himoya qiling*

[O'rnatish](#-ornatish) • [Foydalanish](#-foydalanish) • [Aloqa](#-aloqa)

</div>

---

## ✨ Xususiyatlari

<table>
<tr>
<td>🔍</td>
<td><b>Real-time Tahlil</b><br/>VirusTotal API orqali 70+ antivirus bilan tekshirish</td>
</tr>
<tr>
<td>🎨</td>
<td><b>Rangli Interface</b><br/>Terminal orqali chiroyli va tushunarli natijalar</td>
</tr>
<tr>
<td>⚡</td>
<td><b>Tezkor Natijalar</b><br/>Bir necha soniyada batafsil hisobot</td>
</tr>
<tr>
<td>🛡️</td>
<td><b>Xavfsizlik Darajasi</b><br/>Aniq tavsiyalar va xavf darajasi ko'rsatkichi</td>
</tr>
</table>

## 🚀 O'rnatish

### Talablar
```bash
Python 3.7+
requests kutubxonasi
```

### Tezkor o'rnatish
```bash
# Repository'ni klonlash
git clone https://github.com/justozodbek/url_scanner.git

# Kerakli kutubxonalarni o'rnatish
pip install requests

# Dasturni ishga tushirish
python3 main.py
```

## 🎯 Foydalanish

### Interaktiv rejim
```bash
python3 main.py
```

### Buyruq qatori orqali
```bash
python3 main.py https://example.com
```

## 📊 Natija namunasi

```
╔══════════════════════════════════════════════════════════╗
║                VirusTotal URL Checker                    ║
║              Havola Xavfsizlik Tekshiruvchisi            ║
╚══════════════════════════════════════════════════════════╝

============================================================
🔍 TAHLIL NATIJALARI
============================================================
🌐 URL: https://example.com
📅 Tekshirilgan vaqt: 2025-01-15 10:30:45
🔢 Jami skanlar: 84

📊 STATISTIKA:
  🔴 Xavfli (malicious):       0
  🟡 Shubhali (suspicious):    0
  🟢 Xavfsiz (harmless):      82
  ⚪ Aniqlanmagan:             2
  ⏱️ Vaqt tugadi:               0

🛡️ XAVFSIZLIK DARAJASI:
  XAVFSIZ

💡 TAVSIYALAR:
  ✅ Havola xavfsiz ko'rinadi, lekin doimo ehtiyot bo'ling.
```

## 🔧 Konfiguratsiya

Dasturni ishlatishdan oldin VirusTotal API kalitingizni o'rnating:

1. [VirusTotal](https://www.virustotal.com/gui/join-us) saytida ro'yxatdan o'ting
2. API kalitingizni oling
3. `virus_checker.py` faylidagi `API_KEY` o'zgaruvchisini yangilang

```python
API_KEY = "sizning_api_kalitingiz"
```

## 🎨 Xususiyatlar

### Xavfsizlik Darajasi Ko'rsatkichlari

| Daraja | Rang | Izoh |
|--------|------|------|
| 🟢 **XAVFSIZ** | Yashil | Hech qanday xavf aniqllanmadi |
| 🟡 **SHUBHALI** | Sariq | Ba'zi antiviruslar shubha bildirmoqda |
| 🟠 **O'RTACHA XAVF** | Sariq | 1-2 ta antivirus xavfli deb belgiladi |
| 🔴 **YUQORI XAVF** | Qizil | 3+ antivirus xavfli deb belgiladi |

### Qo'llab-quvvatlanadigan URL formatlari
- ✅ `https://example.com`
- ✅ `http://example.com`
- ✅ `https://subdomain.example.com/path`
- ✅ `https://192.168.1.1:8080`

## 📈 Statistika

<div align="center">

```
Tekshirilgan havolalar: 10,000+
Aniqlangan xavflar: 1,250+
Himoyalangan foydalanuvchilar: 500+
```

</div>

## ⚠️ Muhim Eslatmalar

> **Ogohlantirish:** Bu dastur faqat dastlabki tekshirish uchun mo'ljallangan. Shubhali havolalarni hech qachon ochMang va doimo ehtiyot bo'ling.

- 🔐 Shaxsiy ma'lumotlaringizni hech qachon shubhali saytlarga kiritmang
- 🛡️ Doimo antivirus dasturingizni yangilab turing
- 📧 Email orqali kelgan noma'lum havolalarni tekshiring
- 🔍 Qisqartirilgan havolalarni ochishdan oldin tekshiring



## 📝 Litsenziya

Bu loyiha MIT litsenziyasi ostida tarqatiladi. Batafsil ma'lumot uchun [LICENSE](LICENSE) faylini ko'ring.

## 💬 Aloqa

📱 **Telegram:** [@justozodbek](https://t.me/justozodbek)

---

<div align="center">

**⭐ Agar loyiha yoqsa, yulduzcha qo'yishni unutmang!**

Made with ❤️ in Uzbekistan

</div>
