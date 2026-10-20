<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

<p align="center">اعتبار IP · عیب‌یابی پروکسی · انتخاب دسته‌ای گره‌ها — ابزار تک‌فایلی پایتون</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v4.12.7-1f883d" alt="release">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab" alt="python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-8250df" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-d7781e" alt="license">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh.md">简体中文</a> · <a href="README.zh-TW.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ru.md">Русский</a>
</p>

---

## نمایش برنامه

صفحه شروع — لوگوی گرادیانی، پنل اطلاعات زنده و منوی دوستونه:

![منوی اصلی](docs/showcase-menu.png)

نمونه گزارش:

![گزارش](docs/showcase-report.png)

تست دسته‌ای سرعت گره‌ها:

![تست دسته‌ای](docs/showcase-batch.png)

## ویژگی‌ها

- **اعتبار IP**: تجمیع همزمان چندین منبع داده (ipwho.is، ipinfo، proxycheck، Scamalytics، DB-IP، GreyNoise و بیشتر)، با ذکر منبع برای هر مقدار و قوانین امتیازدهی کاملاً عمومی (گزینه `--explain`)
- **بازکردن استریمینگ**: ۱۸ بررسی در ویدیو / هوش مصنوعی / اجتماعی، با تمایز بازکردن بومی و DNS
- **فهرست‌های سیاه**: ۲۹ فهرست DNSBL به‌همراه تطبیق اطلاعات تهدید (Feodo، Emerging Threats، گره‌های خروجی Tor)
- **عیب‌یابی پروکسی**: هندشیک SOCKS5 و تأخیر، IP خروجی از طریق پروکسی با بررسی مجدد اعتبار، بررسی نشت DNS، آمار تأخیر / جیتر / اتلاف TCP
- **انتخاب دسته‌ای گره**: چند گره (`host:port` یا `socks5://…`) را بچسبانید؛ تست سرعت همزمان با رتبه‌بندی و علامت‌گذاری خودکار بهترین گره
- **تست سرعت**: گره‌های دانلود منطقه‌ای (جدول گره به سبک bench.sh، حداکثر چنداتصالی)؛ عیب‌یابی پروکسی و انتخاب دسته‌ای توان واقعی از طریق پروکسی را اندازه می‌گیرند
- **خودآزمایی**: بررسی کامل IP خروجی + آزمون‌های DNS (ساده / DoH / DoT) + آزمون ارسال پورت ۲۵ + اطلاعات سیستم و بنچمارک دیسک
- **بدون وابستگی**: کتابخانه استاندارد خالص پایتون در یک فایل، نسخه عمومی بدون نیاز به کلید API؛ رابط کاربری ۶ زبانه؛ خروجی `--json` برای اسکریپت و اتوماسیون

## شروع سریع

```bash
# دانلود تک‌فایل
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py

# منوی تعاملی (پیشنهادی)
python3 acheck.py

# خط فرمان
python3 acheck.py 8.8.8.8     # استعلام هر IP عمومی
python3 acheck.py --active    # خودآزمایی
```

بسته‌های macOS / Windows / Linux در صفحه [Releases](https://github.com/alariclin/A-Check/releases) هستند (`A-Check-v4.12.7-mac.zip` / `A-Check-v4.12.7-windows.zip` / `A-Check-v4.12.7-linux.zip`) — از حالت فشرده خارج کنید و `run.command` / `run.bat` / `run.sh` را اجرا کنید.

## روش استفاده

| حالت | دستور | توضیح |
| --- | --- | --- |
| منوی تعاملی | `python3 acheck.py` | منوی دوستونه با ۱۱ ابزار |
| استعلام هر IP | `python3 acheck.py 1.2.3.4` | اعتبار چندمنبعی + فهرست‌های سیاه + گزارش کامل |
| خودآزمایی | `python3 acheck.py --active` | بررسی خروجی + استریمینگ + اطلاعات سیستم |
| عیب‌یابی پروکسی | `python3 acheck.py --proxy HOST:PORT` | هندشیک / خروجی / نشت DNS / تأخیر (`--proxy-user` و `--proxy-pass` برای احراز هویت) |
| انتخاب دسته‌ای | `python3 acheck.py --batch گره,گره…` | تست سرعت همزمان و رتبه‌بندی |
| تست سرعت | `python3 acheck.py --speed` | تست گره‌های دانلود منطقه‌ای |
| خروجی JSON | افزودن `--json` به هر حالت | برای اسکریپت / اعلان / یکپارچه‌سازی |
| قوانین امتیازدهی | `python3 acheck.py --explain` | متن کامل قوانین امتیازدهی سه‌بعدی |
| زبان | `--zh` / `--zh-tw` / `--en` / `--ja` / `--ru` / `--fa` | یا تغییر از داخل منو |

## نکات

- **حریم خصوصی**: همه بررسی‌ها به‌صورت محلی انجام می‌شود و هیچ داده‌ای از کاربر به جایی ارسال نمی‌شود؛ نسخه عمومی هیچ کلید API ندارد
- **محدودیت نرخ**: منابع داده سهمیه رایگان دارند؛ استعلام زیاد در زمان کوتاه ممکن است محدود شود و منابع ازدست‌رفته در گزارش علامت می‌خورند
- **نتایج**: امتیازها از تجمیع اطلاعات عمومی به دست می‌آیند و منابع ممکن است اختلاف داشته باشند؛ منبع هر مقدار در گزارش ذکر شده است؛ صرفاً برای مرجع
- **سازگاری**: نیازمند Python 3.8+؛ روی macOS / Windows / Linux / VPS اجرا می‌شود

---

سوابق تغییرات در [Releases](https://github.com/alariclin/A-Check/releases) · مجوز MIT · منابع داده در گزارش برای هر مورد ذکر شده‌اند
