# 🛡️ MasterHttpRelayVPN (Windows)

> 🚀 ابزاری قدرتمند برای عبور از فیلترینگ و سیستم‌های **DPI (Deep Packet Inspection)**  
> با استفاده از تکنیک **Domain Fronting** — بدون نیاز به سرور یا تنظیمات پیچیده

✨ فقط با یک اکانت گوگل، به اینترنت آزاد متصل شوید

---

> [!WARNING]
> **توجه:** توصیه می‌شود برای راه‌اندازی و Deploy کردن Google Apps Script از یک اکانت Google جدا از اکانت اصلی استفاده کنید.  
> ممکن است برخی اکانت‌ها یا Deployment ID ها توسط Google محدود یا غیرفعال شوند.  
> اگر Deployment کار نکرد، با یک اکانت دیگر دوباره امتحان کنید.

---

## 📥 دانلود برنامه (نسخه آماده)

برای دانلود نسخه آماده (بدون نیاز به کامپایل):

👈 **[دانلود از بخش Releases](https://github.com/AriPath/MasterVPN/releases/tag/MasterVPN)**  
👈 **[دانلود با نت ملی](http://1xd.ir/downloads/index.html)**

📌 فایل اجرایی را دانلود و مستقیم اجرا کنید.

---

## 🧠 سورس پروژه

این مخزن شامل **کد کامل پروژه** است:

- 🔧 بررسی و ویرایش پروژه
- 🛠 ساخت نسخه اختصاصی
- 🚀 اعمال تغییرات دلخواه

---

## ✨ قابلیت‌ها

- ⚙️ برنامه مستقل (`.exe`) بدون نیاز به Python  
- 🔐 تزریق خودکار Certificate  
- 🌐 استفاده از ترافیک Google برای دور زدن محدودیت‌ها  
- 🔄 تنظیم خودکار Proxy ویندوز  

---

## 🚀 راه‌اندازی سریع

### 👤 مراحل اجرا

🔧 وارد لینک دانلود شوید  
🔧 فایل را دریافت کنید  
🔧 برنامه `MasterVPN.exe` را اجرا کنید  
🔧 اطلاعات زیر را وارد کنید:
   - Google Script ID  
   - Auth Key  
🔧 روی کانکت کلیک کنید  

🎉 اتصال برقرار شد

---

## 📱 اتصال در تلگرام

1. Settings  
2. Advanced → Connection Type → Use custom proxy  
3. Add Proxy  
4. وارد کنید:

```text
Hostname: 127.0.0.1
Port: 8085
Type: HTTP
````

---
## 🛠 راه‌اندازی Google Apps Script

### مراحل

1. ورود به Google Apps Script  
https://script.google.com/

2. ایجاد یک پروژه جدید

3. حذف تمام کدهای پیش‌فرض

4. ایجاد یا جایگذاری فایل `Code.gs`

5. قرار دادن کد زیر:
```javascript
const AUTH_KEY = "your_password_here";
```
🔧 تنظیم:

* Type: Web app
* Execute as: Me
* Access: Anyone

🔧 دریافت Deployment ID

---

## 🔗 اتصال

* Google Script ID = Deployment ID
* Auth Key = رمز شما

---

## 📄 License

MIT 
