[English](/README.md) | [فارسی](/README.fa_IR.md)

# CFScanner

> **یک ابزار Cloudflare IPv4 scanner پرسرعت که از TCP و TLS/HTTP
> signatures استفاده می‌کند و به صورت optional اعتبارسنجی واقعی از طریق
> Xray/V2Ray انجام می‌دهد.**

![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20mac-lightgrey)
![.NET](https://img.shields.io/badge/.NET-10.0-512bd4)
![License](https://img.shields.io/badge/license-MIT-green)

## 📖 معرفی کلی

**CFScanner** یک ابزار پیشرفته برای network scanning است که با هدف پیدا
کردن Cloudflare fronting IP های سالم طراحی شده است.\
این ابزار از یک Pipeline چندمرحله‌ای قدرتمند استفاده می‌کند تا مطمئن شود
IP های پیدا شده واقعاً کار می‌کنند و توان عبور دادن traffic واقعی را
دارند.

### ویژگی‌های کلیدی

-   **Pipeline چندمرحله‌ای:**
    1.  **مرحله TCP:** بررسی سریع connectivity روی port 443\
    2.  **مرحله Signature:** تحلیل TLS handshake و HTTP response برای
        تشخیص Cloudflare fingerprint\
    3.  **مرحله Real Proxy (اختیاری):** اعتبارسنجی IP با برقراری اتصال
        واقعی V2Ray/Xray
-   **ورودی‌های متنوع:** امکان اسکن بر اساس **ASN** یا **File** یا
    **CIDR** یا **Single IP**
-   **حذف‌های پیشرفته (Exclusions):** امکان exclude کردن ASN ها، IP range
    ها یا file ها برای جلوگیری از اسکن شبکه‌های ناخواسته
-   **پرفورمنس بالا:** معماری کاملاً asynchronous با worker های قابل
    تنظیم و back-pressure buffer
-   **تست Latency:** اندازه‌گیری latency در مراحل TCP و Handshake و
    مرتب‌سازی نتایج

------------------------------------------------------------------------

## ⚙️ پیش‌نیازها و وابستگی‌ها (فقط برای Source Build)

> ⚠️ **این بخش فقط مخصوص کسانی است که پروژه را از source build
> می‌کنند.**\
> اگر از prebuilt release ها استفاده می‌کنید، نیازی به نصب یا تنظیم موارد
> زیر ندارید.

برای build و اجرای **cfscanner** از source به موارد زیر نیاز دارید:

------------------------------------------------------------------------

### 1. .NET Runtime / SDK

این برنامه برای build و اجرا از source به **.NET 10.0 SDK** (یا Runtime)
نیاز دارد.

> ℹ️ اگر از prebuilt release ها استفاده می‌کنید، .NET به صورت bundle شده
> وجود دارد و نیازی به نصب جداگانه نیست.

------------------------------------------------------------------------

### 2. Xray-core (برای V2Ray Mode لازم است)

برای فعال شدن مرحله Real Proxy Validation با سوییچ `-vc` باید فایل
اجرایی **Xray-core** را داشته باشید (در حالت source build).

-   **دانلود:** آخرین release مناسب سیستم‌عامل خود را از repository رسمی
    بگیرید\
    👉 https://github.com/XTLS/Xray-core/releases
-   **راه‌اندازی:** فایل `xray` یا `xray.exe` را کنار فایل اجرایی
    `cfscanner` قرار دهید\
    یا مطمئن شوید در system `PATH` در دسترس است

> ℹ️ در prebuilt release ها، Xray-core از قبل bundle شده است و نیاز به
> تنظیم جداگانه ندارد.

------------------------------------------------------------------------

### 3. دیتابیس ASN (ip2asn-v4.tsv)

این ابزار برای resolve کردن ASN number و organization ها از دیتابیس
IP-to-ASN استفاده می‌کند (در حالت source build).

-   **دانلود:** فایل از این سایت در دسترس است: https://iptoasn.com/
-   **راه‌اندازی:** فایل `ip2asn-v4.tsv.gz` را دانلود کنید، extract کنید
    و با نام `ip2asn-v4.tsv` در پوشه برنامه قرار دهید
-   **نکته:** برنامه اگر فایل موجود نباشد سعی می‌کند آن را به صورت خودکار
    دانلود کند، اما قرار دادن دستی پایدارتر است

> ℹ️ در prebuilt release ها، دیتابیس ASN از قبل موجود است و نیازی به
> اقدامی نیست.

------------------------------------------------------------------------

## 🚀 نحوه استفاده

``` bash
cfscanner [OPTIONS]
```

### مثال‌های پایه

اسکن یک ASN مشخص (مثلاً cloudflare):

``` bash
cfscanner --asn cloudflare
```

اسکن لیست IP ها از یک File:

``` bash
cfscanner -f my_ips.txt
```

اسکن با concurrency بالا (بهینه برای شبکه‌های پایدار):

``` bash
cfscanner --asn cloudflare --tcp-workers 100 --signature-workers 40
```

------------------------------------------------------------------------

## 🔧 تنظیمات V2Ray / Xray (مهم)

برای فعال کردن مرحله Real Proxy Validation از سوییچ `--v2ray-config` یا
`-vc` استفاده کنید.\
در این حالت بررسی می‌شود که IP پیدا شده واقعاً می‌تواند traffic را proxy
کند یا نه.

### الزامات JSON Template

باید یک فایل JSON معتبر بدهید. نکته مهم این است که بخش `outbounds` را به
شکل زیر تغییر دهید:

1.  بخش `outbounds` را در JSON پیدا کنید\
2.  فیلد `address` مربوط به تنظیمات VLESS یا VMESS یا Trojan را پیدا
    کنید\
3.  به جای IP واقعی مقدار `IP.IP.IP.IP` را قرار دهید

> ⚠️ **نکات مهم**
>
> -   config شما حتماً باید روی port `443` تنظیم شده باشد چون scanner
>     فقط روی این port کار می‌کند\
> -   فقط بخش **`outbounds`** لازم است و بخش‌هایی مثل `inbounds` یا
>     `routing` نیاز نیستند

در زمان اسکن، برنامه به صورت داینامیک مقدار `IP.IP.IP.IP` را با IP های
کاندید جایگزین می‌کند.

### نمونه `config.json`

``` json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "IP.IP.IP.IP",
            "port": 443,
            "users": [
              {
                "id": "YOUR-UUID-HERE",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "your.domain.com",
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "/yourpath",
          "headers": {
            "Host": "your.domain.com"
          }
        }
      }
    }
  ]
}
```

### دستور اجرا

``` bash
cfscanner --asn cloudflare --v2ray-config config.json
```

------------------------------------------------------------------------

## 📋 آرگومان‌های Command-Line

### 📥 گزینه‌های ورودی


  | Option               | توضیح                                                                 |
|----------------------|-----------------------------------------------------------------------------|
  |`-a, --asn <LIST>`                                   | اسکن IP های مربوط به ASN یا Organization مشخص (مثلاً cloudflare)  |
  |`-f, --file <LIST>`                                  | خواندن IP یا CIDR از File متنی.  خطوطی که با `#` شروع می‌شوند  نادیده گرفته می‌شوند |
  |`-r, --range <LIST>`                                |  اسکن IP یا CIDR به صورت inline (مثلاً `1.1.1.1/24`) |


### ⛔ گزینه‌های Exclusion

  Option                   توضیح
  ------------------------ ----------------------------------------
  `-xa, --exclude-asn`     exclude کردن ASN یا Organization خاص
  `-xf, --exclude-file`    exclude کردن IP یا CIDR های داخل File
  `-xr, --exclude-range`   exclude کردن IP یا CIDR به صورت inline

### ⚡ گزینه‌های Performance و Tuning

  -----------------------------------------------------------------------
  Option                                                   توضیح
  -------------------------------------------------------- --------------
  `--tcp-workers <N>`                                      تعداد TCP
                                                           worker های
                                                           همزمان
                                                           (default: 10،
                                                           بازه: 1-1000)

  `--signature-workers <N>`                                تعداد TLS/HTTP
                                                           signature
                                                           worker ها
                                                           (default: 5،
                                                           بازه: 1-500)

  `--v2ray-workers <N>`                                    تعداد V2Ray
                                                           worker ها
                                                           (default: 2،
                                                           بازه: 1-100)

  `--tcp-buffer <N>`                                       اندازه TCP
                                                           channel buffer
                                                           (default: 100)

  `--v2ray-buffer <N>`                                     اندازه V2Ray
                                                           channel buffer
                                                           (default: 30)
  -----------------------------------------------------------------------

### ⏱️ گزینه‌های Timeout (بر حسب میلی‌ثانیه)

  -----------------------------------------------------------------------
  Option                                                   توضیح
  -------------------------------------------------------- --------------
  `--tcp-timeout <N>`                                      timeout برای
                                                           TCP connection
                                                           (default: 3000
                                                           ms، بازه:
                                                           100-30000)

  `--tls-timeout <N>`                                      timeout برای
                                                           TLS handshake
                                                           (default: 5000
                                                           ms، بازه:
                                                           100-30000)

  `--http-timeout <N>`                                     timeout برای
                                                           HTTP request
                                                           (default: 5000
                                                           ms، بازه:
                                                           100-30000)

  `--sign-timeout <N>`                                     timeout برای
                                                           signature
                                                           validation
                                                           (default: 5000
                                                           ms، بازه:
                                                           500-60000)

  `--xray-conn-timeout <N>`                                timeout برای
                                                           Xray/V2Ray
                                                           connection
                                                           (default:
                                                           10000 ms،
                                                           بازه:
                                                           1000-60000)
  -----------------------------------------------------------------------

### 📤 گزینه‌های خروجی

  -----------------------------------------------------------------------
  Option                                                توضیح
  ----------------------------------------------------- -----------------
  `--output <FILE>`                                     ذخیره نتیجه در یک
                                                        File با فرمت JSON

  `--sort`                                              مرتب‌سازی فایل
                                                        خروجی بر اساس
                                                        latency از کم به
                                                        زیاد

  `-nl, --no-latency`                                   عدم ذخیره latency
                                                        در فایل خروجی

  `-s, --shuffle`                                       shuffle کردن لیست
                                                        IP ورودی قبل از
                                                        اسکن
  -----------------------------------------------------------------------

### 🛠️ سایر گزینه‌ها

  Option          توضیح
  --------------- -----------------------------------
  `-h, --help`    نمایش help کوتاه
  `--help full`   نمایش help کامل با توضیحات جزئی‌تر

------------------------------------------------------------------------

## ⚠️ سلب مسئولیت

این ابزار فقط برای مقاصد آموزشی و تحقیقاتی ساخته شده است.\
تولید‌کننده این برنامه هیچ مسئولیتی در قبال سوءاستفاده از این ابزار یا تبعات قانونی آن
ندارد.\
لطفاً هنگام network scanning قوانین محلی و مقررات مربوطه را رعایت کنید.
