﻿﻿[English](/README.md) | [فارسی](/README.fa_IR.md)

# CFScanner

> **یک ابزار Cloudflare IPv4 scanner پرسرعت که از TCP و TLS/HTTP
> signatures استفاده می‌کند و به صورت اختیاری اعتبارسنجی واقعی از طریق
> Xray/V2Ray انجام می‌دهد.**

![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20mac-lightgrey)
![.NET](https://img.shields.io/badge/.NET-10.0-512bd4)
![License](https://img.shields.io/badge/license-MIT-green)

## 📖 معرفی کلی

**سی‌اف‌اسکنر** یک ابزار پیشرفته برای network scanning است که با هدف پیدا
کردن Cloudflare fronting IP های سالم طراحی شده است. \
این ابزار از یک Pipeline چندمرحله‌ای قدرتمند استفاده می‌کند تا مطمئن شود
IP های پیدا شده واقعاً کار می‌کنند و توان عبور دادن traffic واقعی را
دارند.

### ویژگی‌های کلیدی

-   **پایپ‌لاین چندمرحله‌ای:**
    1.  **مرحله TCP:** بررسی سریع اتصال روی پورت یا پورت‌های انتخاب‌شده (پیش‌فرض: 443)
    2.  **مرحله Signature:** تحلیل TLS handshake و HTTP response برای
        تشخیص Cloudflare fingerprint
    3.  **مرحله Real Proxy (اختیاری):** اعتبارسنجی IP با برقراری اتصال
        واقعی V2Ray/Xray
    4.  **تست آپلود و دانلود:** اندازه‌گیری **download و upload
        throughput واقعی** از طریق proxy تایید شده، با حداقل threshold
        قابل تنظیم توسط کاربر
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

>  اگر از prebuilt release ها استفاده می‌کنید، .NET به صورت bundle شده
> وجود دارد و نیازی به نصب جداگانه نیست.

------------------------------------------------------------------------

### 2. Xray-core (برای V2Ray Mode لازم است)

برای فعال شدن مرحله Real Proxy Validation با سوییچ `-vc` باید فایل
اجرایی **Xray-core** را داشته باشید (در حالت source build).

-   **دانلود:** آخرین release مناسب سیستم‌عامل خود را از repository رسمی
    بگیرید\
     https://github.com/XTLS/Xray-core/releases 👉
-   **راه‌اندازی:** فایل `xray` یا `xray.exe` را کنار فایل اجرایی
    `cfscanner` قرار دهید\
    یا مطمئن شوید در system `PATH` در دسترس است

>  در prebuilt release ها، Xray-core از قبل bundle شده است و نیاز به
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

>  در prebuilt release ها، دیتابیس ASN از قبل موجود است و نیازی به
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

باید یک فایل JSON معتبر بدهید.


> ⚠️ **نکات مهم**
>
> - عدد پورت تعریف‌شده داخل فایل کانفیگ JSON مربوط به V2Ray/Xray،
>   **مرجع تصمیم‌گیری اسکنر نیست**.
>
> - تمام مراحل **TCP**، **Signature** و **Real Xray verification**
>   صرفاً بر اساس پورت یا پورت‌هایی که به‌صورت صریح از طریق سوییچ
>   `-p` / `--port` به برنامه داده می‌شوند اجرا می‌شوند.
>
> - در صورتی که چندین پورت مشخص شود، اسکنر فرآیند بررسی را
>   **به‌صورت مستقل برای هر پورت** انجام می‌دهد.
>
> - هنگام اسکن چند پورتی با فعال بودن بررسی **V2Ray/Xray**،
>   سرور **باید برای هر پورت اسکن‌شده یک inbound مجزا** در اختیار داشته باشد.
>
> - تمام inboundهای مربوط به V2Ray/Xray **باید UUID یکسان** داشته باشند
>   و از **`path` و `SNI` کاملاً یکسان** استفاده کنند تا رفتار سیستم
>   قابل پیش‌بینی و قطعی باشد.
>
> - در صورت استفاده از **سرتیفیکیت TLS وایلدکارد**،
>   **بخش ابتدایی (left‑most label) مقدار SNI می‌تواند متغیر باشد**،
>   اما دامنه‌ی اصلی باید در تمام inboundها یکسان باقی بماند.
>
> - برای دستیابی به نتایج **قابل اعتماد و تکرارپذیر**،
>   همواره اطمینان حاصل کنید که پورت‌ها یا پورت‌های معرفی‌شده از طریق
>   `-p` / `--port` **دقیقاً با پورت‌های پیکربندی‌شده در سرور یکسان باشند**.
>
> -   فقط بخش `outbounds` لازم است. سایر بخش‌ها مانند `inbounds`،
>     `routing` یا `dns` لازم نیستند.

### نمونه `config.json` (vless-ws-tls)

``` json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR-WEBSITE-OR-CLOUDFLARE-IP",
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
          "serverName": "YOUR.DOMAIN.COM",
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "/YOUR-PATH",
          "headers": {
            "Host": "YOUR.DOMAIN.COM"
          }
        }
      }
    }
  ]
}
```

### نمونه `config.json` (vless-xhttp-tls)

``` json
{
   "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR-WEBSITE-OR-CLOUDFLARE-IP",
            "port": 8443,
            "users": [
              {
                "id": "YOUR-UUID-HERE",
                "security": "auto",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "YOUR.DOMAIN.COM",
          "alpn": [
            "h3",
            "h2",
            "http/1.1"
          ],
          "fingerprint": "chrome"
        },
        "xhttpSettings": {
          "path": "/PATH",
          "host": "YOUR.DOMAIN.COM",
          "mode": "auto"
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


  | سوییچ               | توضیح                                                                 |
|----------------------|-----------------------------------------------------------------------------|
  |`-a, --asn <LIST>`                                   | اسکن IP های مربوط به ASN یا Organization مشخص (مثلاً cloudflare)  |
  |`-f, --file <LIST>`                                  | خواندن IP یا CIDR از File متنی.  خطوطی که با `#` شروع می‌شوند  نادیده گرفته می‌شوند |
  |`-r, --range <LIST>`                                |  اسکن IP یا CIDR به صورت inline (مثلاً `1.1.1.1/24`) |


### ⛔ گزینه‌های Exclusion

  |سوییچ                |   توضیح     |
  |---------------------| ---------------------------------------- |
  |`-xa, --exclude-asn` |    exclude کردن ASN یا Organization خاص |
  |`-xf, --exclude-file`  |  exclude کردن IP یا CIDR های داخل File |
  |`-xr, --exclude-range`  | exclude کردن IP یا CIDR به صورت inline |

### ⚡ گزینه‌های Performance و Tuning

  |سوییچ                     |                              توضیح   |
  |---------------------------|----------------------------------- |
  | `--tcp-workers <N>`      |   تعداد TCP worker همزمان (بازه: 1-5000). |
  |`--signature-workers <N>` |  تعداد TLS/HTTP signature worker همزمان (بازه: 1-2000). |
  |`--v2ray-workers <N>`     |  تعداد V2Ray worker همزمان (بازه: 1-500). |
  |`--tcp-buffer <N>`        |  اندازه TCP channel buffer (بازه: 1-50000). |
  |`--v2ray-buffer <N>`      |  اندازه V2Ray channel buffer (بازه: 1-10000). اگر تنظیم نشود بر اساس workerها auto-scale می‌شود. |
  |`--speed-dl <N>`          | حداقل سرعت دانلود مورد نیاز برای هر IP (مثلاً 50kb، 1mb). با تنظیم این گزینه تست سرعت دانلود فعال می‌شود.
  |`--speed-ul <N>`          | حداقل سرعت آپلود مورد نیاز برای هر IP (مثلاً 50kb، 1mb). با تنظیم این گزینه تست سرعت آپلود فعال می‌شود.
  
 > ℹ️ مقدارهای بالایی برای `--speed-dl` و `--speed-ul` تنظیم نکنید. ترجیحاً فقط تست آپلود را با آستانه‌های پایین (مثلاً حدود 20kb) فعال کنید؛ مقادیر بالا در کنار تعداد زیاد worker می‌تواند پهنای باند کارت شبکه را اشباع کرده و باعث false negative شود.


### ⏱️ گزینه‌های Timeout (بر حسب میلی‌ثانیه)

  |سوییچ                     |                              توضیح   |
  |------------------------------|----------------------------------- |
  |`--tcp-timeout <N>`        |  Timeout برای اتصال TCP (بازه: 100-30000 ms).              |
  |`--tls-timeout <N>`        |  Timeout برای TLS handshake (بازه: 100-30000 ms).          |
  |`--http-timeout <N>`       |  Timeout برای درخواست HTTP (بازه: 100-30000 ms).           |
  |`--sign-timeout <N>`       | Timeout برای signature validation (بازه: 500-60000 ms).    |
  |`--xray-start-timeout <N>` |  Timeout برای بالا آمدن پروسه Xray (بازه: 1000-60000 ms).   |
  |`--xray-conn-timeout <N>`  |  Timeout برای اتصال Xray/V2Ray (بازه: 1000-60000 ms).      |
  |`--xray-kill-timeout <N>`  |  Timeout برای بستن پروسه Xray (بازه: 100-10000 ms).        |


### 📤 گزینه‌های خروجی

 |سوییچ                     |                              توضیح   |
  |------------------------------|----------------------------------- |
 |`--sort`             |   مرتب‌سازی فایل خروجی نهایی بر اساس latency (کم به زیاد).  |
 |` -nl, --no-latency` |    عدم ذخیره latency در فایل خروجی.                        |
 | `-s, --shuffle`     |    شافل کردن لیست IP ورودی قبل از اسکن.                    |


  ### 📤 پروفایل‌های پیش‍فرض

 |سوییچ                     |                              توضیح   |
  |------------------------------|----------------------------------- |
  |`--extreme`        |  پروفایل دیتاسنتری با بیشترین concurrency. TCP: 200، Sig: 80، V2Ray: 32.        |
  |`--fast`           |  پروفایل تهاجمی برای شبکه‌های پایدار. TCP: 150، Sig: 50، V2Ray: 16.              |
  |`--normal`         |  پروفایل متعادل (پیش‌فرض). استفاده از تنظیمات کارخانه.                           |
  |`--slow`           |  پروفایل پایدار/محافظه‌کارانه برای شبکه‌های ناپایدار. TCP: 50، Sig: 20، V2Ray: 4. |


### 🛠️ سایر گزینه‌ها

 |سوییچ                     |                              توضیح   |
  |------------------------------|----------------------------------- |
  |`-h, --help`                |  نمایش help کوتاه                      |
  |`--help full`               |  نمایش help کامل با توضیحات جزئی‌تر     |
  | `-y, --yes, --no-confirm`  | رد کردن پیام تأیید و شروع فوری اسکن.   |
  |`--random-sni`              | زمانی که در `serverName` از ساب‌دامنه استفاده شده باشد، برچسب اول SNI را به‌صورت تصادفی تغییر می‌دهد (نیازمند گواهی TLS از نوع wildcard است).     |
  | `-p, --port <LIST>`        |  پورت یا پورت‌هایی که اسکنر تست می‌کند  |

## ⚠️ سلب مسئولیت

این ابزار فقط برای مقاصد آموزشی و تحقیقاتی ساخته شده است.\
تولید‌کننده این برنامه هیچ مسئولیتی در قبال سوءاستفاده از این ابزار یا تبعات قانونی آن
ندارد.\
لطفاً هنگام network scanning قوانین محلی و مقررات مربوطه را رعایت کنید.
