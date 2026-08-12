# Web Exploitation Fundamentals: SSTI, Access Control ve Stateful Uygulama Analizi

> Bir "Easy" seviye Flask/Jinja2 CTF çözümünden çıkarılan, gerçek dünya web güvenlik açıklarının temel mantığını derinlemesine ele alan teknik referans.

---

## İçindekiler

1. [Stateful Web Application Mantığı](#1-stateful-web-application-mantığı)
2. [Jinja2 / Template Engine İç Yapısı ve SSTI](#2-jinja2--template-engine-iç-yapısı-ve-ssti)
3. [Statik Kod Denetimi ve Dangerous Sink Analizi](#3-statik-kod-denetimi-ve-dangerous-sink-analizi)
4. [Broken Access Control ve Yetki Modelleri](#4-broken-access-control-ve-yetki-modelleri)
5. [HTTP Metodları ve İstek Manipülasyonu](#5-http-metodları-ve-i̇stek-manipülasyonu)
6. [Dosya Metadata Enjeksiyonu](#6-dosya-metadata-enjeksiyonu)

---

## 1. Stateful Web Application Mantığı

### 1.1 Temel Kavram

HTTP protokolünün kendisi **stateless**'tir — her istek, sunucu için bağımsız bir olaydır, önceki istekle hiçbir doğal bağı yoktur. Ancak web *uygulamaları* stateless değildir; state'i (durumu) sunucu tarafında **veritabanı satırları, session objeleri, dosya sistemi kayıtları** gibi yapılarla simüle ederler.

Bunun pratik sonucu şudur: bir endpoint'in davranışı, sadece kendi kodunun mantığına değil, **daha önce çalışmış başka bir endpoint'in bıraktığı iz'e (side effect)** bağlı olabilir. Bir route'u izole bir fonksiyon gibi değil, bir **state machine'in bir geçişi (transition)** gibi düşünmek gerekir.

### 1.2 Gerçek Dünya Örneği: Parola Sıfırlama Akışı

Bu, neredeyse her üretim sisteminde (Google, GitHub, banka uygulamaları) aynı iskelete sahiptir:

```
State 0 (Başlangıç)
   │
   │  POST /forgot-password  { email }
   ▼
State 1: Reset token DB'ye yazılır
   (tablo: password_reset_tokens, kolonlar: email, token, expires_at)
   │
   │  GET /reset-password/<token>
   ▼
State 2: Token DB'de var mı, expire olmuş mu kontrol edilir
   │
   │  POST /reset-password/<token>  { new_password }
   ▼
State 3: Parola güncellenir, token invalidate edilir
```

Bu challenge'daki `/changepasswd/<hash>` route'u tam olarak **State 2**'ydi ama **State 1** hiç tetiklenmemişti:

```python
@views.route("/changepasswd/<link>")
def changepasswd(link):
    query = Validlinks.query.filter_by(validlink=link).first()
    if query:
        return render_template("resetpassword.html", email=query.email)
    # query None ise buraya hiçbir return yok -> Flask None'ı response'a çeviremez -> 500
```

`Validlinks` tablosunda bu `link` değerine karşılık gelen bir satır yoksa `query` `None` döner, `if` bloğu çalışmaz ve fonksiyon **implicit olarak `None` döndürür**. Flask, `None`'ı geçerli bir HTTP response'a çeviremediği için `TypeError` fırlatır ve bu 500 Internal Server Error olarak dışarı yansır.

> **Kritik çıkarım:** 500 hatası genelde "bu endpoint yanlış/var olmayan bir şey" demek değildir. Çoğunlukla "bu endpoint doğru ama beklediği bir *ön koşul (precondition)* — DB satırı, session değişkeni, dosya — eksik" demektir. 404 ile 500'ü aynı kategoride okumak, saldırı yüzeyinin yarısını kaçırmaya sebep olur.

### 1.3 Neden Race Condition'larla Bağlantılı

Aynı state mantığı, **race condition** zafiyetlerinin de temelidir. Örneğin bir "kupon kullan" endpoint'i şu sırayla çalışıyorsa:

```python
coupon = Coupon.query.get(coupon_id)
if coupon.used == False:
    apply_discount()
    coupon.used = True
    db.session.commit()
```

İki eşzamanlı istek, `coupon.used == False` kontrolünü ikisi de commit'ten önce görebilir — ikisi de indirimi uygular. Bu, "check" (state okuma) ile "act" (state güncelleme) arasındaki **atomicity eksikliğinden** kaynaklanır — tam olarak bugünkü zafiyetle aynı kök neden: state'in ne zaman, hangi sırayla yazıldığını/okunduğunu anlamamak.

### 1.4 Pratik Egzersiz

Herhangi bir açık kaynak Flask/Django uygulaması al (örn. Flask'ın resmi tutorial projesi) ve her route için şu tabloyu çıkar:

| Route | Method | Okuduğu State | Yazdığı State | Bağımlı Olduğu Önceki State |
|---|---|---|---|---|
| `/forgot-password` | POST | `User` (email var mı) | `Validlinks` (yeni satır) | Yok |
| `/changepasswd/<hash>` | GET/POST | `Validlinks` (hash eşleşmesi) | `User.password` | `/forgot-password`'ün yazdığı satır |

Bu tabloyu çıkarmadan bir uygulamaya saldırmak, elektrik şemasını okumadan bir devreyi tamir etmeye çalışmak gibidir.

---

## 2. Jinja2 / Template Engine İç Yapısı ve SSTI

### 2.1 `render_template` ile `render_template_string` Farkı

```python
# GÜVENLİ (genelde)
return render_template("profile.html", bio=user.bio)

# TEHLİKELİ
return render_template_string("Merhaba " + user.bio)
```

İlk örnekte `bio`, **template'in bir değişkeni** olarak geçer — Jinja2 onu düz metin (context değeri) olarak basar, template sözdizimi olarak yorumlamaz. İkinci örnekte `bio`, **template kaynak kodunun kendisine** enjekte edilir. Jinja2 motoru, string'i parse ederken içindeki `{{ ... }}` bloklarını gerçek Jinja ifadesi olarak derler ve çalıştırır. Bu, klasik "kod" ile "veri" ayrımının (code/data separation) ihlalidir — SQL Injection'daki string concatenation ile aynı kök nedene sahiptir, sadece yorumlayıcı SQL değil Jinja2'dir.

### 2.2 Jinja2'nin Sandbox'ı Neden Yeterli Değil

Jinja2, "sandboxed" bir template dili olarak pazarlanır ama bu sandbox, **Python'un nesne modelinin kendisini** kapatmaz. Her Python nesnesi, `__class__` attribute'u üzerinden kendi sınıfına, oradan da `__mro__` (Method Resolution Order) ve `__subclasses__()` üzerinden **çalışan process'teki tüm yüklü sınıflara** erişim sağlar. Bu, Python'un introspection (kendi kendini inceleme) yeteneğinin doğal bir sonucudur ve normalde debugging için faydalıdır — ama kullanıcı girdisi template koduna karışınca bir silaha dönüşür.

**Zincirin mantığı adım adım:**

```python
"".__class__                        # <class 'str'>
"".__class__.__mro__                # (<class 'str'>, <class 'object'>)
"".__class__.__mro__[1]             # <class 'object'>
"".__class__.__mro__[1].__subclasses__()
# -> object'ten türeyen TÜM sınıfların listesi (yüzlerce)
# Bu listede subprocess.Popen, os._wrap_close gibi sınıflar da vardır
```

Bu listede `subprocess.Popen`'ı bulup, onun `__init__.__globals__`'ına erişerek, o modülün import ettiği `os` referansına ulaşılır. Bu bir "trick" değil, **CPython'un nesne modelinin garanti ettiği bir davranıştır** — her fonksiyon nesnesi, tanımlandığı modülün global namespace'ine `__globals__` üzerinden erişim sağlar.

### 2.3 Bu Challenge'da Kullanılan Yol: Jinja2 Global Fonksiyonları

Klasik `__class__.__mro__.__subclasses__()` zincirine gerek kalmadan, Jinja2'nin **kendi default global namespace'i** zaten `__globals__`'a giden bir kısayol sunar:

```python
# Jinja2 Environment'ın varsayılan global'leri arasında:
lipsum    # Lorem ipsum üreten yardımcı fonksiyon
cycler    # Değerler arasında döngü yapan yardımcı sınıf
joiner    # String birleştirme yardımcısı
namespace # Değişken namespace'i oluşturucu
```

`lipsum`, bir Python fonksiyon nesnesidir; her fonksiyon nesnesi gibi `__globals__` attribute'una sahiptir ve bu, `lipsum` fonksiyonunun tanımlandığı `jinja2.utils` modülünün global namespace'idir — bu namespace de `os` modülünü import eder:

```jinja2
{{ lipsum.__globals__.os.popen('id').read() }}
```

```
lipsum  →  .__globals__  →  {'os': <module 'os'>, ...}  →  .os  →  .popen()  →  .read()
   ↑              ↑                    ↑                      ↑         ↑
fonksiyon    modülün global      dict içinden          os modülü    RCE
nesnesi      namespace'i          os'u çek
```

Bu, `__class__.__mro__.__subclasses__()` zincirinin **daha kısa, daha az karakterli bir alternatifidir** — bu challenge'daki gibi karakter/string bazlı blacklist'lerde işe yarar çünkü `class`, `mro`, `subclasses` gibi kelimeleri hiç içermez.

> **Not:** Bu challenge'da EXIF alanına filtre uygulanmadığı için bu inceliğe gerek kalmadı, ama filtreli senaryolarda (örn. `bio` alanı) bu tür kısa yollar tam olarak bu yüzden değerlidir.

### 2.4 Neden Blacklist Yaklaşımı Kırılgandır

`checkInput` fonksiyonu, belirli **string'leri** (`os`, `popen`, `__`, `[`, `]`) yasaklıyordu. Bu, **whitelist (izin verilenler listesi)** yerine **blacklist (yasaklananlar listesi)** yaklaşımıdır ve teorik olarak kırılamaz değildir — çünkü:

- Python'un attribute erişim sözdizimi (`.`) tek başına yasaklı değilse, `getattr()` benzeri dolaylı yollar denenebilir.
- Unicode normalizasyon farklılıkları, string encoding trickleri ile filtre bypass edilebilir.
- Jinja2 filtrelerinin (`|attr`, `|map`, `|select`) kombinasyonları düz string arama ile yakalanamayan yollar açar.

Bu yüzden endüstri standardı, kullanıcı girdisini **hiçbir zaman** `render_template_string`'e vermemek, gerekiyorsa **sandboxed environment** (`jinja2.sandbox.SandboxedEnvironment`) kullanmak ve mümkünse şablon içeriğini tamamen sabit tutup sadece değişken değerlerini enjekte etmektir.

### 2.5 Kaynak

- [PortSwigger — Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

---

## 3. Statik Kod Denetimi ve Dangerous Sink Analizi

### 3.1 Source / Sink Modeli

Güvenlik analizinde veri akışı iki uçla tanımlanır:

- **Source (kaynak):** Kullanıcının kontrol edebildiği herhangi bir giriş noktası — form alanı, URL parametresi, HTTP header, dosya metadata'sı, cookie.
- **Sink (yutak):** Verinin işlendiği, potansiyel olarak tehlikeli bir fonksiyona ulaştığı nokta — `eval()`, `os.system()`, `render_template_string()`, ham SQL sorgusu.

Bir zafiyet, **filtrelenmemiş bir taint (kirlenmiş veri) source'dan sink'e ulaştığında** ortaya çıkar. Bu challenge'da iki source→sink hattı vardı:

| Source | Ara İşlem | Sink | Sonuç |
|---|---|---|---|
| `bio` form alanı | `checkInput()` blacklist | `render_template_string(temp % bio)` | Filtreli — kırılması zor |
| EXIF `Artist` alanı | **Yok** | `render_template_string("Verified! {}".format(sec_code))` | Filtresiz — gerçek zafiyet |

### 3.2 Neden Sistematik Tarama Şart

İnsan (ve tecrübesiz analist) doğal olarak **ilk bulduğu ilginç noktaya kilitlenir** ve confirmation bias ile orada ısrar eder. Profesyonel yaklaşım tam tersidir: **önce tüm sink'leri çıkar, sonra her birinin source'unu ve filtresini incele.**

```bash
# Tehlikeli fonksiyon çağrılarını topluca bul
grep -rn "render_template_string\|eval(\|exec(\|os\.system\|os\.popen\|subprocess\.\|pickle\.loads\|yaml\.load(" --include="*.py" .
```

Bu tek komut, bu challenge'da `views.py` içindeki **her iki** `render_template_string` çağrısını da aynı anda gösterirdi — ikisi arasındaki filtre farkını fark etmek için sadece 30 saniye yeterdi.

### 3.3 Gerçek Dünya Bağlantısı: SAST Araçları

Bu manuel süreç, endüstride **SAST (Static Application Security Testing)** araçlarının otomatikleştirdiği şeydir — Semgrep, CodeQL, Bandit (Python için) gibi araçlar tam olarak bu source-sink zincirlerini kural tabanlı olarak tarar. Örneğin bir Semgrep kuralı:

```yaml
rules:
  - id: flask-render-template-string-injection
    pattern: render_template_string($X)
    message: "Kullanıcı girdisi render_template_string'e ulaşıyor olabilir — SSTI riski"
    languages: [python]
    severity: ERROR
```

Bir CTF'te bu araçları çalıştırma imkânı yoksa bile, **zihinsel modeli** aynı olmalı: "Bu fonksiyon tehlikeli mi? Girdisi nereden geliyor? Aradaki her adımda filtre var mı?"

### 3.4 Kaynak

- [OWASP — Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [Semgrep Registry](https://semgrep.dev/explore) — Python/Flask için hazır kurallar

---

## 4. Broken Access Control ve Yetki Modelleri

### 4.1 Temel Ayrım: Authentication vs Authorization

- **Authentication (kimlik doğrulama):** "Sen kimsin?" — login mekanizması.
- **Authorization (yetkilendirme):** "Sen bu işlemi yapmaya yetkili misin?" — her action için ayrı ayrı kontrol edilmesi gereken şey.

`/verify` route'u yalnızca `current_user.username == "admin"` kontrolü yapıyordu — bu authorization'ın var olduğunu gösterir, ama **authorization'ın kapsamı** (hangi kaynak üzerinde işlem yapılabileceği) burada devreye giren asıl konudur.

### 4.2 Actor / Target Ayrımı

Her yetkilendirilmiş işlemde iki farklı varlık vardır:

- **Actor (eylemi tetikleyen):** İsteği atan, session'ı olan kullanıcı.
- **Target (eylemin hedefi):** İşlemin üzerinde etki ettiği veri/kaynak.

```python
@views.route("/verify", methods=["POST"])
@login_required
def verify():
    if current_user.username == "admin":   # Actor kontrolü VAR
        verification_id = request.form["id"]
        query = Verification.query.get(verification_id)  # Target kontrolü YOK
        ...
```

Actor kontrolü ("sadece admin girebilir") mevcut, ama **hangi target üzerinde** işlem yapılacağı serbestti — bu challenge'da bu tasarım kasıtlıydı (intended path), çünkü admin'in *kendi* verification kaydı zaten "verified" durumdaydı ve tekrar işlenemiyordu; bu yüzden **ayrı bir actor (ikinci hesap) → farklı bir target (o hesabın verification kaydı) → yetkili actor (admin) tarafından işlenmesi** gerekiyordu.

### 4.3 IDOR (Insecure Direct Object Reference) ile İlişkisi

Bu senaryo, klasik **IDOR** zafiyetinin ters çevrilmiş bir varyasyonu gibi düşünülebilir. Standart IDOR:

```
GET /invoice/1234   → Kullanıcı A'nın faturası
GET /invoice/1235   → Kullanıcı B'nin faturası (A, kimlik kontrolü olmadan görebiliyor)
```

Buradaki fark, IDOR'da **yetkisiz bir actor'ün başka birinin target'ına eriştiği** senaryo iken, bu challenge'da **yetkili bir actor'ün (admin) kendi target'ı yerine saldırganın kontrol ettiği bir target'ı işlemesi** gerekiyordu — mantık tersine çevrilmiş ama kök neden aynı: **"bu target, bu actor'e ait mi/bu actor bu target üzerinde işlem yapmalı mı?" sorusunun eksik/yanlış sorulması.**

### 4.4 Yatay ve Dikey Yetki Yükseltme

- **Dikey (vertical) privilege escalation:** Düşük yetkili bir kullanıcının admin yetkisi kazanması. (Bu challenge'da parola sıfırlama zinciriyle admin'e dönüşmek buydu.)
- **Yatay (horizontal) privilege escalation:** Aynı yetki seviyesindeki başka bir kullanıcının verisine/işlemine erişmek. (`/verify`'ın hangi kaydı işleyeceğini kontrol etmemesi bu kategoriye girer.)

### 4.5 Kaynak

- [PortSwigger — Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP Top 10 — A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## 5. HTTP Metodları ve İstek Manipülasyonu

### 5.1 Tarayıcı Adres Çubuğunun Sınırı

Tarayıcının adres çubuğuna bir URL yazıp Enter'a basmak, **her zaman ve sadece** bir `GET` isteği üretir. HTML formlarda `method="POST"` tanımlıysa, form gönderimi tarayıcı tarafından ayrı bir HTTP isteği olarak (farklı bir method, body içinde form verisiyle) oluşturulur — bu adres çubuğundan asla manuel olarak taklit edilemez.

```html
<form method="POST" action="/forgetpassword">
    <input name="email">
    <button type="submit">Gönder</button>
</form>
```

Bu formun "submit" edilmesi tarayıcıda şu HTTP isteğini üretir:

```http
POST /forgetpassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=admin%40master.guild
```

### 5.2 Formsuz/Bozuk Senaryolarda Manuel İstek Atma

Bir uygulamanın POST kabul ettiği ama arayüzde formu görünmeyen/bozuk olduğu durumlarda, tarayıcı DevTools konsolundan `fetch()` ile manuel istek atmak pratik bir çözümdür:

```javascript
fetch("/forgetpassword", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "email=" + encodeURIComponent("admin@master.guild")
})
.then(r => r.text())
.then(html => console.log(html));
```

Bu, tarayıcının o an açık olan sekmenin **session cookie'lerini otomatik olarak isteğe ekler** (same-origin olduğu için), yani ayrıca login/session bilgisi taşımaya gerek kalmaz.

### 5.3 Neden DevTools Network Sekmesi Zorunlu Bir Alışkanlık Olmalı

Bir formun gerçekte hangi method'u, hangi endpoint'i, hangi body formatını (form-urlencoded / multipart / JSON) kullandığını **tahmin etmek yerine gözlemlemek** gerekir. Tarayıcı DevTools → Network sekmesi, her isteğin tam method, header ve body içeriğini gösterir — bu bilgiyi Burp Suite'e taşıyıp tekrar oynatmak (replay) veya değiştirmek (tamper) standart bir iş akışıdır.

### 5.4 Kaynak

- [MDN — HTTP request methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)
- [MDN — Using the Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)

---

## 6. Dosya Metadata Enjeksiyonu

### 6.1 Saldırı Yüzeyi Sadece Dosya İçeriği Değildir

Bir dosya yükleme (file upload) özelliği değerlendirilirken genelde **dosyanın içeriğine** (magic byte kontrolü, virüs taraması, dosya uzantısı) odaklanılır. Ancak birçok dosya formatı (JPEG, PNG, PDF, MP3, DOCX) **structured metadata** taşır ve bu metadata da kullanıcı tarafından tamamen kontrol edilebilir:

| Format | Metadata Alanı | Örnek Kullanım Alanı |
|---|---|---|
| JPEG/TIFF | EXIF (`Artist`, `Copyright`, `Software`, `GPS*`) | Fotoğraf galerileri, doğrulama sistemleri |
| PDF | Document Info (`Author`, `Title`, `Producer`) | Otomatik rapor/CV işleme sistemleri |
| MP3/FLAC | ID3 Tags (`Title`, `Artist`, `Comment`) | Müzik kütüphaneleri, playlist üreticiler |
| DOCX/XLSX | Core Properties (`creator`, `lastModifiedBy`) | Kurumsal doküman yönetim sistemleri |

### 6.2 Bu Challenge'daki Mekanizma

```python
img = Image.open(query.doc)
exif_table = {TAGS.get(k): v for k, v in img.getexif().items()}
if "Artist" in exif_table:
    sec_code = exif_table["Artist"]
    return render_template_string("Verified! {}".format(sec_code))
```

Buradaki hata sınıfı, **dosyanın kendisinin "güvenli" olarak değerlendirilmesi** (sonuçta bir resim dosyası, kod çalıştırmaz gibi görünüyor) ama **metadata'sının kullanıcı girdisi olduğunun unutulmasıdır.** Geliştirici muhtemelen `bio` alanına uyguladığı sıkı filtreyi burada uygulamayı unuttu — çünkü zihinsel modelinde "resim yükleme" ile "form input'u" farklı kategorilerdi, oysa ikisi de sonuçta aynı sink'e (`render_template_string`) giden kullanıcı kontrollü veridir.

### 6.3 EXIF Payload'ının Programatik Olarak Oluşturulması

```python
import piexif
from PIL import Image

payload = "{{ lipsum.__globals__.os.popen('id').read() }}"

img = Image.new("RGB", (200, 200))
img.save("clean.jpg")

exif_dict = {
    "0th": {piexif.ImageIFD.Artist: payload.encode()},
    "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None
}
Image.open("clean.jpg").save("payload.jpg", exif=piexif.dump(exif_dict))
```

`piexif.dump()`, EXIF alanlarını TIFF/EXIF binary spesifikasyonuna uygun şekilde encode eder ve `Image.save(..., exif=...)` bu binary bloğu JPEG dosyasının uygun segmentine (`APP1` marker) yazar. Sunucu tarafında `Pillow`'un `getexif()` fonksiyonu bu segmenti parse edip Python dict'ine çevirir — bu noktada payload, düz bir string olarak uygulamanın eline geçer.

### 6.4 Genel Savunma Prensibi

Herhangi bir dosya formatından çıkarılan metadata, **form input'uyla aynı güven seviyesinde** ele alınmalı ve aynı sanitization/validation sürecinden geçirilmelidir. "Bu bir dosya, form alanı değil" ayrımı güvenlik açısından geçersizdir — ikisi de kullanıcı tarafından tam kontrol edilebilir.

### 6.5 Kaynak

- [ExifTool Documentation](https://exiftool.org/) — metadata okuma/yazma için endüstri standardı araç
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

---

## Kapanış: Bu Kavramların Birbirine Bağlanışı

Bu altı başlık izole değildir — gerçek bir sömürü zinciri, genelde bunların birkaçının **kombinasyonu** ile kurulur:

```
[Statik Kod Denetimi]
        │  filtresiz sink'i bul (/verify)
        ▼
[Stateful App Mantığı]
        │  parola sıfırlama zincirinin ön koşulunu (/forgetpassword) çöz
        ▼
[HTTP Metod Bilgisi]
        │  doğru method ile doğru body'i gönder
        ▼
[Dosya Metadata Enjeksiyonu]
        │  EXIF üzerinden filtresiz sink'e payload taşı
        ▼
[Jinja2 SSTI Mekaniği]
        │  payload'ın çalışma mantığını kur (lipsum.__globals__.os)
        ▼
[Broken Access Control]
        │  actor (admin) ile target (ikinci hesap) ayrımını doğru kur
        ▼
   RCE / Flag
```

Tek bir konuyu derinlemesine bilmek yeterli değildir — bir web uygulamasına gerçekçi bir saldırı, bu katmanların **hepsinde aynı anda** düşünebilmeyi gerektirir.