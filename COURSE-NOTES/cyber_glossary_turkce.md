<div align="center">

# 🌐 OSI Modeli (Open Systems Interconnection)

### *Siber Güvenlik Terim Rehberi — Ağ Katmanı*

![Language](https://img.shields.io/badge/Dil-Türkçe-red)

</div>

---

## 📇 1. Kimlik Kartı

| Alan | Değer |
|---|---|
| **Tam Açılım** | Open Systems Interconnection Model |
| **Kategori** | Bu bir protokol veya araç değil, **kavramsal referans modeldir** — ağ iletişimini katmanlara ayıran teorik bir çerçeve |
| **Ait Olduğu Alan** | Ağ mimarisi ve tüm protokollerin oturduğu zemin; kripto, IAM, DFIR dahil siber güvenliğin her dalı bu modelin üzerine kurulur çünkü her saldırı/savunma belirli bir katmanda gerçekleşir |
| **Port / Protokol** | Yok — çünkü bu bir yazılım değil, bir sınıflandırma sistemi |
| **CVE / CVSS** | Yok |
| **MITRE ATT&CK** | Doğrudan bir teknik ID'si yok ama neredeyse tüm tekniklerin "hangi katmanda çalıştığı" bu modelle etiketlenir (örneğin ARP Spoofing = Katman 2, DNS Spoofing = Katman 7) |

---

## 🕰️ 2. Neden Var Oldu (Tarihsel Bağlam)

1970'lerde ve 80'lerin başında farklı şirketler (IBM'in SNA'sı, DEC'in DECnet'i vb.) birbiriyle konuşamayan kapalı ağ sistemleri üretiyordu; her üretici kendi "dilini" konuşuyordu ve ağlar birbirine bağlanamıyordu.

**ISO** (Uluslararası Standardizasyon Örgütü), 1984'te bu kaosu çözmek için OSI modelini yayınladı: amaç, herhangi bir üreticinin donanımının/yazılımının, standart katmanlara uyduğu sürece diğerleriyle konuşabilmesiydi.

Pratikte **TCP/IP modeli** piyasayı ele geçirdi (internetin gerçek omurgası odur), ama OSI modeli hâlâ eğitimde ve sorun giderme dilinde standart referans olarak yaşıyor çünkü kavramsal netliği TCP/IP'nin 4 katmanından çok daha fazla.

> 💡 Yani OSI "kazanan mimari" değil, **"ortak dil"** oldu.

---

## ⚙️ 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

Model 7 katmandan oluşur, veri üstten alta (gönderici) ve alttan üste (alıcı) akar:

### 7️⃣ Application (Uygulama)
Kullanıcının gördüğü yer. HTTP isteği, e-posta yazma gibi eylemler burada başlar. Veri henüz "ham" haldedir.

### 6️⃣ Presentation (Sunum)
Veri formatlanır — şifreleme (TLS burada devreye girer), sıkıştırma, karakter kodlaması (UTF-8 gibi). Alıcının anlayacağı forma çevrilir.

### 5️⃣ Session (Oturum)
İki cihaz arasında bir "oturum" açılır, sürdürülür ve kapatılır. Hangi konuşmanın hangi konuşmaya ait olduğunu takip eder.

### 4️⃣ Transport (Taşıma)
Burada TCP veya UDP devreye girer. TCP ise 3-way handshake (SYN → SYN/ACK → ACK) ile güvenilir bağlantı kurar, veriyi segmentlere böler, sıra numarası verir, kayıp veriyi yeniden gönderir. UDP ise hiç el sıkışmadan datagram fırlatır — hız öncelikli.

```
İstemci → SYN         → Sunucu
İstemci ← SYN/ACK      ← Sunucu
İstemci → ACK          → Sunucu
```

### 3️⃣ Network (Ağ)
IP adresleri burada devreye girer. Router'lar bu katmanda çalışır, paketin hangi ağdan hangi ağa gideceğine karar verir (routing).

### 2️⃣ Data Link (Veri Bağlantısı)
MAC adresleri burada. Switch'ler bu katmanda çalışır, aynı yerel ağdaki cihazları birbirine bağlar. Veri artık "frame" halindedir.

### 1️⃣ Physical (Fiziksel)
Bit'lerin fiziksel olarak taşınması — kablo, fiber, elektrik sinyali, radyo dalgası (Wi-Fi).

<div align="center">

| # | Katman | Birim | Ne Yapar | Örnek Cihaz/Protokol |
|:---:|---|:---:|---|---|
| 7️⃣ | Application | Data | Kullanıcı isteğinin başladığı nokta | HTTP, FTP, SMTP |
| 6️⃣ | Presentation | Data | Format, şifreleme, sıkıştırma | TLS, JPEG, UTF-8 |
| 5️⃣ | Session | Data | Oturum açma/sürdürme/kapatma | NetBIOS, RPC |
| 4️⃣ | Transport | Segment | Güvenilir/hızlı iletim, handshake | TCP, UDP |
| 3️⃣ | Network | Packet | Adresleme ve yönlendirme | IP, Router |
| 2️⃣ | Data Link | Frame | Yerel ağ iletişimi, MAC adresleme | Switch, ARP |
| 1️⃣ | Physical | Bit | Fiziksel sinyal iletimi | Kablo, Fiber, Wi-Fi |

</div>

### 🔄 Encapsulation (Kapsülleme)

Her katman, alt katmana veri verirken kendi **header**'ını ekler — buna **encapsulation** denir.

```
Gönderici:  [L7 Data] → [+L6] → [+L5] → [+L4 Header] 
            → [+L3 Header] → [+L2 Header/Trailer] → [L1 Bit akışı]
```

Alıcı tarafta bu işlem tersine döner: her katman kendi header'ını okur, çıkarır ve üst katmana teslim eder — buna **de-encapsulation** denir.

```
Alıcı:      [L1 Bit] → [L2 okunur→çıkarılır] → [L3] → [L4] → [L5] → [L6] → [L7 Data]
```

---

## 🧳 4. Somut Gündelik Benzetme (Zorunlu, Güçlü)

Bunu **uluslararası bir kargo/posta sistemi** gibi düşün.

Sen (**Katman 7 - Application**) bir mektup yazarsın — içerik budur, asıl mesaj. Mektubu zarfa koyarken dile çevirirsin, gerekirse şifrelersin — mesela mektubu özel bir koda çeviririm (**Katman 6 - Presentation**). Zarfın üzerine "Bu, Ahmet ile yürüttüğüm 3. yazışma" notunu düşersin — hangi konuşmaya ait olduğu belli olsun diye (**Katman 5 - Session**). Sonra kargo şirketine verirsin, onlar zarfı "takip numarası" ile paketler, kaybolursa yeniden gönderir garantisi verirler (**Katman 4 - Transport**, TCP mantığı). Kargo şirketi paketin hangi şehre, hangi ülkeye gideceğine karar verir — bu bir yol haritasıdır (**Katman 3 - Network**, IP routing). Paket şehir içinde dağıtım merkezine, oradan senin sokağındaki dağıtıcıya teslim edilir (**Katman 2 - Data Link**, MAC/switch mantığı). En sonunda paket gerçekten bir kamyonda, bir yolda, fiziksel olarak taşınır (**Katman 1 - Physical**, kablo/fiber).

Alıcı tarafta bu süreç tam tersine işler: kamyon → dağıtıcı → şehir → takip numarası kontrolü → zarf açılır → mektup okunur.

| OSI Katmanı | Kargo Benzetmesi |
|---|---|
| 7. Application | Mektubun kendisi — asıl mesaj |
| 6. Presentation | Mektubu özel koda çevirmek (şifreleme) |
| 5. Session | Zarfa "3. yazışmam" notu düşmek |
| 4. Transport | Takip numarası, kayıpta yeniden gönderme garantisi |
| 3. Network | Hangi şehre/ülkeye gideceğine karar vermek |
| 2. Data Link | Şehir içi dağıtım merkezinden sokağa ulaşmak |
| 1. Physical | Kamyonla fiziksel taşıma |

---

## 🎯 5. Saldırgan Senaryosu (Uçtan Uca Hikaye)

Bir saldırgan OSI modelini "hangi katmanda saldırırsam en az iz bırakırım ve en fazla etki yaratırım" sorusuna cevap bulmak için kullanır — bu keşif (reconnaissance) ve exploitation aşamalarının her ikisinde de geçerlidir.

<table>
<tr><td>

**Örnek senaryo:**

1. 🔴 **Katman 2:** Saldırgan önce **ARP Spoofing** yapar (`Ettercap` veya `Bettercap` aracıyla) — yerel ağdaki bir cihazın MAC adresini taklit ederek trafiği kendi üzerinden geçirir (Man-in-the-Middle). Bunu bilinçli seçer çünkü Katman 2 saldırıları genelde firewall'ların göremediği, en "sessiz" seviyededir.

2. 🔴 **Katman 7:** Trafiği ele geçirdikten sonra HTTP trafiğini izler (`Wireshark`), şifrelenmemiş kimlik bilgilerini yakalar.

3. 🔴 **Katman 6:** Eğer hedef HTTPS kullanıyorsa, TLS'i **SSL Stripping** (`sslstrip` aracı) ile düşürmeye çalışır — kurbanı HTTPS'ten HTTP'ye zorlamak, çünkü şifreleme burada devreye girer.

</td></tr>
</table>

Bu tam bir kill chain: Katman 2'den giriş → Katman 6'da şifrelemeyi kırma girişimi → Katman 7'de veri hırsızlığı.

---

## 🛡️ 6. Savunma Senaryosu (Uçtan Uca Hikaye)

Bir SOC analisti, bir saldırıyı doğru katmanla eşleştirmeyi bilmezse yanlış yerde arama yapar ve zaman kaybeder — bu yüzden OSI, triage'ın ilk adımıdır.

<table>
<tr><td>

**Triage akışı:**

- ✅ **ARP Spoofing şüphesinde:** Analist Katman 2'ye bakar: switch üzerinde **Dynamic ARP Inspection (DAI)** loglarını kontrol eder, aynı IP'ye birden fazla MAC adresinin eşlendiğini görürse bu kesin bir işarettir. SIEM'de *"duplicate MAC-IP binding"* alarmı tetiklenir.

- ✅ **DNS ile ilgili sorunda** (Katman 7'ye yakın, uygulama seviyesi protokol): analist DNS sorgu loglarına bakar, anormal domain sorgularını (DNS tunneling şüphesi) arar.

</td></tr>
</table>

**Hardening (önleme) tarafında:**

- 🔒 Switch'lerde **Port Security** ve **DHCP Snooping** açılırsa Katman 2 saldırıları baştan engellenir
- 🔒 **HSTS (HTTP Strict Transport Security)** açılırsa SSL Stripping işe yaramaz çünkü tarayıcı HTTP'ye asla düşmeyi kabul etmez

Yani OSI bilgisi, analistin "bu belirti hangi katmanın logunda görünür" sorusuna anında cevap vermesini sağlar.

---

## ⚠️ 7. Zafiyet / Kötüye Kullanım Noktaları

OSI modelinin kendisi bir zafiyet değildir çünkü teorik bir çerçevedir, ama her katmanın altında yatan protokoller tasarım gereği zayıftır ve bu zayıflıklar OSI'nin katman ayrımı sayesinde net şekilde konumlandırılabilir.

- **Katman 2 (ARP):** Hiçbir doğrulama mekanizması olmadan tasarlandığı için ARP Spoofing mümkündür — 1980'lerde güven varsayımıyla yazıldı, kimse "biri bunu kötüye kullanır mı" diye düşünmedi.
- **Katman 3-4:** SYN Flood gibi saldırılar TCP'nin "yarım bağlantı" durumunu istismar eder.

> 📌 **Tarihte en bilinen örnek:** 2013'teki büyük DDoS saldırılarının çoğu Katman 3-4 amplifikasyon teknikleriyle (NTP/DNS amplification) yapıldı, çünkü bu katmanlar hacim bazlı saldırılara açıktır.

Katman ayrımını bilmek, "bu saldırı neden mümkün, hangi katmanın tasarım zaafından besleniyor" sorusunu cevaplamayı sağlar.

---

## 🔀 8. Sık Karıştırılan / Birlikte Anılan Kavramlar

| Kavram | Açıklama |
|---|---|
| **TCP/IP Modeli** | OSI'nin 7 katmanını 4 katmana sıkıştıran, gerçek internette kullanılan modeldir — OSI teorik referans, TCP/IP pratik uygulamadır |
| **Encapsulation** | OSI'nin katmanlar arası veri paketleme mekanizmasıdır, model değil bir süreçtir |
| **Katman 2 vs Katman 3 cihazları** | Switch (Katman 2, MAC bazlı) ile router (Katman 3, IP bazlı) farklı kararlar verir |
| **Protocol Stack** | Bir cihazda hangi protokollerin hangi katmanda çalıştığının somut listesidir — OSI ise bu stack'in sınıflandırma şablonudur |

---

## 🎤 9. Mülakat Sorusu Simülasyonu

> **Soru:** *"Bir kullanıcı belirli bir web sitesine erişemiyor ama aynı ağdaki diğer siteler açılıyor. Sorunu OSI modeline göre nasıl sistematik olarak izole edersin?"*

<details>
<summary><b>✅ Model Cevabı (görmek için tıkla)</b></summary>

<br>

Önce Katman 1-2'yi dışlarım çünkü diğer siteler açılıyor, yani fiziksel bağlantı ve yerel ağ (switch/MAC) sağlam. Katman 3'ü kontrol ederim: ping ile hedef IP'ye ulaşabiliyor muyum, routing sorunu var mı. Ulaşabiliyorsam Katman 4'e geçerim: telnet veya nc ile 443 portuna bağlanabiliyor muyum, TCP handshake tamamlanıyor mu. Buradan geçiyorsa Katman 6-7'ye odaklanırım: TLS sertifika hatası mı var, yoksa DNS çözümlemesi mi yanlış IP döndürüyor. Bu şekilde OSI, sorunu rastgele değil, katman katman elemeyle izole etmemi sağlar — "her yeri aynı anda kontrol etmek" yerine sistematik ilerlerim.

</details>

---

## ⚓ 10. Hafıza Çapası (Memory Anchor)

> **OSI Modeli = uluslararası kargo sistemi; her katman bir zarf, bir adres etiketi veya bir kamyon gibi kendi görevini yapar, ama hiçbiri diğerinin işine karışmaz — bir saldırgan da bir savunmacı da önce "bu olay hangi kamyonda oldu" sorusunu sorar.**

---

## 🔢 11. Sadece Ezberlenecek Çıplak Veri

7 katman sırası (yukarıdan aşağıya):

```
7. Application
6. Presentation
5. Session
4. Transport
3. Network
2. Data Link
1. Physical
```

🧠 Ezber cümlesi (İngilizce yaygın kullanım): **"A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing."


---

<div align="center">

# 🔗 TCP/IP Modeli (Transmission Control Protocol / Internet Protocol)

### *Siber Güvenlik Terim Rehberi — Ağ Katmanı*


</div>

---

## 📇 1. Kimlik Kartı

| Alan | Değer |
|---|---|
| **Tam Açılım** | Transmission Control Protocol / Internet Protocol Suite |
| **Kategori** | Bu bir protokol veya araç değil, **pratikte gerçekten kullanılan mimari referans modeldir** — OSI'nin teorik 7 katmanının aksine, TCP/IP internetin fiilen üzerinde çalıştığı gerçek yapıdır |
| **Ait Olduğu Alan** | Ağ mimarisi — TCP, UDP, IP, HTTP, DNS gibi hemen her protokol bu modelin bir katmanına oturur; DFIR'de paket analizi, threat intel'de trafik sınıflandırması hep bu model üzerinden konuşulur |
| **Port / Protokol** | Yok (kendisi bir çerçevedir, ama Transport katmanında TCP/UDP portlarını barındırır) |
| **CVE / CVSS** | Yok (modelin kendisi değil, üzerindeki protokoller — TCP, IP — ayrı ayrı zafiyetlere sahiptir) |
| **MITRE ATT&CK** | Doğrudan bir teknik ID'si yok ama her ATT&CK tekniği (Network Sniffing T1040, IP Spoofing vb.) bu modelin bir katmanına ait olarak sınıflandırılır |

---

## 🕰️ 2. Neden Var Oldu (Tarihsel Bağlam)

1960'ların sonunda ABD Savunma Bakanlığı'nın **ARPANET** projesi kapsamında bir sorun vardı: nükleer saldırı gibi bir felakette bile ağın parçalarının birbirine ulaşabilmesi gerekiyordu — merkezi bir yapı olursa merkez vurulduğunda her şey çökerdi. Vint Cerf ve Bob Kahn, 1970'lerde **dağıtık, merkezi otoritesi olmayan, esnek** bir iletişim protokolü tasarladılar: TCP/IP.

OSI modeli 1984'te ISO tarafından "kağıt üzerinde mükemmel" bir standart olarak çıktığında, TCP/IP zaten yıllardır gerçek ağlarda **çalışıyordu**. OSI'nin 7 katmanı çok karmaşık ve yavaş standartlaşıyordu; TCP/IP ise basit, kanıtlanmış ve zaten yaygındı. Sonuç: dünya OSI'yi değil, TCP/IP'yi benimsedi — bugün internetin tamamı bu model üzerinde çalışır.

> 💡 OSI "ders kitabı modeli", TCP/IP ise **"gerçek dünyada kazanan model"**dir.

---

## ⚙️ 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

TCP/IP modeli 4 katmandan oluşur (bazı kaynaklarda 5 katman olarak da anlatılır, Data Link ve Physical ayrılarak). OSI'nin 7 katmanını şu şekilde kendi içinde birleştirir:

<div align="center">

| TCP/IP Katmanı | Karşılık Geldiği OSI Katmanları | Ne Yapar | Örnek Protokoller |
|---|:---:|---|---|
| **Application** | 7-6-5 (Application+Presentation+Session) | Kullanıcı uygulaması, format, oturum — hepsi tek katmanda | HTTP, DNS, SMTP, FTP, SSH |
| **Transport** | 4 (Transport) | Uçtan uca iletim, güvenilirlik veya hız | TCP, UDP |
| **Internet** | 3 (Network) | Adresleme ve yönlendirme | IP, ICMP, ARP |
| **Network Access (Link)** | 2-1 (Data Link+Physical) | Yerel ağ iletişimi ve fiziksel taşıma | Ethernet, Wi-Fi, switch |

</div>

### 🔄 Veri Akışı — Baştan Sona

**1. Application Katmanı:** Kullanıcı bir web sitesine gitmek ister → tarayıcı bir **HTTP GET isteği** oluşturur. Bu istek ham veridir, henüz ağa çıkmamıştır.

**2. Transport Katmanı:** İstek TCP'ye teslim edilir. TCP burada **3-way handshake** başlatır:

```
İstemci → SYN (seq=x)              → Sunucu
İstemci ← SYN-ACK (seq=y, ack=x+1)  ← Sunucu
İstemci → ACK (ack=y+1)             → Sunucu
```

Handshake tamamlanınca bağlantı "ESTABLISHED" durumuna geçer. TCP header'ında **source port, destination port, sequence number, acknowledgment number, flags (SYN/ACK/FIN/RST/PSH/URG), window size** gibi alanlar bulunur — her biri akışın güvenilirliğini garanti eder.

**3. Internet Katmanı:** TCP segmenti bir **IP header** ile sarmalanır. Bu header'da **source IP, destination IP, TTL (Time To Live), protocol numarası** (TCP=6, UDP=17) bulunur. Router'lar bu katmanda paketi okuyup bir sonraki hop'a yönlendirir — buna **routing** denir.

**4. Network Access Katmanı:** IP paketi bir **Ethernet frame**'e sarmalanır — kaynak ve hedef **MAC adresleri** eklenir. Frame, fiziksel ortamda (kablo, fiber, radyo dalgası) bit dizisi olarak iletilir.

### 🔁 Alıcı Tarafta (De-encapsulation)

```
Bit akışı → Frame (MAC okunur) → Paket (IP okunur) 
→ Segment (TCP port okunur, ACK gönderilir) → HTTP verisi tarayıcıya teslim edilir
```

Her katman kendi header'ını okur, çıkarır, bir üst katmana teslim eder — bu işlem tamamen simetriktir.

---

## 🧳 4. Somut Gündelik Benzetme (Zorunlu, Güçlü)

TCP/IP'yi **bir apartmana mektup gönderme süreci** gibi düşün — ama OSI'deki kargo şirketi benzetmesinden farklı olarak burada aracılar daha az, süreç daha "pratik" ve doğrudan.

Sen (**Application**) bir mektup yazar, zarfa koyarsın — içindeki dil ne olursa olsun (format, şifreleme) hepsi bu tek adımda halledilir, ayrı bir "tercüman katı" yok. Postaneye (**Transport**) verdiğinde, postane önce alıcının gerçekten evde olup olmadığını üç kez teyit eder — kapıyı çalar (SYN), "evdeyim" cevabı gelir (SYN-ACK), "geliyorum" dersin (ACK) — bu üçlü teyit olmadan mektup teslim edilmez, bu TCP'nin güvenilirlik garantisidir. Postane zarfın üzerine "bu 5 parçalı bir mektubun 2. parçası" notunu da düşer, kaybolursa yeniden gönderir. Sonra mektup şehirler arası kargo ağına (**Internet**) girer — üzerinde sadece "nereden nereye" yazan bir adres etiketi vardır, arada kaç şehir/aktarma merkezinden geçtiği (**TTL**) sayılır. En son, senin mahallendeki dağıtıcı (**Network Access**) mektubu doğru kapıya (MAC adresi) fiziksel olarak bırakır.

| TCP/IP Katmanı | Benzetme |
|---|---|
| Application | Mektubun içeriği + zarfın hazırlanması, tek adımda |
| Transport | Postanenin "üç kez teyit ederek" teslimat garantisi (handshake) |
| Internet | Şehirler arası adres etiketi ve aktarma sayısı (TTL) |
| Network Access | Mahalledeki dağıtıcının fiziksel teslimatı (MAC) |

---

## 🎯 5. Saldırgan Senaryosu (Uçtan Uca Hikaye)

Bir saldırgan TCP/IP modelini **keşif (reconnaissance)** aşamasında en yoğun şekilde kullanır çünkü hedefin hangi portların açık olduğunu, hangi katmanda hangi hizmetin çalıştığını bilmeden hiçbir exploitation adımı atamaz.

<table>
<tr><td>

**Kill Chain Senaryosu:**

1. 🔴 **Keşif — Internet/Transport Katmanı:** Saldırgan `Nmap` ile hedef IP'ye **TCP SYN Scan** (`nmap -sS hedef_ip`) atar. Her portu tam handshake yapmadan (sadece SYN gönderip SYN-ACK alarak) tarar — bu hem hızlıdır hem de bağlantı tam kurulmadığı için bazı loglarda görünmeyebilir (**stealth scan**). Açık portları, arkasındaki servisleri (SSH, HTTP, SMB) öğrenir.

2. 🔴 **Keşif Derinleştirme:** `Nmap -sV` ile servis versiyonlarını çıkarır, `Wireshark` ile TCP handshake trafiğini analiz ederek anormal davranışları (firewall/IDS varlığı) tespit etmeye çalışır.

3. 🔴 **Exploitation — Transport Katmanı DoS:** Eğer amaç hizmeti çökertmekse, saldırgan **SYN Flood** başlatır (`hping3 -S --flood hedef_ip`): binlerce SYN paketi gönderir ama hiçbir zaman ACK ile tamamlamaz — sunucu "yarım açık" (half-open) bağlantı tablosunu doldurur, meşru kullanıcılar bağlanamaz hale gelir.

4. 🔴 **Lateral Movement — Internet Katmanı:** Ağ içine sızdıktan sonra saldırgan **IP Spoofing** ile kaynak IP'sini taklit ederek güvenilir bir cihazmış gibi davranır, iç ağdaki güven ilişkilerinden faydalanır.

</td></tr>
</table>

Bu akış net bir mantık izler: **önce hangi kapılar açık öğren (Nmap), sonra o kapının arkasında ne olduğunu anla (versiyon tarama), sonra ya kırılganlığı istismar et ya da hizmeti çökert (SYN Flood).**

---

## 🛡️ 6. Savunma Senaryosu (Uçtan Uca Hikaye)

Bir SOC analisti için TCP/IP bilgisi, "bu trafik normal mi anormal mi" sorusunu saniyeler içinde cevaplamanın temelidir.

<table>
<tr><td>

**Triage Akışı:**

- ✅ **Port Tarama Şüphesi:** Analist firewall/IDS loglarında kısa sürede aynı kaynak IP'den **çok sayıda farklı porta SYN paketi** gittiğini, ama çok azına tam handshake'in tamamlandığını görür → bu klasik bir **Nmap SYN Scan** imzasıdır. Snort/Suricata kuralı: `alert tcp any any -> $HOME_NET any (flags:S; threshold: type threshold, track by_src, count 20, seconds 5;)`

- ✅ **SYN Flood Şüphesi:** SIEM'de "half-open connections" sayısının anormal yükseldiğini, aynı kaynaktan gelen SYN paketi sayısının aldığı ACK sayısına oranla çok fazla olduğunu görür → **SYN Cookie** mekanizması otomatik devreye girmiş olabilir, netstat/ss ile `SYN_RECV` durumundaki bağlantı sayısı kontrol edilir.

- ✅ **IP Spoofing Şüphesi:** Gelen paketin kaynak IP'si iç ağa aitmiş gibi görünüyor ama paket dış arayüzden geliyorsa → bu tutarsızlık **ingress/egress filtering** kurallarıyla firewall seviyesinde yakalanır.

</td></tr>
</table>

**Hardening (önleme) tarafında:**

- 🔒 **SYN Cookies** açılırsa sunucu bağlantı tablosunu SYN Flood'a karşı korur, her SYN için state tutmadan matematiksel doğrulama yapar
- 🔒 **Rate limiting** ve **connection timeout** ayarları port tarama ve flood saldırılarını yavaşlatır
- 🔒 **Ingress/Egress Filtering (BCP38)** IP Spoofing'i ağ sınırında engeller
- 🔒 Gereksiz portları kapatmak (**port hardening**) saldırganın keşif yüzeyini daraltır

---

## ⚠️ 7. Zafiyet / Kötüye Kullanım Noktaları

TCP/IP, tasarlandığı dönemde (1970'ler) **güven varsayımı** üzerine kuruldu — internetin bugünkü gibi düşmanca bir ortam olacağı öngörülmemişti, bu yüzden protokolün temelinde kimlik doğrulama veya bütünlük kontrolü yoktu.

- **TCP'nin "yarım bağlantı" zafiyeti:** SYN Flood'un temelidir — sunucu her SYN'e kaynak ayırır ama ACK gelmezse bu kaynaklar "kilitli" kalır. Bu, protokolün handshake mantığının doğrudan sonucudur.
- **IP'nin kaynak adresi doğrulamaması:** Herhangi bir cihaz, paketinin üzerine "ben buyum" diye istediği kaynak IP'sini yazabilir — bu **IP Spoofing**'in temelidir ve DDoS amplifikasyon saldırılarının (DNS/NTP amplification) da temelini oluşturur.
- **Sıra numaralarının tahmin edilebilirliği (eski sistemlerde):** 1990'ların ortasında **TCP Sequence Number Prediction** saldırıları, zayıf rastgele sayı üreteçleri yüzünden oturum ele geçirmeyi (session hijacking) mümkün kılıyordu.

> 📌 **Tarihsel örnek:** 1996'daki ünlü **SYN Flood saldırısı** (Panix ISP'ye karşı), bu zafiyetin internette ilk büyük çaplı gerçek dünya istismarlarından biriydi ve SYN Cookie mekanizmasının geliştirilmesine doğrudan yol açtı.

---

## 🔀 8. Sık Karıştırılan / Birlikte Anılan Kavramlar

| Kavram | Açıklama |
|---|---|
| **OSI Modeli** | TCP/IP'nin 4 katmanı, OSI'nin 7 katmanının pratikte birleştirilmiş halidir — OSI teorik referans, TCP/IP gerçek dünyada çalışan modeldir |
| **TCP vs UDP** | Her ikisi de Transport katmanında çalışır ama TCP güvenilir/bağlantı-yönelimli, UDP hızlı/bağlantısızdır — TCP/IP modeli her ikisini de aynı katmanda barındırır |
| **IP vs MAC Adresi** | IP, Internet katmanında mantıksal adreslemedir (değişebilir); MAC, Network Access katmanında fiziksel/donanımsal adrestir (sabittir) |
| **Port Numarası vs IP Adresi** | IP "hangi bilgisayar", port "o bilgisayarda hangi uygulama" sorusuna cevap verir — ikisi birlikte bir **socket** oluşturur |

---

## 🎤 9. Mülakat Sorusu Simülasyonu

> **Soru:** *"Wireshark'ta bir trafik yakalıyorsun ve çok sayıda SYN paketi görüyorsun ama neredeyse hiç ACK yok. Bu ne anlama gelir ve TCP/IP modeli açısından hangi katmanda ne oluyor, nasıl doğrularsın?"*

<details>
<summary><b>✅ Model Cevabı (görmek için tıkla)</b></summary>

<br>

Bu görüntü klasik bir **SYN Flood** belirtisidir — Transport katmanında TCP'nin 3-way handshake mekanizması kasıtlı olarak yarıda bırakılıyor. Normal bir bağlantıda her SYN'in bir SYN-ACK'i ve onu takip eden bir ACK'i olur; burada SYN sayısı ile tamamlanan handshake sayısı arasında ciddi bir uyumsuzluk var. Doğrulamak için önce kaynak IP dağılımına bakarım: tek bir IP'den mi geliyor (klasik flood) yoksa binlerce farklı IP'den mi (dağıtık/DDoS, muhtemelen spoofed kaynaklar). Sonra sunucu tarafında `netstat -an | grep SYN_RECV` ile yarı-açık bağlantı sayısını kontrol ederim — anormal yükseklik teyit sağlar. Son olarak, bu paketlerin kaynak IP'lerinin gerçek mi yoksa spoofed mi olduğunu anlamak için TTL değerlerindeki tutarsızlıklara bakarım, çünkü spoofed paketlerde TTL genelde beklenenden farklı çıkar.

</details>

---

## ⚓ 10. Hafıza Çapası (Memory Anchor)

> **TCP/IP Modeli = OSI'nin "laboratuvar teorisi" değil, "gerçek hayatta çalışan versiyonu"dur; 4 katmanı hatırlamak için "postane üç kez kapıyı çalmadan mektubu teslim etmez" cümlesini düşün — bu, TCP'nin handshake garantisidir.**

---

## 🔢 11. Sadece Ezberlenecek Çıplak Veri

4 katman sırası (yukarıdan aşağıya):

```
4. Application     (HTTP, DNS, FTP, SMTP, SSH)
3. Transport       (TCP, UDP)
2. Internet        (IP, ICMP, ARP)
1. Network Access  (Ethernet, Wi-Fi)
```

**TCP Header temel alanları:** Source Port, Destination Port, Sequence Number, Acknowledgment Number, Flags (SYN/ACK/FIN/RST/PSH/URG), Window Size

**IP Header temel alanları:** Source IP, Destination IP, TTL, Protocol (TCP=6, UDP=17)

---

# TCP (Transmission Control Protocol)

*Siber Güvenlik Terim Rehberi — Transport Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Transmission Control Protocol
- **Kategori:** Protokol
- **Ait Olduğu Katman:** OSI Katman 4 (Transport) / TCP-IP modelinde Transport katmanı
- **Port/Protokol İlişkisi:** Kendisi bir port değil, portların üzerinde çalıştığı taşıma protokolüdür (ör. port 443 + TCP = HTTPS bağlantısı)
- **CVE/CVSS:** Yok — TCP'nin kendisi tek bir CVE'ye sahip değildir, ama TCP implementasyonlarındaki (işletim sistemi seviyesinde) hatalar CVE alır
- **MITRE ATT&CK:** Dolaylı — TCP üzerinden yapılan pek çok teknik (T1046 Network Service Discovery, T1499 Endpoint Denial of Service) bu protokolün mekaniğini istismar eder

> Not: Bir önceki dosyada işlenen **TCP/IP Modeli**, 4 katmanlı genel mimariydi. Bu dosya ise o mimarinin Transport katmanında oturan **tek bir protokolü** — TCP'nin kendisini — derinlemesine inceler.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

1970'lerin başında ARPANET üzerinde veri gönderildiğinde hiçbir garanti yoktu: paket kaybolabilir, sırası bozulabilir, hiç ulaşmayabilirdi. Vint Cerf ve Bob Kahn 1974'te bu sorunu çözmek için TCP'yi tasarladı: amaç, güvenilmez bir ağ üzerinde **güvenilir** bir iletişim katmanı kurmaktı.

TCP'den önce ağlar üzerinde veri "gönder ve umut et" mantığıyla akıyordu. TCP bu boşluğu üç temel garanti ile kapattı: **sıralı teslimat**, **kayıp veri tespiti ve yeniden gönderim**, **akış kontrolü** (alıcı boğulmasın diye hız ayarı). UDP ise bilerek bu garantileri vermez çünkü hız öncelikli senaryolar (video, oyun) için farklı bir ihtiyaç doğmuştu — TCP'nin var oluş nedeni tam olarak bu güvenilirlik açığıdır.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### Bağlantı Kurulumu: 3-Way Handshake

```
İstemci → SYN (seq=1000)                    → Sunucu
İstemci ← SYN-ACK (seq=5000, ack=1001)       ← Sunucu
İstemci → ACK (ack=5001)                     → Sunucu
                    [Bağlantı ESTABLISHED]
```

Her taraf kendi başlangıç sıra numarasını (**sequence number**) bildirir. Bu numaralar rastgele seçilir çünkü tahmin edilebilir olursa saldırgan bağlantıyı ele geçirebilir (**session hijacking**).

### TCP Header'ın Kritik Alanları

| Alan | Görevi |
|---|---|
| Source/Destination Port | Hangi uygulamaya ait olduğunu belirler |
| Sequence Number | Bu segmentin veri akışındaki sırasını gösterir |
| Acknowledgment Number | "Şu ana kadar gelen veriyi aldım" bilgisini taşır |
| Flags (SYN, ACK, FIN, RST, PSH, URG) | Bağlantının durumunu/isteğini belirtir |
| Window Size | Alıcının aynı anda kabul edebileceği veri miktarı (akış kontrolü) |
| Checksum | Verinin bozulup bozulmadığını kontrol eder |

### TCP State Machine (Bağlantı Durumları)

```
CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
```

- **CLOSED:** Hiçbir bağlantı yok
- **SYN_SENT:** İstemci SYN gönderdi, cevap bekliyor
- **ESTABLISHED:** Handshake tamamlandı, veri akışı sürüyor
- **FIN_WAIT / CLOSE_WAIT:** Taraflardan biri bağlantıyı kapatmak istiyor
- **TIME_WAIT:** Bağlantı kapandı ama geç gelebilecek paketler için bir süre beklenir

### Bağlantı Kapatma: 4-Way Handshake

```
Taraf A → FIN  → Taraf B
Taraf A ← ACK  ← Taraf B
Taraf A ← FIN  ← Taraf B
Taraf A → ACK  → Taraf B
```

Her iki taraf da bağlantıyı ayrı ayrı kapatır çünkü TCP **full-duplex**'tir — iki yönlü veri akışı birbirinden bağımsız sonlandırılır.

### Akış Kontrolü ve Yeniden Gönderim

Eğer bir segment kaybolursa, alıcı beklediği sıra numarasını almadığı için tekrar aynı ACK'i gönderir (**duplicate ACK**). Gönderici bunu 3 kez üst üste görürse veriyi yeniden gönderir (**fast retransmit**) — hiçbir üst katman uygulamasının bunu fark etmesine gerek kalmaz, güvenilirlik tamamen TCP seviyesinde çözülür.

---

## 4. Somut Gündelik Benzetme

TCP'yi **telefon görüşmesi başlatmak** gibi düşün.

Sen karşı tarafı ararsın (**SYN**), telefon çalar ve karşı taraf "alo" der (**SYN-ACK**), sen de "evet ben de duyuyorum" dersin (**ACK**) — üçlü bu teyitten sonra konuşma gerçekten başlar. Konuşma sırasında karşı taraf senin söylediklerini anlamazsa "tekrar eder misin" der (**duplicate ACK / retransmit**) — hiçbir cümle kaybolmadan iletişim tamamlanır. Görüşme bittiğinde her iki taraf da ayrı ayrı "tamam, kapatıyorum" der ve karşı taraf da onaylar (**4-way handshake**) — telefonu aniden kapatmak (**RST**) kaba bir davranış sayılır, tıpkı ağda beklenmedik bağlantı kesilmesi gibi.

| TCP Kavramı | Telefon Benzetmesi |
|---|---|
| SYN / SYN-ACK / ACK | Arama, "alo" cevabı, "duyuyorum" teyidi |
| Sequence Number | Konuşmanın hangi cümlede olduğunun takibi |
| Duplicate ACK / Retransmit | "Tekrar eder misin" deyip cümleyi yeniden duymak |
| 4-way handshake | Görüşmeyi karşılıklı, düzgünce kapatmak |
| RST | Telefonu aniden, açıklamasız kapatmak |

---

## 5. Saldırgan Senaryosu

Bir saldırgan TCP'nin mekaniğini hem **keşif** hem **exploitation** aşamasında kullanır çünkü handshake davranışının kendisi bilgi sızdırır.

**Adım adım senaryo:**

1. **Keşif:** Saldırgan `nmap -sS hedef_ip` ile **SYN Scan** yapar — SYN gönderir, SYN-ACK gelirse port açık demektir, ama bilerek ACK göndermeyip handshake'i tamamlamaz. Bu, bazı basit loglama sistemlerinde tam bağlantı olarak görünmediği için "yarı gizli" bir taramadır.

2. **Exploitation — DoS:** Saldırgan `hping3 -S --flood -p 80 hedef_ip` ile **SYN Flood** başlatır: binlerce SYN gönderir, hiçbirini ACK ile tamamlamaz. Sunucunun bağlantı tablosu (backlog queue) dolar, meşru SYN istekleri reddedilmeye başlar.

3. **Session Hijacking:** Eğer sequence number tahmin edilebilirse (eski/zayıf implementasyonlarda), saldırgan meşru bir bağlantının ortasına kendi paketini enjekte edebilir — bunun için doğru sequence/acknowledgment numaralarını tahmin etmesi gerekir, TCP'nin bu numaraları rastgele seçme zorunluluğu tam da bunu engellemek içindir.

4. **Lateral Movement:** Ağ içine girdikten sonra saldırgan açık TCP portlarını (445/SMB, 3389/RDP gibi) tekrar tarar, hangi servislerin yanal hareket için kullanılabileceğine karar verir.

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **SYN Scan şüphesi:** IDS/IPS'te tek bir kaynaktan çok kısa sürede farklı hedef portlara SYN gittiğini ama handshake'in tamamlanmadığını görürsün. Suricata kuralı örneği: `alert tcp any any -> $HOME_NET any (flags:S; threshold: type threshold, track by_src, count 20, seconds 5; msg:"Possible SYN scan";)`

- **SYN Flood şüphesi:** Sunucuda `netstat -an | grep SYN_RECV` ile yarı-açık bağlantı sayısına bakarsın; anormal yükseklik SYN Flood'u doğrular. SIEM'de "half-open connection count" metriği ani sıçrama gösterir.

- **Session Hijacking şüphesi:** Aynı bağlantı için beklenmedik sequence number sıçramaları veya aynı anda iki farklı kaynaktan gelen tutarsız ACK'ler görülür — bu, ortada bir enjeksiyon girişimi olabileceğinin işaretidir.

**Hardening:**

- **SYN Cookies** açmak, sunucunun her SYN için state tutmadan matematiksel doğrulama yapmasını sağlar, SYN Flood'u büyük ölçüde etkisizleştirir
- **Connection rate limiting**, tek bir kaynaktan gelen bağlantı hızını sınırlar
- **Rastgele ve tahmin edilemez sequence number üretimi** (modern işletim sistemlerinde standart), session hijacking riskini azaltır

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

TCP, tasarlandığı dönemde güven varsayımı üzerine kuruldu — kaynak IP'nin gerçekten iddia ettiği kişi olduğu, ağın düşmanca olmadığı varsayıldı.

- **Handshake'in yarım bırakılabilir olması**, doğrudan SYN Flood'un temelidir — protokol tasarımı gereği sunucu her SYN'e kaynak ayırmak zorundadır.
- **Eski sistemlerde tahmin edilebilir sequence number üretimi**, 1990'ların ortasında ciddi session hijacking saldırılarına yol açtı.
- **RST paketlerinin doğrulanmadan kabul edilmesi**, saldırganın sahte RST göndererek meşru bir bağlantıyı zorla kapatmasına (**TCP RST Attack**) izin verebilir.

> **Tarihsel örnek:** 1996'daki **Panix ISP SYN Flood saldırısı**, TCP'nin bu doğuştan zafiyetinin internetteki ilk büyük çaplı istismarlarından biriydi ve doğrudan SYN Cookie mekanizmasının geliştirilmesine yol açtı.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **TCP vs UDP** | TCP bağlantı-yönelimli ve güvenilirdir (handshake, yeniden gönderim); UDP bağlantısızdır, hız için güvenilirlikten feragat eder |
| **TCP vs TCP/IP Modeli** | TCP, Transport katmanında çalışan tek bir protokoldür; TCP/IP Modeli ise TCP'nin de içinde bulunduğu 4 katmanlı genel mimaridir |
| **SYN Scan vs Connect Scan** | SYN Scan handshake'i tamamlamadan bilgi toplar (yarı gizli); Connect Scan tam bağlantı kurar, daha kolay loglanır |
| **RST vs FIN** | FIN, bağlantıyı düzgün ve karşılıklı kapatma isteğidir; RST, bağlantıyı anında ve tek taraflı sonlandırma zorlamasıdır |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"SYN Flood saldırısı sırasında sunucu tarafında neden yeni meşru bağlantılar kabul edilemez hale gelir? Teknik olarak ne doluyor?"*

<details>
<summary>Model Cevabı</summary>

<br>

Sunucu her gelen SYN paketi için bir "yarı açık bağlantı" kaydı oluşturur ve bunu **backlog queue** (bağlantı bekleme kuyruğu) adı verilen sınırlı kapasiteli bir tabloda tutar. Normal koşullarda istemci kısa sürede ACK göndererek bu kaydı "tam bağlantı"ya çevirir ve kayıt kuyruktan çıkar. SYN Flood saldırısında saldırgan binlerce SYN gönderir ama hiçbirini ACK ile tamamlamaz, bu yüzden her kayıt kuyrukta zaman aşımına kadar (genelde saniyeler-dakikalar) kilitli kalır. Kuyruk dolduğunda sunucu yeni gelen meşru SYN paketlerini reddetmek veya görmezden gelmek zorunda kalır çünkü ayıracak kaynak (bellek, bağlantı slotu) kalmamıştır. Çözüm olarak SYN Cookies, bu kaydı hiç tutmadan, sequence number içine matematiksel bir doğrulama gömerek "state'siz" bir handshake doğrulaması yapar.

</details>

---

## 10. Hafıza Çapası

**TCP = telefon görüşmesi; önce üç kez teyit edip konuşmaya başlarsın (handshake), konuşurken cümle kaybolursa tekrar ettirirsin (retransmit), görüşmeyi de karşılıklı olarak düzgünce kapatırsın (4-way close) — aniden telefonu kapatmak (RST) ise saldırının imzasıdır.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **Handshake:** SYN → SYN-ACK → ACK (3 adım)
- **Kapatma:** FIN → ACK → FIN → ACK (4 adım)
- **TCP Flags:** SYN, ACK, FIN, RST, PSH, URG
- **Protocol numarası (IP header içinde):** TCP = 6

---

# UDP (User Datagram Protocol)

*Siber Güvenlik Terim Rehberi — Transport Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** User Datagram Protocol
- **Kategori:** Protokol
- **Ait Olduğu Katman:** OSI Katman 4 (Transport) / TCP-IP modelinde Transport katmanı
- **Port/Protokol İlişkisi:** Kendisi bir port değil, portların üzerinde çalıştığı taşıma protokolüdür (ör. port 53 + UDP = DNS sorgusu, port 123 + UDP = NTP)
- **CVE/CVSS:** Yok — protokolün kendisi değil, UDP'yi kullanan servislerin (DNS, NTP, SNMP) implementasyonları CVE alır
- **MITRE ATT&CK:** Dolaylı — T1498 (Network Denial of Service) altındaki amplifikasyon saldırılarının neredeyse tamamı UDP'nin doğasını istismar eder

> Not: Bir önceki dosyada TCP işlendi — güvenilir, bağlantı-yönelimli kardeşi. Bu dosya, TCP'nin tam tersi felsefeyle tasarlanmış UDP'yi inceler.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

TCP 1974'te tasarlandığında güvenilirlik için ciddi bir bedel ödetiyordu: handshake, sıra numarası takibi, yeniden gönderim — hepsi gecikme (**latency**) yaratıyordu. Ama bazı uygulamalar için bu bedel anlamsızdı: bir DNS sorgusu 10 milisaniyede cevaplanmalıydı, TCP'nin 3 adımlık handshake'ini beklemek gereksizdi; bir canlı video akışında kaybolan tek bir kare için "yeniden gönder" istemek zaten geçmişte kalmış bir kareyi beklemek anlamına gelirdi.

David Reed 1980'de bu ihtiyacı çözmek için UDP'yi tasarladı: TCP'nin sunduğu tüm garantileri **bilerek çıkardı** ve geriye sadece "veriyi gönder, hedefe ulaşsın ya da ulaşmasın" mantığını bıraktı. UDP, TCP'nin eksikliğini kapatan bir protokol değil, TCP'nin getirdiği yükü **reddeden** bir tasarım felsefesidir — hız ve basitlik, güvenilirliğin önüne geçer.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### Bağlantı Kurulumu Yok

TCP'deki 3-way handshake burada yoktur. İstemci, hedefin dinlediğinden bile emin olmadan doğrudan veri gönderir:

```
İstemci → UDP Datagram (veri) → Sunucu
                [Cevap gelirse gelir, gelmezse istemci bilemez]
```

Bu, UDP'nin **bağlantısız (connectionless)** olmasının doğrudan sonucudur — "bağlantı" kavramı zaten yoktur, sadece tek yönlü paket fırlatma vardır.

### UDP Header — Çarpıcı Derecede Basit

TCP header'ının (20+ bayt, 6 flag, sequence/ack numaraları) aksine UDP header sadece 8 bayttır:

| Alan | Görevi |
|---|---|
| Source Port | Gönderenin hangi uygulaması |
| Destination Port | Hedefte hangi uygulamaya gidecek |
| Length | Datagramın toplam uzunluğu |
| Checksum | Verinin bozulup bozulmadığının (opsiyonel) kontrolü |

Sequence number yok, acknowledgment yok, window size yok, state machine yok. Her datagram bağımsız bir birimdir — biri kaybolsa bir sonrakini hiç etkilemez.

### Güvenilirlik Sorumluluğu Kime Ait?

TCP'de kayıp veri protokolün kendisi tarafından fark edilip yeniden gönderilirken, UDP'de bu tamamen **uygulama katmanına** bırakılır. Örneğin DNS, cevap gelmezse kendisi zaman aşımına uğrar ve sorguyu tekrar gönderir — bu UDP'nin değil, DNS uygulamasının sorumluluğudur. Bu tasarım, protokolü son derece hafif tutar ama her uygulamanın kendi güvenilirlik mantığını yazmasını gerektirir.

### Neden Bu Kadar Hızlı?

Handshake yok → gecikme yok. Sıra kontrolü yok → işlem yükü yok. Header küçük → daha az bant genişliği. Bu üç neden birleşince UDP, TCP'ye göre önemli ölçüde daha az gecikmeyle veri iletir — bedeli, hiçbir teslimat garantisi olmamasıdır.

---

## 4. Somut Gündelik Benzetme

UDP'yi **posta kutusuna kartpostal atmak** gibi düşün — TCP'nin "üç kez teyit edilen telefon görüşmesi" benzetmesinin tam zıttı.

Kartpostalı yazarsın, üzerine adresi yazarsın, posta kutusuna atarsın — karşı tarafın evde olup olmadığını, kartpostalın gerçekten ulaşıp ulaşmadığını asla teyit etmezsin (**handshake yok**). Kartpostal yolda kaybolursa hiç kimse sana haber vermez, sen de bunu asla öğrenemezsin — istersen aynı kartpostalı tekrar gönderme kararını **sen** verirsin, posta sistemi değil (**güvenilirlik uygulama katmanında**). Ama bu sistemin büyük avantajı hız ve basitliktir: telefon gibi karşı tarafı aramana, hat meşgulse beklemene gerek yoktur, kartpostalı postaneye bırakır bırakmaz işin biter.

| UDP Kavramı | Kartpostal Benzetmesi |
|---|---|
| Bağlantısız yapı | Karşı tarafı aramadan doğrudan kartpostal atmak |
| Teslimat garantisi yok | Kartpostalın ulaşıp ulaşmadığını asla öğrenmemek |
| Güvenilirlik uygulamada | Gerekirse tekrar göndermeye sen karar verirsin |
| Düşük gecikme | Postaneye bırakır bırakmaz iş biter, bekleme yok |

---

## 5. Saldırgan Senaryosu

Bir saldırgan UDP'yi öncelikle **exploitation** aşamasında, özellikle **amplifikasyon DDoS** saldırılarında kullanır çünkü UDP'nin kaynak IP doğrulaması yapmaması ve bağlantısız yapısı bu saldırıyı mümkün kılar.

**Adım adım senaryo (DNS Amplification):**

1. **Hazırlık:** Saldırgan, açık DNS çözümleyicileri (**open resolver**) tarayarak bulur — `nmap -sU -p 53 hedef_ip_araligi` ile UDP 53 portunun açık olduğu sunucuları listeler.

2. **Spoofing:** Saldırgan bir DNS sorgusu hazırlar ama paketin **kaynak IP adresini kurbanın IP'si olarak sahte** (spoof) yazar — UDP bağlantısız olduğu için hiçbir handshake, hiçbir kaynak doğrulaması yoktur, bu sahtecilik fark edilmeden gönderilebilir.

3. **Amplifikasyon:** Küçük bir DNS sorgusu (örneğin 60 bayt), açık DNS sunucusundan çok daha büyük bir cevap (3000+ bayt) tetikler — bu **amplifikasyon faktörüdür** (50 kata kadar çıkabilir). Sunucu cevabı, sorguyu kimin gönderdiğini sandıysa (kurbanın IP'si) ona gönderir.

4. **DDoS:** Binlerce açık DNS sunucusu aynı anda kurbana devasa miktarda cevap trafiği gönderir — kurban, hiç sorgu göndermediği halde trafiğin altında kalır.

Saldırgan bu tekniği bilinçli seçer çünkü TCP'de bu mümkün değildir — handshake, kaynak IP'nin gerçekten geri dönüş adresinde olduğunu doğrular, UDP'de böyle bir doğrulama hiç yoktur.

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **Amplifikasyon DDoS şüphesi:** Ağ trafiğinde aniden büyük hacimde **gelen** UDP paketi (kaynak port 53, 123, 1900 gibi bilinen amplifikasyon portlarından) görülür, ama kuruluşun bu kadar sorgu gönderdiğine dair hiçbir kayıt yoktur — bu asimetri (az giden sorgu, çok gelen cevap) klasik amplifikasyon işaretidir.

- **UDP Port Tarama şüphesi:** IDS'te tek bir kaynaktan çok sayıda farklı UDP portuna kısa sürede paket gittiği, çoğuna "ICMP port unreachable" cevabı döndüğü görülür — bu `nmap -sU` taramasının tipik imzasıdır.

- **DNS Tunneling şüphesi:** UDP 53 üzerinden normalden çok daha uzun ve sık DNS sorguları, anormal subdomain uzunlukları görülür — bu, UDP'nin (DNS'in taşıyıcısı olarak) veri sızdırma kanalına dönüştürülmüş olabileceğinin işaretidir.

**Hardening:**

- **Ingress/Egress Filtering (BCP38)**, sahte kaynak IP'li UDP paketlerinin ağdan çıkmasını/girmesini engeller — amplifikasyon saldırılarının temelini kurutur
- **Open resolver'ları kapatmak / rate limiting eklemek**, kuruluşun kendi sunucularının amplifikasyon aracı olarak kullanılmasını engeller
- **UDP rate limiting ve anomaly detection**, ani hacim artışlarını erken yakalar

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

UDP'nin zafiyeti, tasarımının doğrudan sonucudur: **kaynak doğrulaması yok, bağlantı durumu yok, güvenilirlik kontrolü yok** — bunların hepsi hız için bilinçli olarak feda edildi, ama bu feda ediş güvenlik açısından bedelini ödetiyor.

- **Kaynak IP doğrulamaması**, IP Spoofing tabanlı tüm amplifikasyon saldırılarının temel nedenidir.
- **Bağlantısız yapı**, saldırganın herhangi bir "durum" takip etmeden binlerce paket fırlatabilmesini kolaylaştırır — TCP'deki gibi her bağlantı için kaynak ayırma zorunluluğu yoktur.
- **Checksum'ın opsiyonel olması** (IPv4'te), bazı eski/yanlış yapılandırılmış sistemlerde veri bütünlüğü kontrolünün atlanmasına izin verebilir.

> **Tarihsel örnek:** 2018'deki **GitHub'a karşı yapılan 1.35 Tbps'lik DDoS saldırısı**, o zamana kadarki en büyük saldırılardan biriydi ve **Memcached Amplification** (UDP 11211 portu üzerinden, amplifikasyon faktörü 50.000 kata kadar) tekniğini kullanmıştı — tamamen UDP'nin kaynak doğrulamaması üzerine kuruluydu.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **UDP vs TCP** | UDP bağlantısız ve garantisizdir, hız önceliklidir; TCP bağlantı-yönelimli ve güvenilirdir, doğruluk önceliklidir |
| **UDP Flood vs Amplification Attack** | UDP Flood doğrudan hedefe paket yağdırır; Amplification, üçüncü taraf sunucuları kullanarak küçük isteği büyük cevaba çevirip hedefe yönlendirir |
| **Open Resolver vs Recursive DNS** | Her open resolver recursive DNS sunucusudur, ama güvenlik açısından sorun olan, bunun herkese açık (kaynak kısıtlaması olmadan) yapılandırılmasıdır |
| **Checksum (UDP) vs Sequence Number (TCP)** | Checksum sadece veri bozulmasını kontrol eder; sequence number ayrıca sıralamayı ve kayıp tespitini sağlar — UDP'de ikincisi yoktur |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"Bir DNS Amplification saldırısında saldırgan neden UDP kullanır, TCP ile bu saldırı neden aynı etkiyle gerçekleştirilemez?"*

<details>
<summary>Model Cevabı</summary>

<br>

DNS Amplification saldırısının temel mekaniği, saldırganın kaynak IP adresini kurbanın IP'si olarak sahtecilik yapmasına (spoofing) dayanır — böylece açık DNS sunucusu büyük cevabı saldırgana değil, doğrudan kurbana gönderir. UDP bağlantısız bir protokol olduğu için hiçbir el sıkışma (handshake) yoktur ve kaynak IP'nin gerçekten o adresten geldiğini doğrulayan hiçbir mekanizma bulunmaz — saldırgan paketi rahatça sahte kaynakla gönderebilir. TCP'de ise bu mümkün değildir çünkü bağlantı kurulmadan önce 3-way handshake gerekir: saldırgan kaynak IP'yi sahte yazsa bile, sunucunun göndereceği SYN-ACK cevabı gerçek (sahte) IP'ye gider, saldırgan bu cevabı asla göremez ve ACK ile handshake'i tamamlayamaz — dolayısıyla bağlantı hiç kurulmaz, spoofing işe yaramaz. Bu yüzden amplifikasyon saldırıları neredeyse istisnasız UDP tabanlı protokoller (DNS, NTP, memcached, SSDP) üzerinden yapılır.

</details>

---

## 10. Hafıza Çapası

**UDP = posta kutusuna kartpostal atmak; karşı tarafı aramadan, teyit beklemeden gönderirsin, ulaşıp ulaşmadığını asla öğrenmezsin — ama tam da bu "kimden geldiğini sorgulamama" özelliği, saldırganın kaynak adresini sahtecilik yaparak devasa DDoS saldırıları (amplification) yapmasının kapısını açar.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **UDP Header boyutu:** 8 bayt (Source Port, Destination Port, Length, Checksum)
- **Protocol numarası (IP header içinde):** UDP = 17
- **Yaygın UDP portları:** 53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP), 1900 (SSDP), 11211 (Memcached)
- **Bağlantı durumu / state machine:** Yok

---

# IP (Internet Protocol)

*Siber Güvenlik Terim Rehberi — Internet/Network Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Internet Protocol
- **Kategori:** Protokol
- **Ait Olduğu Katman:** OSI Katman 3 (Network) / TCP-IP modelinde Internet katmanı
- **Port/Protokol İlişkisi:** IP'nin kendisi port taşımaz — port kavramı bir üst katmanda (Transport: TCP/UDP) devreye girer. IP sadece "hangi cihazdan hangi cihaza" sorusuna cevap verir
- **CVE/CVSS:** Yok — protokolün kendisi değil, IP stack implementasyonlarındaki (işletim sistemi seviyesinde) hatalar CVE alır
- **MITRE ATT&CK:** Dolaylı — T1090 (Proxy), T1571 (Non-Standard Port) gibi teknikler IP seviyesindeki adresleme/yönlendirme mantığını istismar eder

> Not: TCP ve UDP, Transport katmanında "nasıl gönderileceğine" karar verir. IP ise bir katman altta, "nereye gönderileceğine" karar verir. Bu iki katman birbirini tamamlar, biri olmadan diğeri işe yaramaz.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

1970'lerin başında ARPANET büyüdükçe bir sorun ortaya çıktı: ağa bağlı her cihazın, birbirinden bağımsız binlerce farklı ağ üzerinden diğer herhangi bir cihaza nasıl ulaşacağı belirsizdi. Tek bir ağ içinde MAC adresleri yeterliydi ama ağlar arası (**internetworking**) bir adresleme ve yönlendirme sistemine ihtiyaç vardı.

Vint Cerf ve Bob Kahn, TCP'yi tasarlarken bu adresleme/yönlendirme sorununu ayrı bir protokole devretmeye karar verdiler — böylece **IP** doğdu: her cihaza benzersiz bir mantıksal adres (IP adresi) verilecek, paketler bu adrese göre ağdan ağa yönlendirilecekti. IP'den önce ağlar birbirinden izoleydi; IP, "ağların ağı" (internet) kavramını mümkün kılan temel taşıdır. TCP güvenilirliği sağlarken, IP sadece **adresleme ve yönlendirmeyi** üstlendi — bu görev ayrımı bilinçliydi, her protokol tek bir işi iyi yapsın diye.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### IP'nin Görevi: Sadece Adresleme ve Yönlendirme

IP, TCP'nin aksine hiçbir güvenilirlik garantisi vermez — paket kaybolabilir, sırası bozulabilir, IP bunu umursamaz. Tek işi: paketi kaynak adresten hedef adrese, ağlar arasında **en iyi çabayla** (**best-effort delivery**) ulaştırmaya çalışmaktır.

### IP Header'ın Kritik Alanları

| Alan | Görevi |
|---|---|
| Source IP Address | Paketi gönderen cihazın adresi |
| Destination IP Address | Paketin gitmesi gereken adres |
| TTL (Time To Live) | Paketin kaç router'dan (hop) geçebileceğinin sayacı |
| Protocol | Bir üst katmanda hangi protokolün taşındığı (TCP=6, UDP=17, ICMP=1) |
| Fragmentation Alanları (Flags, Fragment Offset) | Büyük paketlerin küçük parçalara bölünüp yeniden birleştirilmesi |
| Header Checksum | IP header'ının bozulup bozulmadığının kontrolü |

### Paketin Yolculuğu — Router'lar Arası Yönlendirme

```
Kaynak Cihaz → Router 1 → Router 2 → Router 3 → ... → Hedef Cihaz
              (TTL: 64) → (TTL: 63) → (TTL: 62) →        (TTL: 60)
```

Her router, paketi bir sonraki hop'a göndermeden önce **routing table**'ına (yönlendirme tablosu) bakar ve "bu hedef IP'ye en kısa/en uygun yol hangisi" sorusuna cevap verir. Her geçişte **TTL değeri bir azalır** — bu, paketin sonsuza kadar ağda dolaşmasını (routing loop) engellemek için konmuş bir güvenlik mekanizmasıdır. TTL sıfıra düşerse paket düşürülür ve gönderen tarafa bir ICMP "Time Exceeded" mesajı gönderilir.

### Neden "Best-Effort" (En İyi Çaba)?

IP, paketin ulaşıp ulaşmadığını asla kontrol etmez, kayıp paketi asla yeniden göndermez. Bu sorumluluk tamamen bir üst katmandaki TCP'ye (isteniyorsa) bırakılmıştır. IP'nin bu kadar "sorumsuz" tasarlanmasının nedeni basitlik ve hızdır — her router milyonlarca paketi saniyede işlerken, her paket için güvenilirlik kontrolü yapması sistemi felç ederdi.

### IPv4 vs IPv6 Adresleme Mantığı

IPv4, 32 bitlik adresler kullanır (örnek: `192.168.1.1`) ve toplam yaklaşık 4.3 milyar benzersiz adres sunar — bu sayı, internete bağlı cihaz sayısı arttıkça yetersiz kalmaya başladı. IPv6, 128 bitlik adresler kullanarak (örnek: `2001:0db8::1`) bu sorunu pratik olarak sonsuza kadar çözer.

---

## 4. Somut Gündelik Benzetme

IP'yi **bir şehirdeki ev adresi sistemi ve kargo yönlendirme ağı** gibi düşün.

Her evin benzersiz bir adresi vardır (**IP adresi**) — bu adres olmadan kimse sana bir şey gönderemez. Bir kargo şirketi, paketi doğrudan senin evine değil, önce bölge dağıtım merkezine, oradan şehir merkezine, oradan senin mahallene gönderir — her aktarma noktası bir **router**'dır ve paket üzerindeki "bu paket en fazla 20 aktarmadan geçebilir" notu (**TTL**) sonsuza kadar kaybolmuş paketlerin şehirler arası dolaşıp durmasını engeller. Kargo şirketi paketin gerçekten ulaşıp ulaşmadığını **garanti etmez** — sadece elinden gelenin en iyisini yapar (**best-effort**); paket kaybolursa bunu fark edip tekrar göndermek sana (yani üst katman TCP'ye) kalmıştır. Eğer paket çok büyükse kargo şirketi onu birden fazla küçük kutuya böler ve her kutunun üzerine "5 kutunun 2.'si" yazar — bu **fragmentation**'dır, hedefte tekrar birleştirilir.

| IP Kavramı | Kargo/Adres Benzetmesi |
|---|---|
| IP Adresi | Evin benzersiz posta adresi |
| Router | Bölge/şehir dağıtım merkezi |
| TTL | "En fazla 20 aktarmadan geçebilir" notu |
| Best-effort delivery | Kargo şirketinin garanti vermemesi |
| Fragmentation | Büyük paketin küçük kutulara bölünmesi |

---

## 5. Saldırgan Senaryosu

Bir saldırgan IP'yi hem **keşif** hem **exploitation** hem de **iz gizleme (evasion)** aşamalarında kullanır çünkü IP'nin kaynak doğrulaması yapmaması ve yönlendirme mantığı doğrudan istismar edilebilir.

**Adım adım senaryo:**

1. **Keşif:** Saldırgan `traceroute hedef_ip` (veya Windows'ta `tracert`) çalıştırarak hedefe giden yoldaki tüm router'ları TTL değerini kademeli artırarak (1, 2, 3...) tespit eder — her router paketi düşürdüğünde ICMP "Time Exceeded" mesajı gönderir, bu da ağ topolojisini ortaya çıkarır.

2. **Keşif Derinleştirme:** `nmap -O hedef_ip` ile IP paketlerindeki TTL ve header özelliklerinden **işletim sistemi parmak izi** (**OS fingerprinting**) çıkarır — farklı işletim sistemleri farklı varsayılan TTL değerleri (Linux genelde 64, Windows genelde 128) kullanır.

3. **IP Spoofing — Exploitation:** Saldırgan, gönderdiği paketlerin kaynak IP adresini sahte yazar (`hping3 -a sahte_ip hedef_ip`) — IP bu doğrulamayı hiç yapmadığı için sahte kaynak adresi hiçbir engelle karşılaşmadan ağda ilerler. Bu, hem kimliğini gizlemek hem de amplifikasyon DDoS saldırılarında kurbanı hedef göstermek için kullanılır.

4. **Evasion — Fragmentation Saldırısı:** Saldırgan paketleri bilerek küçük, garip parçalara böler (`nmap -f`) çünkü bazı eski IDS/IPS sistemleri parçalanmış paketleri doğru şekilde yeniden birleştirip analiz edemez — bu, imza tabanlı tespitten kaçmanın klasik bir yoludur.

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **IP Spoofing şüphesi:** Firewall loglarında, iç ağa ait bir IP adresinden geldiği iddia edilen ama paketin **dış arayüzden** geldiği görülür — bu coğrafi/topolojik tutarsızlık spoofing'in klasik işaretidir. Ayrıca TTL değerinin, o IP'nin normalde göstermesi gereken değerden farklı çıkması ek bir ipucu verir.

- **Traceroute/OS Fingerprinting şüphesi:** IDS'te art arda artan TTL değerleriyle gönderilen ICMP paketleri, ya da tek kaynaktan gelen ve anormal header kombinasyonları taşıyan taramalar görülür — Suricata kuralı örneği: `alert icmp any any -> $HOME_NET any (itype:11; msg:"Possible traceroute activity";)`

- **Fragmentation saldırısı şüphesi:** Ağ trafiğinde normalden çok daha fazla parçalanmış (fragmented) paket, özellikle çok küçük ve tekrarlayan fragment boyutları görülür — bu, IDS'i atlatma girişiminin işareti olabilir.

**Hardening:**

- **Ingress/Egress Filtering (BCP38)**, sahte kaynak IP'li paketlerin ağdan çıkmasını/girmesini engeller — IP Spoofing'in temelini kurutur
- **IDS/IPS'te fragment reassembly (yeniden birleştirme) desteği**, parçalanmış paketleri analiz etmeden önce birleştirerek evasion girişimlerini engeller
- **ICMP rate limiting**, traceroute ve ping tabanlı keşif faaliyetlerini yavaşlatır, tamamen engellemese de saldırganın işini zorlaştırır

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

IP'nin zafiyeti, tasarımının doğrudan sonucudur: **kaynak adresinin doğrulanmaması** ve **best-effort teslimat felsefesi**, güvenlik değil verimlilik önceliğiyle tasarlandı.

- **Kaynak IP doğrulamaması**, IP Spoofing'in ve buna dayalı tüm amplifikasyon/yansıtma (reflection) saldırılarının temel nedenidir — protokol, "bu paket gerçekten iddia ettiği adresten mi geldi" sorusunu hiç sormaz.
- **Fragmentation mekanizması**, kötü amaçla yeniden birleştirildiğinde bellek taşması (buffer overflow) yaratacak şekilde manipüle edilebilir.
- **TTL'in tahmin edilebilir/varsayılan değerlere sahip olması**, işletim sistemi parmak izi çıkarmayı (fingerprinting) kolaylaştırır, bu da saldırganın hedefe özel exploit seçmesine yardımcı olur.

> **Tarihsel örnek:** 1997'deki **"Teardrop Attack"**, IP'nin fragmentation mekanizmasındaki bir zafiyeti istismar ediyordu — saldırgan bilerek üst üste binen (overlapping) fragment offset değerleri gönderiyor, bazı işletim sistemleri bunları yeniden birleştirirken çöküyordu (DoS). Bu saldırı, IP'nin fragment yeniden birleştirme mantığına duyulan "güvenin" ne kadar tehlikeli olabileceğinin erken bir kanıtıydı.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **IP vs MAC Adresi** | IP, Network katmanında mantıksal ve değişebilir bir adrestir (ağlar arası yönlendirme için); MAC, Data Link katmanında fiziksel ve sabit bir donanım adresidir (yerel ağ içinde) |
| **IPv4 vs IPv6** | IPv4, 32 bit adres uzayı sunar ve tükenme sorunu yaşar; IPv6, 128 bit adres uzayı sunarak bu sorunu pratik olarak ortadan kaldırır, ayrıca yerleşik güvenlik (IPSec desteği) ile tasarlanmıştır |
| **IP vs TCP/UDP** | IP "nereye" sorusuna (adresleme, yönlendirme) cevap verir; TCP/UDP "nasıl" sorusuna (güvenilir mi hızlı mı) cevap verir — ikisi farklı katmanlarda ve farklı görevlerdedir |
| **Public IP vs Private IP** | Public IP, internette doğrudan erişilebilir ve benzersizdir; Private IP (10.x, 192.168.x gibi) sadece yerel ağ içinde geçerlidir ve NAT ile internete çıkar |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"Bir saldırganın IP Spoofing ile TCP tabanlı bir bağlantıyı tam olarak ele geçirmesi neden UDP'ye göre çok daha zordur? IP seviyesinde ne oluyor?"*

<details>
<summary>Model Cevabı</summary>

<br>

IP seviyesinde spoofing'in kendisi kolaydır — saldırgan paketin kaynak IP alanına istediği adresi yazabilir çünkü IP bu alanı doğrulamaz. Ancak TCP, IP'nin üzerine bir güvenilirlik katmanı (handshake) eklediği için, saldırganın sahte kaynak IP ile gönderdiği SYN paketine karşılık sunucunun göndereceği SYN-ACK cevabı, saldırgana değil, sahte olarak kullanılan gerçek IP sahibine gider. Saldırgan bu SYN-ACK içindeki sequence number'ı görmediği için handshake'i tamamlayacak doğru ACK'i gönderemez — bağlantı kurulamaz. Bunu aşmanın tek yolu, sequence number'ı önceden tahmin etmek (blind spoofing) ki modern sistemlerde bu numaralar kriptografik olarak rastgele üretildiği için pratikte imkansıza yakındır. UDP'de ise hiçbir handshake, hiçbir sequence number beklentisi olmadığı için saldırgan tek bir paketle, cevabı hiç görmeden bile etkili bir saldırı (örneğin amplifikasyon) gerçekleştirebilir — IP seviyesindeki spoofing zafiyeti UDP ile doğrudan, TCP ile ise sadece dolaylı ve zor şekilde istismar edilebilir.

</details>

---

## 10. Hafıza Çapası

**IP = şehirdeki adres sistemi; her evin (cihazın) benzersiz bir adresi vardır, kargo şirketi (router'lar) paketi bu adrese göre yönlendirir ama teslimatı garanti etmez — ve hiç kimse kargonun üzerindeki "gönderen adresi"nin gerçek olup olmadığını kontrol etmez, saldırganın sahte adres yazabilmesinin sebebi tam olarak budur.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **OSI Katmanı:** 3 (Network) — TCP/IP modelinde: Internet katmanı
- **IPv4 adres uzunluğu:** 32 bit
- **IPv6 adres uzunluğu:** 128 bit
- **IP Header'da Protocol alanı:** TCP = 6, UDP = 17, ICMP = 1
- **Varsayılan TTL değerleri (yaklaşık):** Linux/Unix = 64, Windows = 128, bazı network cihazları = 255

---

# IPv4 ve IPv6

*Siber Güvenlik Terim Rehberi — Internet/Network Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Internet Protocol version 4 / Internet Protocol version 6
- **Kategori:** Protokol (IP'nin iki farklı versiyonu)
- **Ait Olduğu Katman:** OSI Katman 3 (Network) / TCP-IP modelinde Internet katmanı
- **Port/Protokol İlişkisi:** İkisi de port taşımaz — port bilgisi bir üst katmanda (TCP/UDP) bulunur
- **CVE/CVSS:** Yok (protokolün kendisi değil, implementasyonları CVE alır) — ama IPv6'nın göreceli yeniliği, bazı işletim sistemi/ağ cihazı IPv6 stack'lerinde daha az test edilmiş, dolayısıyla daha fazla implementasyon zafiyeti anlamına gelir
- **MITRE ATT&CK:** Dolaylı — T1090 (Proxy) ve keşif teknikleri, IPv4/IPv6'nın farklı adresleme mantığına göre farklı şekillerde uygulanır

> Not: Bir önceki dosyada IP'nin genel çalışma mantığı (adresleme, routing, TTL, fragmentation) işlendi. Bu dosya, o genel mantığın **iki farklı versiyonu** arasındaki kritik farkları ve her birinin kendine özgü güvenlik risklerini derinlemesine inceler.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

IPv4, 1981'de standartlaştırıldığında 32 bitlik adres alanı (yaklaşık 4.3 milyar adres) o dönem için "asla tükenmeyecek kadar büyük" görünüyordu — internete bağlı cihaz sayısı o zamanlar sadece birkaç bin araştırma bilgisayarıydı. Ama 1990'ların sonuna gelindiğinde, kişisel bilgisayarların ve internetin patlayan büyümesiyle mühendisler bir gerçekle yüzleşti: bu adres havuzu tükenecekti.

IETF, bu soruna karşı iki çözüm geliştirdi: kısa vadeli yama olarak **NAT** (Network Address Translation — birden fazla cihazın tek bir public IP'yi paylaşmasını sağlar) ve uzun vadeli gerçek çözüm olarak **IPv6**'yı (1998'de standartlaştı) tasarladı. IPv6'nın amacı sadece adres sayısını artırmak değildi — aynı zamanda IPv4'ün eksik kaldığı noktaları (yerleşik güvenlik desteği, basitleştirilmiş header, otomatik adres yapılandırma) da kapatmaktı. 2011'de IANA'nın elindeki son IPv4 blokları resmen tükendi — bu, IPv6'ya geçişin artık teorik değil, zorunlu hale geldiği andı.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### Adres Yapısı Karşılaştırması

**IPv4** 32 bitlik bir adrestir, 4 grup halinde ondalık gösterilir:
```
192.168.1.1
```
Toplam adres sayısı: 2³² ≈ 4.3 milyar

**IPv6** 128 bitlik bir adrestir, 8 grup halinde onaltılık (hexadecimal) gösterilir:
```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```
Toplam adres sayısı: 2¹²⁸ ≈ 340 undesilyon (pratikte tükenmesi imkansız bir sayı)

IPv6 adresleri genelde kısaltılarak yazılır — ardışık sıfır grupları `::` ile bir kez temsil edilebilir: `2001:db8::8a2e:370:7334`

### Header Yapısındaki Fark — Basitleştirme Felsefesi

IPv4 header'ı zamanla eklenen pek çok opsiyonel alan yüzünden karmaşıklaşmıştı (fragmentation alanları, options, checksum). IPv6 bunu bilinçli olarak sadeleştirdi:

| Özellik | IPv4 | IPv6 |
|---|---|---|
| Header boyutu | Değişken (20-60 bayt) | Sabit (40 bayt) |
| Checksum | Var (her router'da yeniden hesaplanır) | Yok (üst katmana bırakıldı, router yükü azaltıldı) |
| Fragmentation | Router'lar tarafından yapılabilir | Sadece kaynak cihaz tarafından yapılır (router'lar yapmaz) |
| Adres yapılandırma | Manuel veya DHCP | DHCP veya **SLAAC** (Stateless Address Autoconfiguration — cihaz kendi adresini otomatik üretir) |
| Güvenlik (IPSec) | Opsiyonel, sonradan eklendi | Tasarımda yerleşik olarak düşünüldü (pratikte yine opsiyonel kullanılır) |
| Broadcast | Var (ağdaki herkese paket gönderme) | Yok — yerine **Multicast** ve **Anycast** kullanılır |

### NAT'ın Rolü — IPv4'ün Yama Çözümü

IPv4 dünyasında bir ev/ofis ağındaki onlarca cihaz genelde tek bir public IP'yi paylaşır — router bu paylaşımı **NAT (Network Address Translation)** ile yönetir: iç ağdaki her cihazın private IP'sini (10.x, 192.168.x) dışarıya çıkarken tek bir public IP'ye çevirir, hangi cevabın hangi iç cihaza ait olduğunu port numaralarını takip ederek hatırlar.

IPv6'da adres bolluğu o kadar fazladır ki her cihaza (telefon, buzdolabı, sensör) doğrudan **benzersiz bir global adres** verilebilir — NAT'a teorik olarak gerek kalmaz, her cihaz doğrudan internete "görünür" olabilir. Bu, güvenlik açısından hem avantaj hem risktir: NAT'ın yarattığı "gizli" iç ağ katmanı artık yoktur.

### SLAAC — IPv6'ya Özgü Otomatik Adresleme

IPv6'da bir cihaz ağa bağlandığında, router'dan gelen **Router Advertisement (RA)** mesajlarını dinleyerek kendi adresini kendisi oluşturabilir (SLAAC) — bu, DHCP'ye benzer bir amaca hizmet eder ama merkezi bir sunucuya ihtiyaç duymaz, cihaz kendi MAC adresini (veya rastgele bir değeri) kullanarak adresini türetir.

---

## 4. Somut Gündelik Benzetme

Bunu **eski bir kasabanın telefon numarası sistemi (IPv4) ile yeni kurulan bir megakentin adres sistemi (IPv6)** gibi düşün.

Eski kasabada (**IPv4**) sadece 4.3 milyar telefon numarası basılabilecek kadar küçük bir defter vardı — kasaba büyüdükçe numaralar tükenmeye başladı, bu yüzden aynı numarayı birden fazla eve paylaştırmak zorunda kaldılar (**NAT**): bir apartmanın tek bir ana numarası vardır, gelen aramalar "dahili" numaralarla (portlarla) doğru daireye yönlendirilir, dışarıdan arayan kişi hangi daireyle konuştuğunu tam olarak bilemez. Yeni megakentte (**IPv6**) ise o kadar geniş bir numaralandırma sistemi kuruldu ki (340 undesilyon numara) her eve, her odaya, hatta her prize bile ayrı ve doğrudan bir numara verilebiliyor (**global unicast adresler**) — kimse paylaşımlı numara kullanmak zorunda kalmıyor, herkes doğrudan aranabiliyor. Yeni kentte ayrıca evler taşındığında (yeni bir ağa bağlandığında) kendi adreslerini otomatik olarak öğrenip kayıt oluyorlar (**SLAAC**), eski kasabadaki gibi bir memura (DHCP sunucusuna) gitmelerine bile gerek kalmıyor.

| IPv4/IPv6 Kavramı | Kasaba/Kent Benzetmesi |
|---|---|
| IPv4 adres kıtlığı | Eski kasabanın küçük telefon defteri |
| NAT | Apartmanın tek ana numarası + dahili yönlendirme |
| IPv6 bol adres alanı | Megakentin her prize kadar uzanan numaralandırması |
| SLAAC | Evin kendi adresini otomatik öğrenmesi |
| IPv4 "gizliliği" (NAT arkasında) | Dışarıdan sadece ana numara görünür, dahili gizlidir |
| IPv6 doğrudan erişilebilirlik | Her cihaz doğrudan aranabilir, arada gizleyici katman yok |

---

## 5. Saldırgan Senaryosu

Bir saldırgan, hedef ağın IPv4 mi IPv6 mı (ya da her ikisini birden, **dual-stack**) kullandığını **keşif** aşamasında mutlaka belirler çünkü saldırı yüzeyi ve araçlar tamamen farklıdır.

**Adım adım senaryo:**

1. **Keşif — Protokol Tespiti:** Saldırgan `nmap -6 hedef_domain` ile hedefin IPv6 desteği olup olmadığını kontrol eder. Pek çok kurum IPv4 güvenlik duvarlarını sıkı yapılandırırken **IPv6 trafiğini unutur veya yeterince filtrelemez** — bu, saldırgan için bilinçli olarak aranan bir zayıf nokta haline gelir.

2. **IPv6 Tarama Zorluğunu Aşma:** IPv4'te `nmap -sn 192.168.1.0/24` gibi tüm alt ağı (256 adres) taramak saniyeler sürer, ama IPv6'da aynı alt ağ 2⁶⁴ adres içerebilir — bu, kaba kuvvetle taramayı imkansız hale getirir. Bu yüzden saldırgan farklı bir yaklaşım kullanır: **NDP (Neighbor Discovery Protocol)** trafiğini dinleyerek (`ndpscan` veya `Wireshark` ile) ağda gerçekten aktif olan IPv6 adreslerini pasif olarak toplar.

3. **Dual-Stack İstismarı:** Saldırgan, hedefin IPv4 firewall'ı sıkı ama IPv6 firewall'ı zayıf/hiç yapılandırılmamışsa, IPv4 üzerinden engellenen bir bağlantıyı **IPv6 üzerinden tünelleyerek** (`6to4`, `Teredo` gibi tünelleme teknikleriyle) güvenlik duvarını atlar — bu teknik, "IPv4'te kapalı olan kapı IPv6'da açık unutulmuş" mantığına dayanır.

4. **NDP Spoofing — Lateral Movement:** Yerel ağ içinde saldırgan, IPv4'teki ARP Spoofing'in IPv6 karşılığı olan **NDP Spoofing / Router Advertisement (RA) Spoofing** saldırısını yapar (`parasite6` aracıyla) — sahte bir Router Advertisement göndererek kendini "router" gibi tanıtır, tüm IPv6 trafiğini kendi üzerinden geçirir (MITM).

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **Unutulmuş IPv6 trafiği şüphesi:** Firewall loglarında IPv4 kuralları detaylı ama IPv6 trafiğinin hiç loglanmadığı veya "allow all" gibi gevşek bir kuralla geçtiği görülür — bu, kurumun "dual-stack kör noktası" olduğunun işaretidir, mutlaka ayrı bir IPv6 güvenlik politikası denetimi gerektirir.

- **NDP/RA Spoofing şüphesi:** Ağda beklenmedik sayıda **Router Advertisement** mesajı, ya da bilinen router dışında başka bir cihazdan gelen RA paketleri görülür — Suricata kuralı örneği: `alert icmp6 any any -> any any (icmp6type:134; msg:"Unexpected Router Advertisement detected";)`

- **Tünelleme (6to4/Teredo) şüphesi:** Normal IPv4 trafiği içinde protokol alanı 41 (IPv6-in-IPv4 encapsulation) olan paketler görülür — bu, birinin IPv6 trafiğini IPv4 üzerinden gizlice taşıdığının işareti olabilir ve genelde politika ihlalidir.

**Hardening:**

- **RA Guard**, switch seviyesinde sadece yetkili router'lardan gelen Router Advertisement mesajlarını kabul eder, NDP Spoofing'i engeller
- **IPv6 firewall kurallarının IPv4 ile eşit sıkılıkta yapılandırılması**, dual-stack kör noktasını kapatır — "kullanmıyoruz" diye IPv6'yı tamamen kapatmak da bir seçenektir ama bu, yanlışlıkla açık bırakılan tünelleme protokollerini fark etmeyi zorlaştırabilir
- **Gereksiz tünelleme protokollerinin (6to4, Teredo, ISATAP) devre dışı bırakılması**, IPv4 güvenlik kontrollerinin IPv6 trafiğiyle atlatılmasını engeller

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

Her iki protokolün de kendine özgü, doğuştan gelen zayıflıkları vardır.

**IPv4 tarafında:** Adres kıtlığının zorunlu kıldığı NAT, aslında yanlışlıkla bir "güvenlik" hissi yaratır — pek çok kurum NAT'ı gerçek bir güvenlik katmanı sanır, oysa NAT bir adresleme çözümüdür, güvenlik mekanizması değildir; port yönlendirme (port forwarding) yanlış yapılandırıldığında iç ağ yine de doğrudan erişilebilir hale gelir.

**IPv6 tarafında:** NDP (Neighbor Discovery Protocol), tıpkı IPv4'teki ARP gibi hiçbir kimlik doğrulama içermeden tasarlandı — bu, NDP Spoofing'in doğrudan nedenidir. Ayrıca kurumların IPv6'yı "kullanmıyoruz" diye tamamen görmezden gelmesi, işletim sistemlerinin IPv6'yı varsayılan olarak açık tutması gerçeğiyle birleşince ciddi bir kör nokta yaratır — cihaz IPv6 konuşabiliyor ama kimse onu izlemiyor.

> **Tarihsel örnek:** Pek çok kurumsal sızma testinde (ve gerçek saldırıda) tekrar eden bir örüntü: saldırganlar IPv4 güvenlik duvarını tamamen sağlam bulup, **aynı ağdaki hiç izlenmeyen IPv6 trafiği** üzerinden içeri sızmayı başarır — bu o kadar yaygın bir teknik haline geldi ki SANS ve benzeri kuruluşlar "IPv6, kurumsal ağların en çok göz ardı edilen saldırı yüzeyidir" uyarısını sıkça tekrarlar.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **NAT vs Firewall** | NAT, adres paylaşımı/çevirisi yapar; firewall, trafiği kurallara göre engeller/izin verir — NAT bir güvenlik aracı değildir, yan etkisi güvenlik hissi yaratmasıdır |
| **ARP (IPv4) vs NDP (IPv6)** | ARP, IPv4'te IP-MAC eşleşmesi yapar; NDP, IPv6'da aynı işi (ve daha fazlasını, ör. router keşfi) yapar — ikisi de kimlik doğrulaması içermez, ikisi de spoofing'e açıktır |
| **DHCP vs SLAAC** | DHCP, merkezi bir sunucudan adres talep eder ve genelde her iki protokolde de kullanılabilir; SLAAC, sadece IPv6'ya özgüdür ve cihazın adresini merkezi sunucu olmadan kendi kendine türetmesini sağlar |
| **Public IP vs Private IP (IPv4 bağlamında)** | Public IP internette doğrudan görünür ve benzersizdir; Private IP sadece yerel ağda geçerlidir ve NAT ile dışarı çıkar — IPv6'da bu ayrım adres bolluğu yüzünden büyük ölçüde ortadan kalkar |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"Bir kurum ağında hem IPv4 hem IPv6 çalışıyor (dual-stack) ve IPv4 firewall kuralları çok sıkı yapılandırılmış. Bir saldırgan bu ortamda neden hâlâ başarılı olabilir, ve sen bir SOC analisti olarak bunu önlemek için ilk kontrol edeceğin şey ne olurdu?"*

<details>
<summary>Model Cevabı</summary>

<br>

Dual-stack ortamlarda güvenlik ekiplerinin en sık yaptığı hata, IPv4 için detaylı ve sıkı firewall politikaları yazarken IPv6 trafiğini ya tamamen unutmak ya da "kullanmıyoruz zaten" varsayımıyla gevşek bırakmaktır — oysa modern işletim sistemleri (Windows, Linux, macOS) IPv6'yı varsayılan olarak etkin tutar ve otomatik yapılandırır (SLAAC ile). Bu durumda bir saldırgan, IPv4 üzerinden engellenen bir bağlantıyı IPv6 üzerinden deneyebilir çünkü aynı güvenlik kontrolleri bu protokolde uygulanmamış olabilir; hatta saldırgan IPv6 trafiğini bir IPv4 tüneli (6to4/Teredo) içine gizleyerek IPv4 seviyesindeki izleme sistemlerini de atlatabilir. Bir SOC analisti olarak ilk kontrol edeceğim şey, firewall ve IDS/IPS kurallarının **IPv6 için de IPv4 ile eşdeğer kapsamda** yazılıp yazılmadığı olurdu — yani "IPv4 kuralı var, IPv6 karşılığı da var mı" sorusunu her kural için tek tek sormak, ayrıca ağda gerçekten hangi cihazların IPv6 konuştuğunu pasif trafik analiziyle (NDP mesajlarını dinleyerek) tespit etmek olurdu.

</details>

---

## 10. Hafıza Çapası

**IPv4 = eski kasabanın küçük telefon defteri, apartmanların tek ana numarayı paylaşması (NAT) zorunluluğundan doğdu; IPv6 = her prize kadar uzanan yeni kentin sınırsız numaralandırması — ama unutma: saldırganlar sıkı korunan IPv4 kapısını değil, kimsenin bakmadığı açık IPv6 penceresini arar.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **IPv4 adres uzunluğu:** 32 bit → yaklaşık 4.3 milyar adres
- **IPv6 adres uzunluğu:** 128 bit → yaklaşık 340 undesilyon adres
- **IPv4 header boyutu:** Değişken, 20-60 bayt
- **IPv6 header boyutu:** Sabit, 40 bayt
- **IPv6-in-IPv4 encapsulation protocol numarası:** 41
- **IPv4 son adres tükenmesi (IANA):** 2011

---

# ICMP (Internet Control Message Protocol)

*Siber Güvenlik Terim Rehberi — Internet/Network Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Internet Control Message Protocol
- **Kategori:** Protokol
- **Ait Olduğu Katman:** OSI Katman 3 (Network) / TCP-IP modelinde Internet katmanı
- **Port/Protokol İlişkisi:** ICMP port kullanmaz — TCP/UDP'nin aksine bir "uygulama" taşımaz, doğrudan IP üzerinde çalışan bir kontrol/hata bildirim protokolüdür
- **CVE/CVSS:** Yok — protokolün kendisi değil, ICMP işleyen implementasyonlardaki hatalar (ör. eski Windows Ping of Death zafiyeti) CVE alır
- **MITRE ATT&CK:** T1046 (Network Service Discovery) keşif aşamasında; T1498 (Network Denial of Service) altında ICMP flood/amplifikasyon teknikleri; T1571 altında ICMP tünelleme ile veri sızdırma

> Not: TCP, UDP ve IP birer "veri taşıma" protokolüyken, ICMP bambaşka bir işe hizmet eder: veri taşımaz, sadece **ağdaki durumu bildirir**. Bu farkı anlamak, ICMP'nin neden hem bu kadar yararlı hem de bu kadar istismar edilebilir olduğunun anahtarıdır.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

IP tasarlanırken bilinçli olarak "sorumsuz" bırakılmıştı — paket kaybolursa, hedefe ulaşmazsa, bir router çok meşgulse, IP'nin kendisi bu durumları göndericiye asla bildirmiyordu. Bu, ciddi bir kör nokta yaratıyordu: bir yönetici veya sistem, ağda bir sorun olduğunu anlamanın hiçbir yolunu bulamıyordu, paketler sessizce kayboluyordu.

Jon Postel 1981'de bu boşluğu kapatmak için ICMP'yi tasarladı: amaç, ağdaki cihazların (özellikle router'ların) birbirine "bu paket ulaşmadı", "bu hedef erişilemez", "yavaşla, seni boğuyorum" gibi **kontrol ve hata mesajları** gönderebilmesini sağlamaktı. ICMP, TCP/UDP gibi bir veri taşıyıcı değildir — IP'nin eksik bıraktığı "geri bildirim" mekanizmasını tamamlayan bir **teşhis ve sinyalleşme protokolüdür**. `ping` ve `traceroute` gibi en temel ağ teşhis araçlarının var olabilmesinin nedeni doğrudan ICMP'dir.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### ICMP Mesaj Yapısı — Type ve Code

ICMP header'ı TCP/UDP'ye göre çok daha basittir; temel olarak iki alan taşır:

| Alan | Görevi |
|---|---|
| Type | Mesajın genel kategorisi (ör. Echo Request, Destination Unreachable) |
| Code | Type içindeki alt detay (ör. "Destination Unreachable" için "Network Unreachable" mı "Port Unreachable" mı) |
| Checksum | Mesajın bozulup bozulmadığının kontrolü |

En sık karşılaşılan Type değerleri:

| Type | Anlamı | Kullanım Alanı |
|---|---|---|
| 0 | Echo Reply | `ping` cevabı |
| 8 | Echo Request | `ping` isteği |
| 3 | Destination Unreachable | Hedefe ulaşılamadı |
| 11 | Time Exceeded | TTL sıfırlandı (traceroute'un temeli) |
| 5 | Redirect | Daha iyi bir yol var, router yönlendiriyor |

### Ping (Echo Request/Reply) — En Temel ICMP Kullanımı

```
İstemci → ICMP Echo Request (Type 8)  → Hedef
İstemci ← ICMP Echo Reply (Type 0)     ← Hedef
```

Hiçbir handshake yok, hiçbir port yok — istemci sadece "buradasın mı" diye sorar, hedef "evet buradayım" diye cevaplar. Bu basitlik, ICMP'nin hem gücü hem de zafiyetinin kaynağıdır.

### Traceroute — TTL ile Yol Haritası Çıkarma

`traceroute`, ICMP'nin "Time Exceeded" mesajını akıllıca kullanan bir tekniktir:

```
1. TTL=1 ile paket gönder  → İlk router TTL'i sıfırlar → "Time Exceeded" (Type 11) cevabı gelir → 1. router tespit edilir
2. TTL=2 ile paket gönder  → İkinci router TTL'i sıfırlar → 2. router tespit edilir
3. TTL=3 ile devam...      → Hedefe ulaşana kadar bu tekrarlanır
```

Her adımda TTL bir artırılır, bu da paketin bir router daha ileri gitmesine ve o router'ın kimliğinin ortaya çıkmasına neden olur — traceroute, IP'nin TTL mekanizmasıyla ICMP'nin hata bildirim mekanizmasının birlikte çalışmasının bir ürünüdür.

### Destination Unreachable — Neden Erişilemedi Bilgisi

Bir paket hedefe ulaşamazsa (port kapalı, ağ yok, firewall engelledi), ilgili router veya hedef cihaz, gönderene **Type 3 (Destination Unreachable)** mesajı yollar, Code alanı ile de nedenini belirtir (Code 0 = Network Unreachable, Code 3 = Port Unreachable). Bu bilgi, hem meşru sorun giderme için hem de saldırganın ağ haritası çıkarması için aynı derecede değerlidir.

---

## 4. Somut Gündelik Benzetme

ICMP'yi **bir binadaki yangın alarmı ve interkom sistemi** gibi düşün — kargo (veri) taşımaz, sadece durum bildirir.

Kargo şirketi (TCP/UDP/IP) paketleri taşırken, binadaki interkom sistemi (**ICMP**) hiç paket taşımaz, sadece "bu kat kapalı", "asansör arızalı, buradan geçemezsin", "sesimi duyuyor musun" gibi anonslar yapar. Sen interkomdan "beni duyuyor musun" diye sorduğunda (**Echo Request**), karşı taraf "evet duyuyorum" diye cevap verir (**Echo Reply**) — bu tam olarak `ping`'in yaptığı şeydir. Eğer bir kata paket göndermeye çalışırsan ve o kat kapalıysa, güvenlik görevlisi sana interkomdan "o kata giremezsin, kapı kilitli" diye haber verir (**Destination Unreachable**) — bu bilgi hem senin (meşru kullanıcı) işine yarar hem de binayı kötü niyetle haritalamaya çalışan birinin işine yarar, çünkü hangi katların "var" hangi katların "kapalı" olduğunu ona da söyler.

| ICMP Kavramı | Bina/İnterkom Benzetmesi |
|---|---|
| Echo Request/Reply (ping) | "Beni duyuyor musun" - "Evet duyuyorum" |
| Destination Unreachable | "O kata giremezsin, kapı kilitli" anonsu |
| Time Exceeded (traceroute) | Her katta "buraya kadar geldin" işareti bırakmak |
| Redirect | "Bu yol kapalı, öbür merdivenden git" yönlendirmesi |

---

## 5. Saldırgan Senaryosu

Bir saldırgan ICMP'yi hem **keşif** hem **DoS/exploitation** hem de **veri sızdırma (exfiltration)** aşamalarında kullanır çünkü ICMP genelde "zararsız teşhis trafiği" sayılıp firewall'larda gevşek bırakılır.

**Adım adım senaryo:**

1. **Keşif — Host Discovery:** Saldırgan `nmap -sn hedef_ag/24` (ping sweep) ile ağdaki hangi cihazların canlı olduğunu ICMP Echo Request göndererek tespit eder — cevap veren her cihaz "burada bir sistem var" bilgisini verir, bu saldırının ilk adımıdır çünkü hedef listesi olmadan hiçbir şey yapılamaz.

2. **Keşif Derinleştirme — Ağ Haritalama:** `traceroute hedef_ip` veya `tracert` ile hedefe giden yoldaki tüm router'ları, dolayısıyla ağ topolojisini çıkarır — bu bilgi, saldırganın "hangi güvenlik katmanlarından geçmesi gerektiğini" anlamasını sağlar.

3. **DoS — ICMP Flood:** Saldırgan `hping3 --icmp --flood hedef_ip` ile devasa miktarda Echo Request göndererek hedefin işlem gücünü ve bant genişliğini tüketmeye çalışır (**Ping Flood**). Daha gelişmiş bir versiyonu olan **Smurf Attack**'ta, saldırgan Echo Request'i bir ağın **broadcast adresine**, kaynak IP'yi kurbanın IP'si gibi sahte göstererek gönderir — ağdaki tüm cihazlar aynı anda kurbana cevap yağdırır (amplifikasyon).

4. **Persistence/Exfiltration — ICMP Tunneling:** Sızma sonrası saldırgan, firewall'ların genelde ICMP'yi çok az denetlediğini bildiği için, çalınan veriyi ICMP Echo paketlerinin **veri (payload)** alanına gizleyerek dışarı sızdırır (`icmpsh` veya `ptunnel` aracıyla) — bu, "zararsız ping trafiği" gibi görünen ama aslında veri kaçırma kanalı olan klasik bir tekniktir.

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **Ping Sweep şüphesi:** IDS'te tek bir kaynaktan kısa sürede, sıralı IP aralığına (192.168.1.1, .2, .3...) giden yoğun ICMP Echo Request trafiği görülür — Suricata kuralı örneği: `alert icmp any any -> $HOME_NET any (itype:8; threshold: type threshold, track by_src, count 50, seconds 5; msg:"Possible ICMP ping sweep";)`

- **ICMP Flood şüphesi:** SIEM'de aniden ICMP trafiğinin toplam ağ trafiğine oranının anormal yükseldiği, tek bir hedefe yoğunlaştığı görülür — bant genişliği kullanım grafiğinde ani bir sıçrama bunu doğrular.

- **ICMP Tunneling şüphesi:** Normal ping paketlerinin veri alanı genelde küçük ve sabit bir örüntü taşırken (işletim sistemine göre standart payload), anormal derecede büyük veya değişken ICMP payload'ları, ya da normalden çok daha sık ping trafiği görülür — bu, veri sızdırma kanalına dönüştürülmüş olabileceğinin işaretidir.

**Hardening:**

- **ICMP rate limiting**, hem ping sweep hem de ICMP flood saldırılarını büyük ölçüde yavaşlatır, sistem kaynaklarının tükenmesini engeller
- **Directed broadcast'in devre dışı bırakılması** (router seviyesinde), Smurf Attack'ın temelini kurutur — modern router'larda bu genelde varsayılan olarak kapalıdır ama eski/yanlış yapılandırılmış cihazlarda risk taşır
- **ICMP payload boyutu ve içeriği için DPI (Deep Packet Inspection) kuralları**, ICMP tunneling girişimlerini normal ping trafiğinden ayırt etmeye yardımcı olur
- **Dışarıdan gelen ICMP Echo Request'in seçici olarak kısıtlanması** (tamamen kapatmak yerine, sadece gerekli kaynaklara izin vermek), hem teşhis yeteneğini korur hem de keşif yüzeyini daraltır

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

ICMP'nin zafiyeti, "zararsız kontrol mesajı" olarak tasarlanmış olmasının ironik sonucudur — protokol, kötüye kullanılabileceği hiç düşünülmeden, sadece teşhis amacıyla tasarlandı.

- **Hiçbir kimlik doğrulaması olmaması**, herkesin herkese ICMP mesajı gönderebilmesi anlamına gelir — bu hem ping sweep'i hem de sahte Redirect mesajlarıyla trafiği yanlış yönlendirmeyi (**ICMP Redirect Attack**) mümkün kılar.
- **Firewall'larda genelde "zararsız" sayılıp gevşek bırakılması**, ICMP'yi tünelleme ve veri sızdırma için cazip bir kanal haline getirir — güvenlik ekipleri genelde HTTP/HTTPS trafiğini yakından izlerken ICMP'yi göz ardı eder.
- **Broadcast adresine yönlendirilebilmesi**, tek bir sahte paketin binlerce cihazı aynı anda tetikleyip kurbana yanıt yağdırmasına (amplifikasyon) izin verir.

> **Tarihsel örnek:** 1990'ların sonunda yaygın olan **Smurf Attack**, bu zafiyetin en klasik istismarıydı — saldırgan tek bir sahte ICMP Echo Request ile bir ağın tamamını kurbana yanıt göndermeye zorluyor, küçük bir istekle devasa bir DDoS etkisi yaratıyordu. Ayrıca 1996'daki **Ping of Death** zafiyeti, anormal derecede büyük (65535 bayt sınırını aşan) ICMP paketlerinin bazı işletim sistemlerini çökertmesine dayanıyordu — bu, ICMP implementasyonlarındaki bir buffer overflow zafiyetiydi.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **ICMP vs TCP/UDP** | ICMP veri taşımaz, sadece kontrol/hata mesajı iletir; TCP/UDP gerçek uygulama verisini taşır — ICMP'de port kavramı yoktur |
| **Ping Flood vs Smurf Attack** | Ping Flood, saldırganın doğrudan hedefe yüksek hacimli ICMP gönderdiği basit bir DoS'tur; Smurf Attack, üçüncü taraf ağları amplifikasyon aracı olarak kullanan, çok daha etkili bir tekniktir |
| **Traceroute vs Ping** | Ping, tek bir hedefin erişilebilir olup olmadığını kontrol eder; Traceroute, hedefe giden yoldaki her adımı (router'ı) TTL manipülasyonuyla ortaya çıkarır |
| **ICMP Redirect vs ARP Spoofing** | İkisi de trafiği yanlış yönlendirmeyi amaçlar; ICMP Redirect Katman 3'te router seviyesinde çalışır, ARP Spoofing Katman 2'de yerel ağ MAC eşleşmesinde çalışır |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"Bir kurum, güvenlik gerekçesiyle tüm gelen ICMP trafiğini firewall'da tamamen bloke etmiş. Bu yaklaşımın hem faydası hem de gizli bir maliyeti var — ikisini de açıkla."*

<details>
<summary>Model Cevabı</summary>

<br>

Faydası açık: dışarıdan gelen ICMP Echo Request'leri tamamen bloke etmek, saldırganların `ping sweep` ile ağdaki canlı hostları kolayca keşfetmesini engeller ve Smurf/Ping Flood gibi bazı DoS senaryolarının etkisini azaltır — kurum dışarıya karşı "görünmez" hale gelir. Ancak gizli maliyeti, ICMP'nin sadece kötüye kullanılan bir protokol olmadığı, aynı zamanda ağın **kendi kendini teşhis etmesi için** kritik bir mekanizma olduğu gerçeğinden gelir: özellikle **Path MTU Discovery** denen süreç, göndericinin ağ üzerindeki en büyük paket boyutunu (MTU) öğrenmesi için ICMP "Fragmentation Needed" (Type 3, Code 4) mesajlarına dayanır. ICMP tamamen bloke edilirse, bu mesajlar hiç ulaşmaz, gönderici paketlerinin neden "kayboldu" gibi göründüğünü asla öğrenemez — bu da bazı bağlantıların sebepsiz yere kesilmesine veya çok yavaşlamasına yol açan, teşhisi son derece zor "black hole" (kara delik) sorunlarına neden olur. Doğru yaklaşım, ICMP'yi tamamen kapatmak değil, tehlikeli olan Echo Request gibi mesajları dışarıdan sınırlarken, Fragmentation Needed gibi ağın sağlıklı çalışması için gerekli olan mesaj tiplerine izin vermektir.

</details>

---

## 10. Hafıza Çapası

**ICMP = binanın interkom sistemi; hiçbir eşya (veri) taşımaz, sadece "buradasın mı", "o kat kapalı", "buraya kadar geldin" gibi anonslar yapar — ve tam da "zararsız anons sistemi" sayıldığı için, saldırganlar en çok bu kanaldan içeri süzülür veya dışarıya veri kaçırır.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **OSI Katmanı:** 3 (Network) — TCP/IP modelinde: Internet katmanı
- **IP Header'da Protocol numarası:** ICMP = 1
- **Type 8 / Type 0:** Echo Request / Echo Reply (ping)
- **Type 3:** Destination Unreachable
- **Type 11:** Time Exceeded (traceroute'un temeli)
- **Type 5:** Redirect

---

# ARP (Address Resolution Protocol)

*Siber Güvenlik Terim Rehberi — Data Link Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Address Resolution Protocol
- **Kategori:** Protokol
- **Ait Olduğu Katman:** OSI Katman 2 (Data Link) — ama IP (Katman 3) adresini MAC (Katman 2) adresine çevirdiği için iki katman arasında köprü görevi görür
- **Port/Protokol İlişkisi:** Port kullanmaz — TCP/UDP'nin bile altında, doğrudan Ethernet frame içinde taşınan bir protokoldür
- **CVE/CVSS:** Yok — protokolün kendisi bir zafiyet olarak sınıflandırılmaz ama tasarımı gereği CWE-290 (Authentication Bypass by Spoofing) kategorisine giren saldırılara doğrudan zemin hazırlar
- **MITRE ATT&CK:** T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning) — bu teknik doğrudan ARP'nin zafiyetini hedefler

> Not: IP, "hangi ağdan hangi ağa" sorusuna cevap verirken, ARP çok daha yerel ve pratik bir soruya cevap verir: "bu IP adresi, aynı yerel ağdaki hangi fiziksel cihaza (MAC adresine) ait?" ARP olmadan, IP paketleri asla bir Ethernet frame'ine dönüşüp gerçekten gönderilemez.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

1980'lerin başında yerel ağlar (Ethernet) yaygınlaşırken bir uyumsuzluk sorunu vardı: IP katmanı cihazları **mantıksal** IP adresleriyle tanırken, Ethernet donanımı cihazları **fiziksel** MAC adresleriyle tanıyordu. Bir cihaz "192.168.1.5'e paket göndermek istiyorum" dediğinde, bu paketi gerçekten bir Ethernet kablosuna göndermek için karşı tarafın MAC adresini bilmesi gerekiyordu — ama bu iki adresleme sistemi arasında hiçbir doğal bağlantı yoktu.

David Plummer, 1982'de bu boşluğu kapatmak için ARP'yi tasarladı: yerel ağdaki bir cihaz, "bu IP adresine sahip olan kimse, lütfen MAC adresini bana söylesin" diye bağırabilecek (**broadcast**) ve ilgili cihaz cevap verecekti. ARP, IP'nin mantıksal dünyası ile Ethernet'in fiziksel dünyası arasındaki **tercüman** görevini üstlendi — bu çeviri olmadan, aynı yerel ağdaki iki cihaz bile birbirine paket gönderemezdi.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### ARP Request/Reply — Temel Çalışma Mekaniği

Bir cihaz, yerel ağdaki başka bir IP adresine paket göndermek istediğinde önce kendi **ARP Cache**'ine (önbelleğine) bakar — eğer o IP'nin MAC karşılığı zaten biliniyorsa doğrudan gönderir. Bilinmiyorsa şu süreç işler:

```
Cihaz A → ARP Request (broadcast: "192.168.1.5 kimde? MAC'ini söyle")  → Tüm Ağ
Cihaz B ← ARP Reply (unicast: "192.168.1.5 bende, MAC'im: AA:BB:CC:DD:EE:FF") ← Cihaz A'ya
```

**ARP Request**, ağdaki **herkese** gönderilir (broadcast, hedef MAC: `FF:FF:FF:FF:FF:FF`) çünkü gönderen henüz hedefin MAC adresini bilmiyordur — sadece IP adresini bilir. Sadece o IP adresine sahip cihaz cevap verir (**ARP Reply**, unicast — doğrudan soran cihaza).

### ARP Paketinin Temel Alanları

| Alan | Görevi |
|---|---|
| Sender MAC / Sender IP | Bu ARP mesajını gönderenin kendi MAC ve IP adresi |
| Target MAC / Target IP | Sorulan/cevaplanan cihazın MAC ve IP adresi (Request'te Target MAC boş bırakılır) |
| Operation | 1 = Request, 2 = Reply |

### ARP Cache — Hız İçin Hafıza

Her işletim sistemi, öğrendiği IP-MAC eşleşmelerini bir süreliğine (genelde birkaç dakika) **ARP Cache**'te tutar — böylece her paket için tekrar tekrar sormaya gerek kalmaz. Bu önbellek `arp -a` komutuyla görüntülenebilir. Ama işte tam burada kritik bir tasarım zaafı devreye girer:

### Gratuitous ARP — Sorulmadan Cevap Vermek

Normalde bir cihaz sadece kendisine sorulan bir ARP Request'e cevap verir. Ama protokol, bir cihazın **hiç sorulmadan** "ben şu IP'ye sahibim, MAC'im budur" diye duyuru yapmasına da izin verir — buna **Gratuitous ARP** denir ve genelde bir cihaz ağa yeni bağlandığında IP çakışması olup olmadığını kontrol etmek için kullanılır. Sorun şu: **hiçbir cihaz bu duyurunun doğru olup olmadığını doğrulamaz** — herhangi bir cihaz, "ben senin router'ınım" diye duyuru yapabilir ve ağdaki herkes bu yalanı sorgusuzca ARP Cache'ine kaydeder.

---

## 4. Somut Gündelik Benzetme

ARP'yi **bir ofis binasındaki "kimsiniz" bağırışı** gibi düşün.

Sen (Cihaz A) elinde bir zarf tutuyorsun, üzerinde sadece "Ahmet Yılmaz'a" (IP adresi) yazıyor ama Ahmet'in hangi masada oturduğunu (MAC adresi) bilmiyorsun. Ofis koridorunda yüksek sesle bağırırsın: "Ahmet Yılmaz burada mı, hangi masadasın?" (**ARP Request — broadcast**) — bu sesi ofisteki **herkes** duyar ama sadece gerçekten Ahmet olan kişi cevap verir: "Ben Ahmet, 5 numaralı masadayım" (**ARP Reply**). Sen de bu bilgiyi not defterine yazarsın (**ARP Cache**) ki bir dahaki sefere tekrar bağırmana gerek kalmasın. Sorun şu: eğer ofiste kötü niyetli biri, sen sormadan önce koridorda dolaşıp "Ben Ahmet Yılmaz'ım, 5 numaralı masadayım!" diye bağırırsa (**Gratuitous ARP / Spoofing**), hiç kimse bu iddiayı kontrol etmez — herkes bu yalanı olduğu gibi not defterine yazar ve o andan itibaren "Ahmet'e" gönderdikleri her şey aslında yalancıya gider.

| ARP Kavramı | Ofis Benzetmesi |
|---|---|
| ARP Request | "Ahmet Yılmaz burada mı?" diye bağırmak (herkese) |
| ARP Reply | Gerçek Ahmet'in "Ben buradayım, 5 numaralı masa" cevabı |
| ARP Cache | Not defterine yazılan "Ahmet = 5. masa" bilgisi |
| Gratuitous ARP / Spoofing | Sorulmadan "Ben Ahmet'im" diye yalan söylemek |

---

## 5. Saldırgan Senaryosu

Bir saldırgan ARP'yi neredeyse her zaman **lateral movement** aşamasında, yerel ağa zaten girdikten sonra kullanır çünkü ARP mesajları router'ları geçemez — bu saldırı sadece aynı yerel ağdaki (subnet) cihazlar arasında işe yarar.

**Adım adım senaryo:**

1. **Keşif:** Saldırgan yerel ağa (örneğin bir kafede, ofiste veya sızdığı bir iç ağda) bağlandıktan sonra `arp-scan --localnet` veya `netdiscover` ile ağdaki tüm canlı cihazları ve MAC adreslerini hızlıca listeler.

2. **ARP Cache Poisoning — MITM Başlangıcı:** Saldırgan `Ettercap` veya `Bettercap` ile hem kurbana hem de router'a **sahte Gratuitous ARP** mesajları göndermeye başlar: kurbana "Ben router'ım" der, router'a ise "Ben kurban'ım" der. Bunu bilinçli seçer çünkü ARP hiçbir doğrulama yapmadığı için her iki taraf da bu yalanı sorgusuzca kabul eder ve ARP Cache'lerini günceller.

3. **Man-in-the-Middle Kurulumu:** Artık kurbanın tüm internete giden trafiği önce saldırganın makinesinden geçer, saldırgan bunu router'a iletir (**IP forwarding** açarak), kurban hiçbir şeyin farkına varmaz çünkü internet erişimi normal şekilde çalışmaya devam eder.

4. **Veri Toplama/Exploitation:** Saldırgan artık tüm trafiği `Wireshark` ile izleyebilir, şifrelenmemiş HTTP trafiğinden kimlik bilgileri yakalayabilir, ya da DNS yanıtlarını manipüle ederek kurbanı sahte sitelere yönlendirebilir (**DNS Spoofing** ile birleştirerek).

---

## 6. Savunma Senaryosu

**Triage akışı:**

- **ARP Spoofing şüphesi:** Analist, aynı IP adresine ait birden fazla farklı MAC adresinin kısa süre içinde ARP Cache'lerde göründüğünü tespit eder — bu, `arpwatch` gibi bir araçla veya switch loglarıyla izlenir. SIEM'de tipik alarm: *"duplicate IP-MAC binding detected"*.

- **Gratuitous ARP yoğunluğu şüphesi:** Ağda normalden çok daha sık Gratuitous ARP mesajı trafiği görülür, özellikle router'ın veya kritik sunucuların IP'si adına gönderilen mesajlarda artış olur — bu, birinin kendini bu cihazlar gibi göstermeye çalıştığının işaretidir.

- **Doğrulama:** Şüpheli MAC adresinin gerçekten o cihaza mı ait olduğunu, yoksa bilinen bir saldırı aracının (Ettercap, Bettercap gibi genelde belirli üretici öneklerine sahip sanal arayüzler oluşturur) izini mi taşıdığını MAC adresinin **OUI (Organizationally Unique Identifier)** kısmından kontrol eder.

**Hardening:**

- **Dynamic ARP Inspection (DAI)**, switch seviyesinde çalışır ve gelen ARP mesajlarını DHCP Snooping tablosuyla karşılaştırarak sahte olanları otomatik olarak reddeder — ARP Spoofing'e karşı en etkili kurumsal önlemdir
- **Statik ARP girişleri**, kritik cihazlar (router, sunucu) için IP-MAC eşleşmesini sabitler, bu cihazlara yönelik spoofing girişimlerini işe yaramaz hale getirir (ama büyük ağlarda ölçeklenmesi zordur)
- **Port Security**, bir switch portuna sadece belirli MAC adreslerinin bağlanmasına izin vererek yetkisiz cihazların ağa girip ARP saldırısı başlatmasını zorlaştırır

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

ARP'nin zafiyeti, protokolün 1982'de tasarlandığı dönemin "herkes güvenilir" varsayımının doğrudan mirasıdır — kimse "biri bu duyuruyu kötüye kullanır mı" diye düşünmedi çünkü o dönemde yerel ağlara erişim zaten fiziksel olarak kısıtlıydı.

- **Hiçbir kimlik doğrulaması olmaması**, herhangi bir cihazın herhangi bir IP adresi adına konuşabilmesine izin verir — bu, ARP Spoofing'in tek ve yeterli nedenidir.
- **Cevabın sorgulanmadan kabul edilmesi (stateless doğa)**, bir cihazın hiç ARP Request göndermediği bir IP için bile Gratuitous ARP cevabını kabul etmesine yol açar.
- **Sadece yerel ağda çalışması**, bu saldırıyı uzaktan yapılamaz hale getirir ama aynı zamanda "iç ağ zaten güvenlidir" güven varsayımını (**implicit trust**) doğrudan hedef alır — pek çok kurum dış tehditlere odaklanıp iç ağ trafiğini yeterince izlemez.

> **Tarihsel örnek:** ARP Spoofing, herhangi bir tek olayla değil, **onlarca yıldır süregelen sistematik bir teknik** olarak bilinir — kurumsal sızma testlerinde (pentest) hâlâ en sık başarıyla uygulanan ilk-erişim-sonrası tekniklerden biridir, çünkü switch'lerin varsayılan yapılandırmalarının büyük kısmı hâlâ DAI gibi korumaları etkinleştirmeden gelir.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **ARP vs DNS** | ARP, yerel ağda IP'yi MAC'e çevirir (Katman 2-3 arası); DNS, internette domain adını IP'ye çevirir (Katman 7) — ikisi de "isim çözümleme" yapar ama tamamen farklı katmanlarda ve kapsamlarda |
| **ARP Spoofing vs DNS Spoofing** | ARP Spoofing yerel ağ trafiğini yönlendirmeyi hedefler; DNS Spoofing kullanıcıyı yanlış bir web sitesine yönlendirmeyi hedefler — genelde birlikte kullanılırlar (önce ARP ile trafiği ele geçir, sonra DNS ile yönlendir) |
| **ARP Request vs Gratuitous ARP** | ARP Request, bir soruya cevap almak için gönderilir; Gratuitous ARP, hiçbir soru olmadan kendiliğinden yapılan bir duyurudur — spoofing genelde ikincisini istismar eder |
| **Dynamic ARP Inspection vs Port Security** | DAI, gelen ARP mesajlarının içeriğini doğrular; Port Security, fiziksel portlara hangi MAC adreslerinin bağlanabileceğini sınırlar — ikisi farklı problemleri çözer, birlikte kullanılmaları önerilir |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"ARP Spoofing saldırısı neden sadece aynı yerel ağdaki (subnet) cihazlar arasında işe yarar, saldırgan internetin başka bir yerinden bir kurumun iç ağına karşı bu saldırıyı neden gerçekleştiremez?"*

<details>
<summary>Model Cevabı</summary>

<br>

ARP, OSI'nin Katman 2'sinde (Data Link) çalışan bir protokoldür ve ARP mesajları Ethernet frame'leri içinde taşınır — bu frame'ler router'lar tarafından **yönlendirilmez**, sadece aynı yerel ağ segmentindeki switch'ler arasında dolaşır. Bir router, bir ağdan diğerine paket geçirirken Katman 3'te (IP) çalışır ve gelen paketleri yeni bir Ethernet frame'i içine sarmalayarak gönderir — bu süreçte orijinal ARP mesajı asla router'ın diğer tarafına geçmez, çünkü ARP'nin kendisi zaten IP paketi değil, doğrudan bir Ethernet frame'idir ve broadcast domain'i router sınırında biter. Bu yüzden bir saldırgan, kurbanla aynı yerel ağda (aynı switch'e bağlı, aynı subnet'te) fiziksel veya mantıksal olarak bulunmadan ARP Spoofing yapamaz — internetin herhangi bir yerinden bu saldırıyı başlatmak protokolün temel çalışma prensibi gereği mümkün değildir. Bu da ARP Spoofing'i, uzak saldırılardan çok, içeriden erişim gerektiren (fiziksel erişim, Wi-Fi'ye sızma, veya zaten ele geçirilmiş bir cihaz üzerinden) bir teknik haline getirir.

</details>

---

## 10. Hafıza Çapası

**ARP = ofis koridorunda "kimsiniz" diye bağırmak; herkes duyar, sadece gerçek sahibi cevap vermeli ama kimse kimliği kontrol etmez — bu yüzden kötü niyetli biri sorulmadan "benim!" diye bağırırsa (Gratuitous ARP), tüm ofis onu gerçek sanıp ona göre davranmaya başlar.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **OSI Katmanı:** 2 (Data Link)
- **ARP Operation kodu:** 1 = Request, 2 = Reply
- **Broadcast MAC adresi:** `FF:FF:FF:FF:FF:FF`
- **ARP Cache görüntüleme komutu:** `arp -a`
- **MITRE ATT&CK Teknik ID:** T1557.002 (ARP Cache Poisoning)

---

# RARP (Reverse Address Resolution Protocol)

*Siber Güvenlik Terim Rehberi — Data Link Katmanı*

---

## 1. Kimlik Kartı

- **Tam Açılım:** Reverse Address Resolution Protocol
- **Kategori:** Protokol (büyük ölçüde kullanımdan kalkmış — **legacy/tarihsel** önemi var, güncel ağlarda neredeyse hiç kullanılmıyor)
- **Ait Olduğu Katman:** OSI Katman 2 (Data Link) — ARP'nin tam tersi yönde çalışan bir çeviri protokolü
- **Port/Protokol İlişkisi:** Port kullanmaz, ARP gibi doğrudan Ethernet frame içinde taşınır
- **CVE/CVSS:** Yok — kullanımdan kalkmış olması nedeniyle güncel CVE veritabanlarında aktif bir zafiyet olarak izlenmez
- **MITRE ATT&CK:** Doğrudan bir teknik ID'si yok çünkü modern saldırı yüzeyinde pratik önemi kalmamıştır

> Not: Bu terimin öğrenilme değeri, güncel bir tehdide karşı savunma değil, **"neden DHCP var" sorusunun köküne inmektir** — RARP'yi anlamak, DHCP'nin hangi boşluğu doldurduğunu gerçekten kavramanı sağlar.

---

## 2. Neden Var Oldu (Tarihsel Bağlam)

ARP, bir cihazın IP adresini bilip MAC adresini öğrenmesini sağlıyordu — "192.168.1.5 kimde?" sorusuna cevap buluyordu. Ama 1980'lerin başında farklı bir sorunla karşılaşıldı: **disksiz iş istasyonları** (diskless workstations) ve bazı ağ yazıcıları gibi cihazlar, kendi MAC adreslerini biliyordu (bu donanıma gömülüydü) ama hangi **IP adresine** sahip olduklarını bilmiyorlardı çünkü hiçbir yerel depolamaları yoktu, IP adresini kaydedecek bir yerleri olmuyordu.

1984'te bu tam ters problemi çözmek için **RARP** tasarlandı: "Benim MAC adresim şu, bana hangi IP adresini kullanmam gerektiğini söyler misiniz?" RARP, ARP'nin sorduğu soruyu tam olarak tersine çevirir — ARP "IP'den MAC'e" giderken, RARP "MAC'ten IP'ye" gider. Ama RARP'nin ciddi kısıtlamaları vardı (aşağıda işlenecek) ve çok geçmeden çok daha kapsamlı bir çözüm olan **BOOTP**, ardından **DHCP** onun yerini aldı — bugün RARP'yi gerçek bir ağda çalışırken görme ihtimalin neredeyse sıfırdır.

---

## 3. Teknik Çalışma Mantığı — Adım Adım Veri Akışı

### RARP Request/Reply — ARP'nin Ayna Görüntüsü

```
Cihaz A (sadece MAC'ini biliyor) → RARP Request (broadcast: "MAC'im AA:BB:CC:DD:EE:FF, IP'm ne?") → Ağ
RARP Sunucusu ← RARP Reply (unicast: "Senin IP'n: 192.168.1.20")                                    ← Cihaz A'ya
```

Cihaz, kendi MAC adresini içeren bir broadcast mesajı gönderir. Ağdaki özel bir **RARP sunucusu** (bu sunucunun önceden yapılandırılmış bir MAC-IP eşleşme tablosu olması gerekir) bu isteği görür, tablosunda ilgili MAC'i bulur ve karşılık gelen IP adresini cevap olarak gönderir.

### Kritik Kısıtlama — Neden RARP Yetersiz Kaldı

RARP'nin paket yapısı ARP ile neredeyse birebir aynıdır (aynı Ethernet frame formatını, benzer Operation kodlarını kullanır) ama üç ciddi eksikliği vardı:

| Eksiklik | Sonucu |
|---|---|
| Her yerel ağ segmentinde ayrı bir RARP sunucusu gerekliydi | Büyük ağlarda yönetimi son derece zordu, router'lar RARP broadcast'ini geçirmezdi |
| Sadece IP adresi veriyordu | Subnet maskesi, varsayılan ağ geçidi (gateway), DNS sunucusu gibi başka hiçbir bilgi taşımıyordu |
| MAC-IP eşleşmeleri elle, statik olarak yapılandırılmalıydı | Otomatik/dinamik adres yönetimi mümkün değildi |

Bu üç eksiklik birleşince, ağlar büyüdükçe RARP pratik olarak kullanılamaz hale geldi. **BOOTP** (Bootstrap Protocol) bu eksiklikleri kapatmak için geldi (IP dışında gateway, subnet gibi bilgileri de taşıyabiliyordu), ardından **DHCP** (Dynamic Host Configuration Protocol) BOOTP'nin üzerine inşa edilerek tam otomatik, dinamik ve kiralama (**lease**) tabanlı bir adres yönetim sistemi sundu — bugün her ağda kullanılan budur.

---

## 4. Somut Gündelik Benzetme

RARP'yi **hafızasını kaybetmiş ama kimliğini (parmak izini) bilen biri gibi** düşün.

Bir kişi (disksiz iş istasyonu) uyanır ve hiçbir şey hatırlamaz — nerede oturduğunu, hangi eve ait olduğunu bilmez, ama parmak izini (**MAC adresi**, donanıma gömülü, değişmez) bilir. Bu kişi belediye binasına gider ve "parmak izim bu, bana hangi eve ait olduğumu söyler misiniz?" diye sorar (**RARP Request**). Belediye memuru (**RARP sunucusu**), elindeki önceden hazırlanmış "parmak izi → ev adresi" listesine bakar ve "senin evin şu adres" der (**RARP Reply**) — ama sadece ev adresini söyler, o eve nasıl gidileceğini (gateway), posta kodunu (subnet mask) ya da komşularının kim olduğunu (DNS) söylemez. Bu yüzden zamanla kasabalar, sadece ev adresini değil, kişiye ihtiyacı olan **her şeyi** (yol tarifi, posta kodu, komşu bilgisi) tek seferde veren daha kapsamlı bir danışma masası (**DHCP**) kurmaya karar verdi.

| RARP Kavramı | Benzetme |
|---|---|
| MAC adresi | Değişmeyen parmak izi |
| RARP Request | "Parmak izim bu, evim nerede?" sorusu |
| RARP sunucusu | Elle hazırlanmış parmak izi-adres listesine bakan memur |
| RARP'nin eksikliği | Sadece ev adresini söylemesi, başka hiçbir bilgi vermemesi |
| DHCP'nin üstünlüğü | Tek seferde her şeyi (adres+yol tarifi+komşu bilgisi) veren kapsamlı danışma masası |

---

## 5. Saldırgan Senaryosu

RARP'nin modern ağlarda pratik olarak kullanılmaması nedeniyle, güncel bir saldırı senaryosu **gerçekçi değildir** — bu terimin saldırgan/savunma değeri, daha çok **tarihsel farkındalık ve DHCP'nin neden bu kadar özenle korunması gerektiğini anlamak** üzerinedir.

**Tarihsel/eğitici bağlam:** RARP'nin aktif olduğu eski/legacy sistemlerde (bugün neredeyse hiç yok, ama teorik olarak endüstriyel kontrol sistemleri gibi çok eski altyapılarda kalıntı olarak bulunabilir), saldırganın izleyebileceği mantık ARP Spoofing ile neredeyse birebir aynıdır: RARP'nin de hiçbir kimlik doğrulaması yoktur, bu yüzden sahte bir RARP sunucusu kurup cihazlara yanlış IP adresleri dağıtmak (**rogue RARP server**) teorik olarak mümkündür — bu, bugünkü **Rogue DHCP Server** saldırısının doğrudan atasıdır. Bir saldırgan, eğer nadir bir RARP-bağımlı legacy sistemle karşılaşırsa, kendi RARP sunucusunu kurup cihazları kontrolü altındaki bir IP'ye yönlendirebilir, böylece o cihazın tüm trafiğini kendi üzerinden geçirmeye zorlayabilir.

**Neden bugün pratik değeri düşük:** Modern kill chain'lerde saldırganlar RARP yerine doğrudan **Rogue DHCP Server** tekniğini kullanır çünkü hemen hemen her ağ DHCP kullanır, RARP değil — bu yüzden bu terimi öğrenmenin asıl faydası, Rogue DHCP saldırısının **mantığını** RARP'nin basit atası üzerinden net şekilde kavramaktır.

---

## 6. Savunma Senaryosu

RARP'ye özgü aktif bir savunma senaryosu yazmak gerçekçi olmaz çünkü güncel ortamlarda izlenecek bir RARP trafiği yoktur. Ama bu terimin savunma değeri, doğrudan **RARP'nin yerini alan DHCP'nin nasıl korunması gerektiğini** anlamaktan geçer:

**Triage akışı (DHCP bağlamında, RARP'nin mirası olarak):**

- **Rogue DHCP Server şüphesi** (RARP'nin modern karşılığı): Ağda birden fazla cihazın DHCP sunucusu gibi davrandığı, istemcilerin beklenmedik/tutarsız IP aralıkları veya gateway bilgileri aldığı görülür — bu, RARP'nin sahte sunucu zafiyetinin doğrudan modern versiyonudur.

**Hardening:**

- **DHCP Snooping**, switch seviyesinde sadece yetkili portlardan gelen DHCP sunucu cevaplarını kabul eder, sahte/rogue sunucuları engeller — bu, RARP döneminde hiç var olmayan, sonradan öğrenilen bir derstir
- Eğer nadiren RARP'ye bağımlı bir legacy sistem tespit edilirse, bu sistemin **izole bir ağ segmentinde** (VLAN ile ayrılmış) tutulması, saldırı yüzeyini daraltır

---

## 7. Zafiyet / Kötüye Kullanım Noktaları

RARP'nin zafiyeti, ARP'ninkiyle neredeyse birebir aynı köktedir: **hiçbir kimlik doğrulaması yoktur**, herhangi bir cihaz kendini "RARP sunucusu" gibi tanıtıp sahte cevaplar verebilir. Protokol, 1984'te tasarlandığında güven varsayımı üzerine kuruldu — kimse bir RARP sunucusunun sahte olabileceğini düşünmedi.

Ayrıca RARP'nin **her yerel ağ segmentinde ayrı bir sunucu gerektirmesi**, kendi başına bir güvenlik zafiyeti değildi ama operasyonel bir zayıflıktı — bu dağınık yapı, merkezi bir güvenlik politikasının uygulanmasını zorlaştırıyordu.

> **Tarihsel not:** RARP'nin kendisiyle ilişkilendirilen büyük, isimlendirilmiş bir güvenlik olayı yoktur — çünkü protokol geniş çapta yaygınlaşmadan önce BOOTP ve DHCP tarafından hızla ikame edildi. Asıl önemli tarihsel ders, RARP'nin **kimlik doğrulamasız sunucu modelinin** zafiyetinin, DHCP'ye miras kaldığıdır — bugün hâlâ karşılaşılan **Rogue DHCP Server** ve **DHCP Starvation** saldırıları, kökeninde RARP'nin çözemediği aynı güven sorununu taşır.

---

## 8. Sık Karıştırılan Kavramlar

| Kavram | Fark |
|---|---|
| **RARP vs ARP** | ARP, IP'den MAC'e gider ("bu IP kimde?"); RARP, MAC'ten IP'ye gider ("bu MAC'in IP'si ne?") — birbirinin tam tersi yönünde çalışırlar |
| **RARP vs BOOTP** | RARP sadece IP adresi verir; BOOTP ayrıca gateway, subnet mask gibi ek yapılandırma bilgilerini de taşıyabilir — BOOTP, RARP'nin doğrudan eksikliğini kapatan halefidir |
| **RARP vs DHCP** | RARP statiktir, elle yapılandırılmış bir tabloya bağlıdır; DHCP dinamiktir, adresleri otomatik kiralama (lease) mantığıyla dağıtır — DHCP, BOOTP'nin üzerine inşa edilen son ve güncel çözümdür |
| **Rogue RARP Server vs Rogue DHCP Server** | İkisi de sahte bir yapılandırma sunucusu kurup istemcileri yanıltmayı hedefler; Rogue DHCP Server, güncel ağlarda hâlâ gerçek bir tehdit iken Rogue RARP Server neredeyse tamamen tarihsel bir kavramdır |

---

## 9. Mülakat Sorusu Simülasyonu

**Soru:** *"RARP neden günümüzde neredeyse hiç kullanılmıyor, ve DHCP'nin RARP'ye göre çözdüğü üç temel sorun nedir?"*

<details>
<summary>Model Cevabı</summary>

<br>

RARP, 1980'lerde disksiz iş istasyonlarının kendi IP adreslerini öğrenmesi için tasarlandı ama üç ciddi kısıtlaması vardı. Birincisi, RARP broadcast mesajları router'lar tarafından geçirilmediği için her yerel ağ segmentinde ayrı bir RARP sunucusunun bulunması gerekiyordu, bu da büyük ağlarda yönetimi pratik olarak imkansız hale getiriyordu. İkincisi, RARP sadece IP adresini veriyordu; subnet mask, varsayılan ağ geçidi, DNS sunucu adresi gibi bir cihazın ağda tam olarak çalışabilmesi için ihtiyaç duyduğu diğer kritik bilgileri hiç taşımıyordu, bu yüzden bu bilgilerin ayrıca elle yapılandırılması gerekiyordu. Üçüncüsü, MAC-IP eşleşmeleri RARP sunucusunda statik ve elle girilmesi gerekiyordu, hiçbir otomatik/dinamik adres kiralama mekanizması yoktu, bu da adres yönetimini son derece emek yoğun hale getiriyordu. DHCP, önce BOOTP'nin bu eksiklikleri kısmen kapatmasının ardından geliştirildi ve üç sorunu birden çözdü: merkezi bir sunucudan tüm ağ genelinde (router'lar DHCP relay ile bu trafiği taşıyabilir) hizmet verebilir, IP adresiyle birlikte gateway/subnet/DNS gibi tüm yapılandırma bilgilerini tek pakette sunar, ve adresleri otomatik olarak, süreli kiralama (lease) mantığıyla dinamik şekilde dağıtıp geri alabilir.

</details>

---

## 10. Hafıza Çapası

**RARP = hafızasını kaybetmiş ama parmak izini bilen kişi; "ben buyum, evim nerede?" diye sorar ama cevap olarak sadece adres alır — yol tarifi yok, komşu bilgisi yok. İşte bu eksiklik yüzünden RARP tarihe karıştı, yerini her şeyi tek seferde veren DHCP aldı.**

---

## 11. Sadece Ezberlenecek Çıplak Veri

- **OSI Katmanı:** 2 (Data Link)
- **Yön:** MAC → IP (ARP'nin tam tersi)
- **Yerini alan protokoller:** BOOTP → DHCP
- **Güncel kullanım durumu:** Pratik olarak kullanımdan kalkmış (obsolete/legacy)

---