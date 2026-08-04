<div align="center">

# 🌐 OSI Modeli (Open Systems Interconnection)

### *Siber Güvenlik Terim Rehberi — Ağ Katmanı*

![Category](https://img.shields.io/badge/Kategori-Kavramsal%20Model-blue)
![Layer](https://img.shields.io/badge/Katman-1--7-orange)
![Difficulty](https://img.shields.io/badge/Seviye-Temel-green)
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

## 🔗 12. Bir Sonraki Adım İçin Not

Bir sonraki mantıklı adım **TCP/IP Model** olmalı çünkü OSI'yi gerçek dünyadaki 4 katmanlı karşılığıyla eşleştirmen gerekiyor. Ardından **TCP Three-Way Handshake ve TCP Flags** konusuna geçmen iyi olur çünkü Katman 4'teki teorik bilgiyi paket seviyesinde (Wireshark'ta gerçekten görerek) somutlaştırmış olursun.

---

<div align="center">

*📘 Bu doküman [Siber Güvenlik Terim Rehberi] serisinin bir parçasıdır.*

</div>

---