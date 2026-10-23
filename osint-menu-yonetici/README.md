# OSINT Menü Yöneticisi

Kali tabanlı (XFCE + Whisker menü) OSINT dağıtımınızı özelleştirmek için grafik
arayüzlü bir araç. GitHub'dan indirdiğiniz araçları tek tıkla kurar, menüde
istediğiniz kategoriye koyar ve **terminalde adını yazınca çalışır** hale getirir.

- **GitHub / Git deposu** → `/opt/osint-tools/<araç>` altına indirir, Python
  bağımlılıklarını aracın kendi sanal ortamına (`.venv`) kurar ve
  `/usr/local/bin/<komut>` oluşturur. Artık terminalde `eyes ornek@mail.com` yazmanız yeterli.
- **Bilgisayardaki klasör/dosya** → aynı şekilde `/opt/osint-tools` altına kopyalar.
- **pipx paketi** → sistem geneline kurar (`/opt/pipx`, komutlar `/usr/local/bin`).
- **APT paketi** → `apt-get install` ile kurar.
- **Zaten kurulu komut** (pip, pipx, apt ile kendi kurduklarınız) → sadece menüye ekler.
- **Kategori oluşturma:** “OSINT username”, “Recon” gibi kendi kategorilerinizi en üste
  ya da var olan bir kategorinin içine (alt kategori) ekleyin.
- **Sürükle-bırak:** Eklediğiniz araçları ve kategorileri ağaçta sürükleyip başka bir
  kategoriye bırakın. Değişiklik menüye hemen yansır.
- **Simgeler:** 44 hazır OSINT simgesi (e-posta, telefon, kullanıcı adı, sosyal medya,
  dark web, kripto, harita, IP, DNS…) içeren bir galeri. Galeriden sistem/Kali simge
  temasındaki simgeleri (ör. `kali-sherlock`) de seçebilir ya da kendi PNG/SVG dosyanızı
  yükleyebilirsiniz.
- **Hazır kategoriler:** “OSINT Sosyal Medya”, “OSINT Dark Web”, “OSINT Kripto Para” gibi
  21 kategoriyi simgeleriyle birlikte tek tıkla oluşturabilirsiniz.
- **Var olan kategori ve uygulamaları özelleştirme:** Menünüzde zaten olan “OSINT email”
  gibi kategorilerin ya da uygulamaların adını ve simgesini değiştirebilirsiniz. Özgün dosya
  bozulmaz, istediğiniz zaman “Varsayılana döndür” ile geri alınabilir.
- Düzenle, sil, güncelle (`git pull` / `pipx upgrade` / `apt`), **Dene** (menüden açılmış
  gibi çalıştır), arama.

Var olan menünüz XFCE/Whisker'ın gördüğü şekilde okunur: Kali kategorileri, menulibre
ya da “Menüyü düzenle” ile yaptığınız kategoriler (OSINT ▸ OSINT email gibi) ve Whisker'ın
**Favorites** listesi ağaçta gri olarak gösterilir. Yeni araçlarınızı bunların içine de
ekleyebilirsiniz. Sistem dosyalarınıza dokunulmaz; her şey ayrı bir menü birleştirme
dosyasıyla eklenir.

## Kurulum

```bash
git clone https://github.com/emrekybs/Expulso.git
cd Expulso/osint-menu-yonetici
sudo ./install.sh
```

Gerekli paketler (`python3-gi`, `gir1.2-gtk-3.0`, `git`, `python3-venv`,
`pipx`) otomatik kurulur.

Açmak için: **Menü ▸ Settings ▸ OSINT Menü Yöneticisi** ya da terminalde
`osint-menu-yonetici`. Sistem menüsünü düzenlediği için parola sorar (pkexec/sudo).

Kurmadan denemek isterseniz klasör içinden `./osint-menu-yonetici` ile de açabilirsiniz.

## Kullanım

### GitHub'dan araç eklemek

1. **Araç Ekle**'ye tıklayın.
2. Kaynak türü: **GitHub / Git deposu**. Adres: `https://github.com/N0rz3/Eyes`
   (ya da kısaca `N0rz3/Eyes`).
3. Ad ve terminal komutu otomatik dolar (`Eyes` / `eyes`); isterseniz değiştirin.
4. **Kategori** listesinden yerini seçin (ör. `OSINT ▸ OSINT email`).
5. **Ekle** → indirme ve kurulum penceresinde ilerlemeyi canlı izlersiniz.
6. Son adımda hangi dosyanın çalışacağı sorulur; en olası dosya (ör. `eyes.py`) zaten
   seçili gelir. **Tamam** deyin.

Sonuç:

```bash
$ eyes -h          # her terminalde çalışır
```

Menüden tıklandığında terminal açılır, araç `Menü parametreleri` alanındaki
parametrelerle (varsayılan `-h`) çalışır ve terminal açık kalır.

> **“Komutu aracın kendi klasöründe çalıştır”** seçeneği (varsayılan açık): Birçok
> GitHub aracı veri/ayar dosyalarını kendi klasöründen göreli yolla okur; bu seçenek
> bu tür araçların bozulmadan çalışmasını sağlar. Aracın kaydettiği çıktı dosyaları da
> o klasöre yazılır (klasör herkese yazılabilir yapılır). Çıktının bulunduğunuz klasöre
> yazılmasını istiyorsanız aracı düzenleyip bu seçeneği kapatın.

### Kategori oluşturmak

**Kategori Oluştur** → ad yazın → **Nerede olsun?**:

- `Uygulama Menüsü (en üst)` → solda Recon, OSINT gibi ana kategorilerin yanında görünür.
- `OSINT` → OSINT'in içinde “OSINT email” gibi alt kategori olur.

“Hazır şablon” listesinden bir OSINT kategorisi seçerseniz ad, simge ve açıklama kendiliğinden
dolar. Birden fazla kategoriyi bir kerede oluşturmak için araç çubuğundaki
**Hazır Kategoriler** düğmesini kullanın: istediklerinizi işaretleyip
**Seçilenleri Oluştur**'a basmanız yeterli. O konumda aynı adda bir kategori zaten varsa
listede pasif görünür.

XFCE boş kategorileri menüde göstermez; içine bir araç eklediğiniz anda görünür.

### Simge seçmek

Araç ya da kategori penceresinde **Simge seç…** düğmesi (ya da simgenin kendisi) galeriyi
açar:

- **Hazır OSINT Simgeleri:** Pakette gelen renkli simgeler. Arama kutusuna `posta`,
  `telefon`, `dark`, `kripto` gibi bir kelime yazıp süzebilirsiniz.
- **Sistem / Kali Simgeleri:** Yüklü simge temasındaki bütün simgeler. Kali araç
  simgeleri `kali-` ile başlar (ör. `kali-sherlock`, `kali-maltego`).
- **Aracın Kendi Resimleri:** GitHub'dan indirilen aracın klasöründeki resimler (logo,
  ikon…). Adında `logo` ya da `icon` geçen bir resim varsa kurulumun son adımında simge
  olarak kendiliğinden önerilir.
- **Dosyadan seç…:** Kendi PNG/SVG/XPM dosyanız. Dosya sisteme kopyalanır, yani ISO'ya da
  girer.

Simge seçmeden bir araç eklerseniz, Kali temasında aracın adına uygun bir simge varsa
(ör. `kali-holehe`) o kullanılır, yoksa terminal simgesi gösterilir.

### Var olan kategori ve uygulamaların ad/simgesini değiştirmek

Ağaçta gri görünen bir uygulamayı (ör. Holehe, H8mail) ya da “OSINT email” gibi sistemdeki
bir kategoriyi seçip **Düzenle**'ye basın, ya da üzerine çift tıklayın (sağ tık ▸
“Adını / simgesini değiştir…”). Favoriler listesindeki uygulamalar için de aynısı geçerli. Ad ve simgeyi değiştirip
**Kaydet**'e basın. Değiştirilen öğeler “(özelleştirildi)” olarak işaretlenir. Aynı
pencerede **Varsayılana döndür** ile özgün haline geri döner.

Nasıl çalışıyor: `/usr/share` altındaki dosyalar değiştirilmez. Onların yerine
`/usr/local/share` altına öncelikli bir kopya yazılır (paket güncellemeleri bu değişikliği
bozmaz). Kullanıcı klasörünüzdeki (`~/.local/share`) dosyalar ise yerinde değiştirilir ve
özgün halleri `.omy-yedek` uzantısıyla saklanır.

### Sürükle-bırak

Ağaçta **kalın** yazılan öğeler sizin eklediklerinizdir ve sürüklenebilir. Bir aracı
bir kategorinin üzerine bırakınca oraya taşınır. Kategoriyi taşırsanız içindekiler
de birlikte taşınır. Gri öğeler sistemde zaten olan uygulamalardır ve taşınmaz.

Sağ tık menüsünden “Buraya araç ekle”, “Buraya alt kategori oluştur”, “Klasörü aç”
gibi kısayollara ulaşabilirsiniz. `Delete` siler, `F2` düzenler.

## ISO'ya aktarmadan önce

Her şey sistem klasörlerine yazıldığı için ISO'ya otomatik olarak dahil olur:

| Ne | Nerede |
|---|---|
| Kayıt dosyası (eklenen her şey) | `/etc/osint-menu-yonetici/state.json` |
| Menü yapısı | `/etc/xdg/menus/applications-merged/osint-menu-yonetici.menu` |
| Kategoriler | `/usr/share/desktop-directories/omy-*.directory` |
| Menüdeki araçlar | `/usr/share/applications/omy-*.desktop` |
| Terminal komutları | `/usr/local/bin/<komut>` |
| GitHub/yerel araçlar | `/opt/osint-tools/<araç>` |
| pipx araçları | `/opt/pipx` |
| Hazır simge paketi | `/usr/share/osint-menu-yonetici/simgeler` |
| Kendi yüklediğiniz simgeler | `/usr/share/osint-menu-yonetici/icons` |
| Sistem öğelerinde yapılan ad/simge değişiklikleri | `/usr/local/share/applications`, `/usr/local/share/desktop-directories` |

İpuçları:

- Mevcut OSINT kategorilerinizi menulibre/“Menüyü düzenle” ile oluşturduysanız bunlar
  kullanıcı klasörünüzdedir (`~/.config/menus`, `~/.local/share/desktop-directories`,
  `~/.local/share/applications`). ISO'daki yeni kullanıcılarda da görünmeleri için bu
  klasörleri `/etc/skel` altına kopyalayın (ya da ISO aracınız ev klasörünü dahil etsin).
- Dosyaları bir şekilde bozduysanız hepsini kayıttan yeniden üretmek için:
  `sudo osint-menu-yonetici --uygula`
- Eklenenleri listelemek için: `osint-menu-yonetici --liste`

## Sorun giderme

- **Mevcut menü görünmüyor:** Pencerenin üstünde sarı bir uyarı çubuğu çıkar ve nedenini
  yazar. Aracı her zaman normal kullanıcınızla, menüden ya da `osint-menu-yonetici`
  komutuyla açın (kendisi parola sorar). `sudo su` ile root olup açarsanız sizin
  kullanıcı menünüzü (`~/.config/menus`) bulamayabilir.
- **Favorites:** Whisker'ın favori listesi bir menü kategorisi değildir. Ağaçta en üstte
  “Favoriler (Whisker menü)” olarak gösterilir ve buradaki uygulamaların simgesini
  değiştirebilirsiniz. Listeye öğe eklemek için Whisker menüde uygulamaya sağ tıklayıp
  “Add to Favorites” seçin.

- **Menüde görünmüyor:** Birkaç saniye bekleyin; görünmezse `xfce4-panel -r` ile paneli
  yeniden başlatın. Boş kategoriler menüde gösterilmez.
- **Komut bulunamadı:** Açık terminallerde `hash -r` yazın ya da yeni terminal açın.
- **Bağımlılık hatası:** Kurulum günlüğünü okuyun; eksik sistem paketi varsa
  (`sudo apt install ...`) kurup araç üzerinde **Güncelle**'ye basın.
- **Depoda `install.sh` var:** Güvenlik nedeniyle otomatik çalıştırılmaz. Sağ tık ▸
  “Klasörü aç” ile klasöre gidip gerekiyorsa elle çalıştırın.

## Kaldırma

```bash
sudo ./uninstall.sh          # yalnızca uygulamayı kaldırır, eklediğiniz araçlar kalır
sudo ./uninstall.sh --hepsi  # eklediklerinizi kaldırır, ad/simge değişikliklerini geri alır
```

## Geliştirici notları

```bash
python3 -m unittest discover -s tests -v                  # çekirdek testler
xvfb-run -a python3 tests/gui_smoke.py /tmp/ekran         # arayüz testi + ekran görüntüleri
```

Testler `OMY_ROOT` ile sahte bir kök dizinde çalışır, sisteminize dokunmaz.

Simge paketine yeni simge eklemek için `tools/simge_uret.py` içindeki `GLYPHS` ve `ICONS`
listelerine bir satır ekleyip `python3 tools/simge_uret.py` çalıştırın.
