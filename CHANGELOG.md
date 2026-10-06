# Değişiklik Günlüğü

## 0.1.0 — 6 Ekim 2026

İlk genel yayın.

### Eklenenler

- Birleşik güvenlik olay hattı
- SSH journal sensörü
- SSH brute-force ilişkilendirmesi
- PAM/faillock hesap kilidi algılama
- Başarısız girişlerden sonra başarılı SSH oturumu algılama
- Pasif nftables TCP SYN sensörü
- Ağ port tarama ilişkilendirmesi
- Yerel bağlantıda MAC eşleme korumaları
- Suricata EVE JSON okuyucu
- Suricata trafik yönü sınıflandırması
- Suricata gürültü bastırma politikası
- Suricata tekrar engelleme
- İsteğe bağlı Tailscale userspace tarama sensörü
- Heuristik Tailscale peer eşleme
- JSONL olay kaydı
- JSON ve metin olay anlık görüntüleri
- Masaüstü bildirim sistemi
- Kullanıcı oturumu bildirim tüketicisi
- Birleşik canlı kaynak yöneticisi
- TOML yapılandırması
- arch-guard komut satırı arayüzü
- systemd servis tanımları
- Pasif nftables kuralı
- sysusers ve tmpfiles tanımları
- Arch Linux PKGBUILD iskeleti

### Güvenlik ve gizlilik

- Root çalışma zamanı doğrudan grafik masaüstüne bildirim göndermez.
- Sensörler ile bildirim/anlık görüntü politikası ayrıdır.
- Tailscale Node ID ve User ID normalize edilmiş olaylara eklenmez.
- Gateway MAC adresi uzak kaynak cihazın MAC adresi olarak kullanılmaz.
- Geçmiş Suricata kayıtları güncel socket durumu ile yanlış ilişkilendirilmez.
- Bilinen makineye özel değerler genel kaynak ağacından temizlenmiştir.
