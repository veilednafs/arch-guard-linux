# Güvenlik Politikası

## Desteklenen sürüm

Şu anda desteklenen sürüm serisi: **0.1.x**

## Güvenlik açığı bildirimi

İstismar edilebilir güvenlik açıklarını doğrudan herkese açık issue olarak yayımlamayın.

GitHub deposu yayımlandıktan sonra mümkünse özel Security Advisory mekanizmasını kullanın.

Bir güvenlik raporunda şu bilgiler bulunmalıdır:

- Etkilenen Arch Guard sürümü
- Etkilenen bileşen
- Yeniden üretme adımları
- Beklenen ve gerçekleşen davranış
- Güvenlik etkisi
- Root veya yükseltilmiş yetki gerekip gerekmediği

Özel anahtar, parola, token veya ilgisiz kişisel logları rapora eklemeyin.

## Güvenlik sınırları

- Arch Guard bir firewall değildir.
- SSH sertleştirmesinin yerine geçmez.
- Suricata kural bakımının yerine geçmez.
- Heuristik Tailscale eşlemesi kesin kimlik kanıtı değildir.

## Yerel veriler

Korunması gereken varsayılan yollar:

- `/etc/arch-guard/config.toml`
- `/var/log/arch-guard/events.jsonl`
- `/var/log/arch-guard/incidents/`

Olay anlık görüntüleri yerel sistem ve ağ bilgileri içerebilir. Herkese açık paylaşmadan önce içeriklerini kontrol edin.

## Yetkili test

Arch Guard yalnızca sahibi olduğunuz veya açıkça test izniniz bulunan sistemlerde kullanılmalıdır.
