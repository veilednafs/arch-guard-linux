# Arch Guard

Arch Guard, Arch Linux için yerel çalışan host ve ağ güvenliği izleme sistemidir.

## Durum

Güncel sürüm: **0.1.0**

Arch Guard şu kaynakları tek olay hattında birleştirir:

- SSH kimlik doğrulama olayları
- PAM/faillock hesap kilitleri
- Pasif nftables ağ gözlemi
- Port tarama ilişkilendirmesi
- Suricata EVE JSON uyarıları
- İsteğe bağlı Tailscale userspace tarama sensörü

## Mimari

```text
Sensörler -> Normalleştirilmiş olaylar -> İlişkilendirme + politika
                                      -> events.jsonl
                                      -> incident snapshots
                                      -> kullanıcı bildirim servisi
```

Sensörler yalnızca gözlem yapar. Bildirim ve olay anlık görüntüsü kararları politika katmanında verilir.

## Varsayılan yapılandırma

`/etc/arch-guard/config.toml`

Örnek yapılandırma `config/arch-guard.example.toml` dosyasındadır.

## Komutlar

```bash
arch-guard version
arch-guard status
arch-guard doctor
arch-guard events
arch-guard run
arch-guard notify
```

## Güvenlik yaklaşımı

- Ana runtime ile masaüstü bildirim süreci ayrıdır.
- nftables sensörü pasiftir; trafik engellemez.
- Tailscale cihaz eşlemesi gerektiğinde `heuristic` olarak işaretlenir.
- Node ID ve User ID normalize edilmiş olaylara eklenmez.
- Arch Guard firewall veya SSH sertleştirmesinin yerine geçmez.

## Geliştirme

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests
```

## Lisans

MIT — ayrıntılar için `LICENSE` dosyasına bakın.
