<p align="center"><img src="assets/logo.svg" alt="huntx" width="820"></p>

# huntx

Tek binary bug bounty motoru: keşif, şablon + aktif tespit, deterministik doğrulama,
ve LLM destekli triyaj/rapor — merkezinde in-scope güvenlik kapısıyla. Sıfır runtime
bağımlılık.

```text
                     ┌───────────────────────────────────────────┐
  hedef (scope içi) →│  güvenlik kapısı                          │  hedefe dokunan tek şey
         scope.json →│  scope · rate-limit · blast · authorized  │  fetch istemcisidir;
          kimlikler →│                                           │  başka hiçbir şey değil
                     └───────────────────────────────────────────┘
                                           │
                                           ▼

        discover  →  detect         →  verify       →  intelligence    →  interface
        ────────  →  ──────         →  ──────       →  ────────────    →  ─────────
        recon        templates         re-confirm      EV-ranked plan     dashboard
        crawl        secrets           OOB collab.     attack chains      report md/SARIF
        fuzz         active checks     BOLA / IDOR     FP feedback        mcp · /huntx
        api          greybox           out-of-band     clusters           notify · monitor

         motor bulur  ·  deterministik kontrol kanıtlar  ·  ancak o zaman model triyaj yapar
```

<p align="center">
  <img src="assets/dashboard.png" alt="huntx konsolu: bulgular önem derecesine göre, doğrulanmış kontroller, host görünümü" width="920">
</p>

**Canlı demo:** [talkdedsec.github.io/tlk-huntx](https://talkdedsec.github.io/tlk-huntx/) — aynı dashboard, tarayıcında örnek veriyle çalışıyor.

> huntx zafiyeti kanıtlar, sömürmez. Yalnız sahip olduğun ya da test etmeye yetkili
> olduğun hedeflere çalıştır. scope dosyası ve `--authorized` olmadan aktif komutlar
> çalışmaz. Ayrıntı: [SECURITY.md](SECURITY.md).

## Kurulum

```
go install github.com/talkdedsec/tlk-huntx/cmd/huntx@latest
# ya da: git clone + go build -o huntx ./cmd/huntx
```

## Kullanım

```
huntx --scope scope.json scope check api.acme.com evil.com
huntx --scope scope.json --authorized recon
huntx --scope scope.json --authorized --verify -o findings.jsonl scan
huntx --scope scope.json report findings.jsonl -o report.md
```

## Komutlar

| Komut | İş |
|---|---|
| `scope check` | Hedef scope içinde mi (istek göndermez) |
| `recon` | Pasif subdomain + kapılı probe + graf |
| `full` | Tek atış: recon + crawl + scan + aktif param kontrolleri + plan |
| `scan` | Şablon tespiti + secret tarama (`--verify` ile doğrula) |
| `crawl` | HTML/JS/robots.txt/sitemap.xml'den endpoint ve parametre çıkar |
| `fuzz` | Common-paths kelime listesiyle içerik keşfi (soft-404 farkındalıklı) |
| `api` | GraphQL introspection + OpenAPI/Swagger keşfi |
| `reflect` / `xss` | Yansıyan parametre tespiti (potansiyel XSS) |
| `redirect` | Yaygın parametrelerde açık yönlendirme tespiti |
| `ssrf` | Gömülü collaborator ile OOB SSRF |
| `cmdi` | Collaborator callback ile OOB komut enjeksiyonu |
| `sqli` | Hata tabanlı SQL enjeksiyonu tespiti |
| `ssti` | Sunucu tarafı template enjeksiyonu tespiti |
| `lfi` | Yerel dosya dahil etme / path traversal tespiti |
| `hostheader` | Host-header injection tespiti |
| `bola` | Kimlikler arası nesne-düzeyi yetki testi |
| `greybox` | Kaynak sink'lerini canlı endpoint'lerle eşle |
| `verify` | Deterministik re-confirm (scan içinde `--verify`) |
| `plan` | Bulguları EV'ye göre sırala, saldırı zinciri kur |
| `monitor` | Öncekiyle diff; `--interval` tekrar, `--notify` webhook |
| `feedback` | Triager kararını kaydet, güveni kalibre et |
| `report` | Markdown veya SARIF çıktı |
| `dashboard` | Graf ve bulguların yerel görünümü |
| `coordinate` / `worker` | Dağıtık tarama |
| `mcp` | MCP sunucusu (stdio) |

Aktif komutlar scope dosyası + `--authorized` olmadan çalışmaz. Rate-limit, toplam
istek tavanı ve durum-değiştiren metod bloğu varsayılan açık.

Ayrıntılı geliştirme durumu `DEVAM.md`'de.
