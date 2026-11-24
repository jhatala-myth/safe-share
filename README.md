# Safe Share – jednorazowe udostępnianie sekretów

Portal do bezpiecznego przekazywania haseł, certyfikatów i kluczy przez jednorazowy,
wygasający link. Szyfrowanie odbywa się **w przeglądarce** (zero-knowledge):
serwer przechowuje wyłącznie szyfrogram.

```
https://share.example.com/s/<ID>#<KLUCZ>
                             │     └─ fragment URL – przeglądarka NIE wysyła go do serwera
                             └─ identyfikator rekordu (192 bity losowości)
```

## Architektura

```
 Internet ──443──▶ nginx (TLS, rate-limit, redakcja logów) ──▶ app (FastAPI) ──▶ Redis (RAM, TTL)
                   sieć "edge"                 sieć "frontend" (internal)   sieć "backend" (internal)
```

| Komponent | Rola | Hardening |
|---|---|---|
| **nginx** (`nginx-unprivileged`) | terminacja TLS 1.2/1.3, HSTS, przekierowanie 80→443, rate limiting, ograniczenie dostępu do tworzenia, logi bez ID sekretów | non-root (UID 101), read-only FS, `cap_drop: ALL` |
| **app** (FastAPI/uvicorn) | API + strony, CSP/SRI, atomowy odczyt-i-usunięcie | non-root (UID 10001), read-only FS, brak dostępu do internetu, brak access logu |
| **Redis** | magazyn z natywnym TTL | tylko RAM (bez RDB/AOF), hasło, `noeviction`, wyłączone `CONFIG`/`DEBUG`, sieć wewnętrzna |

## Model bezpieczeństwa

- **AES-256-GCM** w przeglądarce (WebCrypto). Losowy klucz 256-bit tylko we fragmencie `#`.
- **Hasło dodatkowe (opcjonalne)**: klucz = PBKDF2-SHA256(klucz‖hasło, sól, 600 000 iteracji).
  Przekazywane innym kanałem, więc sam przechwycony link nie wystarcza.
- **Jednorazowość**: skrypt Lua w Redis sprawdza token i usuwa rekord w jednej atomowej operacji.
- **Dowód posiadania klucza**: odczyt wymaga `X-Reveal-Token = SHA-256("safeshare-v1:reveal:"‖klucz)`.
  Osoba znająca tylko ID (np. z logów) nie może ani odczytać, ani „spalić” sekretu.
- **Boty podglądu linków** (Slack, Teams, Outlook Safe Links) otwierają `GET /s/...`, ale
  ta strona niczego nie kasuje. Odczyt następuje dopiero po kliknięciu „Pokaż sekret” (POST).
- **Błędne hasło dodatkowe**: szyfrogram zostaje w pamięci strony, więc można spróbować ponownie
  bez utraty danych (dopóki karta jest otwarta).
- Po odczycie klucz jest usuwany z paska adresu i historii (`history.replaceState`).
- **Unieważnienie**: nadawca dostaje jednorazowy `delete_token` i może usunąć sekret przed odczytem.
- Serwer przechowuje tylko szyfrogram, IV, sól i **skróty** tokenów. Nie zna treści, klucza ani tokenów.
- Ten sam `404 not_found` dla: nieistniejący / wygasły / odczytany / zły token.
- Nagłówki: ścisłe CSP (bez `inline`, Trusted Types), SRI na JS/CSS, `no-store`,
  `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`, HSTS.

## Uruchomienie

```bash
# 1. certyfikat (szczegóły: certs/README.md)
cp /ścieżka/fullchain.pem certs/fullchain.pem
cp /ścieżka/privkey.pem   certs/privkey.pem
sudo chown root:101 certs/privkey.pem && sudo chmod 640 certs/privkey.pem

# 2. konfiguracja
cp .env.example .env
sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(openssl rand -hex 32)|" .env
chmod 600 .env

# 3. nazwa hosta: w nginx/conf.d/safe-share.conf ustaw server_name na swoje FQDN

# 4. (zalecane) ograniczenie, kto może TWORZYĆ sekrety: nginx/snippets/create-access.conf

# 5. start
docker compose up -d --build
docker compose ps
docker compose logs -f nginx
```

Weryfikacja:

```bash
curl -sI https://share.example.com/ | grep -i strict-transport
testssl.sh share.example.com        # lub: https://www.ssllabs.com/ssltest/
```

## API (JSON)

| Metoda | Ścieżka | Nagłówek | Opis |
|---|---|---|---|
| `POST` | `/api/v1/secrets` | – | utwórz: `{v, ciphertext, iv, salt, reveal_token, ttl}` → `{id, path, expires_at, delete_token}` |
| `GET` | `/api/v1/secrets/{id}` | `X-Reveal-Token` | metadane (`expires_at`, `passphrase`), **bez** usuwania |
| `POST` | `/api/v1/secrets/{id}/reveal` | `X-Reveal-Token` | zwraca szyfrogram i **usuwa** sekret |
| `DELETE` | `/api/v1/secrets/{id}` | `X-Delete-Token` | unieważnienie przez nadawcę |

Dane w API są zawsze zaszyfrowane. Odszyfrowanie robi przeglądarka albo klient CLI.

## Ikony i grafika

`app/safeshare/static/img/`:

| Plik | Użycie |
|---|---|
| `icon.svg` | favicon (nowoczesne przeglądarki), logo w nagłówku, manifest |
| `favicon.ico` (16/32/48), `apple-touch-icon.png` (180), `icon-192.png`, `icon-512.png` | starsze przeglądarki, iOS, Android / PWA |
| `create.svg` | strona tworzenia: dane → szyfrowanie AES-256 → jednorazowy link z czasem ważności |
| `reveal.svg` | strona odbioru: zapieczętowana koperta „1×” |
| `gone.svg` | sekret niedostępny (odczytany / wygasły) |

Ilustracje to własne pliki SVG bez zewnętrznych zasobów (zgodne z CSP). Same przełączają kolory
w trybie ciemnym (`prefers-color-scheme`). Kolor przewodni to `#1f5fd1`; aby go zmienić, edytuj
klasy `.acc` / `.dot` w plikach SVG oraz `--accent` w `style.css`. PNG/ICO po zmianie ikony
wygenerujesz poleceniem `rsvg-convert -w 512 icon.svg -o icon-512.png` (analogicznie dla innych rozmiarów).

## Klient CLI (`cli/safeshare_cli.py`)

Wymaga `pip install cryptography`. Szyfruje lokalnie, ten sam format co przeglądarka.

```bash
# tekst ze stdin
echo -n 'P@ssw0rd' | ./cli/safeshare_cli.py create --url https://share.example.com --ttl 3600

# plik z hasłem dodatkowym (prompt lub $SAFESHARE_PASSPHRASE)
./cli/safeshare_cli.py create --url https://share.example.com --file client.p12 --passphrase --json

# odbiór
./cli/safeshare_cli.py get 'https://share.example.com/s/<id>#<klucz>'                # na stdout
./cli/safeshare_cli.py get '<link>' --json                                          # {"type":"text","text":...}
./cli/safeshare_cli.py get '<link>' --out id_ed25519                                # plik 0600

# unieważnienie
./cli/safeshare_cli.py revoke '<link>' --delete-token <token>
```

Opcje: `--ca-bundle ca.pem` (wewnętrzne CA), `SAFESHARE_AUTH_HEADER` (np. `Basic ...`,
gdy tworzenie jest chronione w nginx).

## Konfiguracja (`.env`)

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `REDIS_PASSWORD` | – (wymagane) | hasło Redis |
| `TTL_OPTIONS` | `300,3600,86400,259200,604800` | dozwolone czasy życia (s) |
| `DEFAULT_TTL` | `86400` | domyślny wybór w UI |
| `MAX_PLAINTEXT_BYTES` | `1048576` | maks. rozmiar sekretu/pliku |
| `REDIS_MAXMEMORY` | `256mb` | limit pamięci (po przekroczeniu nowe sekrety są odrzucane) |
| `HTTPS_PORT` / `HTTP_PORT` | `443` / `80` | porty na hoście |

## Rate limiting (nginx, na IP)

| Zakres | Limit |
|---|---|
| tworzenie `POST /api/v1/secrets` | 10/min (burst 5) |
| status / odczyt / unieważnienie | 30/min (burst 10) |
| strony (`/`, `/s/…`) | 120/min (burst 20) |
| pliki statyczne, ikony | bez limitu (jedno otwarcie strony ≈ 8 żądań; biura za NAT) |

Jeśli przed nginx stoi kolejny load balancer, skonfiguruj `real_ip_header` / `set_real_ip_from`,
inaczej limity zadziałają na IP balancera.

## Testy

```bash
cd app && pip install -r requirements.txt pytest httpx "fakeredis[lua]" cryptography
python -m pytest -q tests
```

## Produkcja – lista kontrolna

- [ ] obrazy przypięte po digest (`image: ...@sha256:...`), skan Trivy w CI
- [ ] `server_name` ustawione na FQDN, port 80 tylko dla przekierowania
- [ ] dostęp do tworzenia ograniczony (VPN/IP, Basic auth, docelowo SSO przez oauth2-proxy)
- [ ] monitoring: liczba 404/429 w logach nginx (próby enumeracji)
- [ ] w razie potrzeby anonimizacja IP w logach (RODO)
- [ ] kopia zapasowa **nie jest potrzebna**: sekrety są ulotne z założenia

## Ograniczenia (świadome)

- Przejęty serwer mógłby podać zmodyfikowany JavaScript i wykraść klucz. Ograniczają to SRI,
  podpisywanie obrazów i monitoring integralności, a CLI jest od tego niezależne.
- Endpoint odbiorcy (zainfekowany komputer) jest poza zakresem serwisu.
- Logi błędów nginx (poziom `warn`) mogą w rzadkich przypadkach (np. awaria upstream) zawierać ID.
  Samo ID bez klucza i tokenu jest bezużyteczne.
