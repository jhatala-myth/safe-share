# Certyfikat TLS

Umieść tutaj:

| Plik            | Zawartość                                                         |
|-----------------|-------------------------------------------------------------------|
| `fullchain.pem` | certyfikat serwera **+ certyfikaty pośrednie** (w tej kolejności) |
| `privkey.pem`   | klucz prywatny (PEM, bez hasła)                                   |

nginx w kontenerze działa jako UID/GID **101**, więc klucz musi być dla niego czytelny,
ale nie dla wszystkich:

```bash
sudo chown root:101 certs/privkey.pem
sudo chmod 640      certs/privkey.pem
chmod 644           certs/fullchain.pem
```

Konwersja z innych formatów:

```bash
# z .pfx/.p12
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.pem
openssl pkcs12 -in cert.pfx -cacerts -nokeys -out chain.pem
openssl pkcs12 -in cert.pfx -nocerts -nodes -out privkey.pem
cat cert.pem chain.pem > fullchain.pem

# sprawdzenie, czy klucz pasuje do certyfikatu (oba skróty muszą być identyczne)
openssl x509 -in fullchain.pem -noout -pubkey | sha256sum
openssl pkey -in privkey.pem -pubout | sha256sum
```

Po odnowieniu certyfikatu: `docker compose exec nginx nginx -s reload`.
