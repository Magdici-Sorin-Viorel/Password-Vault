# 🔐 Vault — manager de parole personal

Aplicație web instalabilă pe telefon (PWA). Funcționează **offline**, iar parolele **nu părăsesc niciodată dispozitivul**: totul e criptat local, nu există server și nicio conexiune spre exterior.

## Instalare pe GitHub Pages

1. Pe GitHub: **New repository** → nume `vault` → **Public** → Create. (Codul nu conține nicio parolă; datele stau doar pe telefon.)
2. Urcă fișierele, într-unul din două moduri:
   - **Din browser:** în repository, *Add file → Upload files*, trage în pagină **conținutul** folderului `vault` (fișierele și folderele `icons` și `vendor`, nu folderul `vault` însuși) → *Commit changes*.
   - **Cu git:**
     ```bash
     cd vault
     git init -b main && git add -A && git commit -m "Vault"
     git remote add origin https://github.com/UTILIZATOR/vault.git
     git push -u origin main
     ```
3. **Settings → Pages → Source: Deploy from a branch → `main` / `/ (root)`** → Save.
4. După 1–2 minute aplicația e la `https://UTILIZATOR.github.io/vault/`.
5. Pe telefon, în **Chrome**: deschide adresa → meniul ⋮ → **Instalează aplicația** (sau *Adaugă pe ecranul de pornire*).

> ⚠️ **Toate site-urile GitHub Pages ale aceluiași cont au aceeași „origine”** (`UTILIZATOR.github.io`) și ar putea accesa datele din browser ale acestei aplicații. **Nu publica alte site-uri GitHub Pages pe același cont.** Dacă ai deja, folosește un cont GitHub separat doar pentru Vault.

> ⚠️ Datele sunt legate de adresă **și** de browser. Dacă schimbi adresa sau ștergi datele Chrome, seiful dispare de pe telefon. **Fă periodic export (📤).**

### Rulare locală (pentru test)
```bash
python3 -m http.server 8000
# deschide http://localhost:8000
```
Nu merge deschizând direct `index.html` din fișiere (`file://`) — criptarea browserului cere HTTPS sau localhost.

## Cum funcționează

**Prima pornire:** alegi un PIN (4, 6 sau 8 cifre), înregistrezi amprenta și primești **24 de cuvinte** (standard BIP39, ca la portofelele crypto). Le scrii pe hârtie; aplicația verifică 3 dintre ele.

**Deschidere:** PIN + amprentă, de fiecare dată.

**Greșeli de PIN:**
- 3 greșeli → aplicația se blochează 5 minute
- după numărul ales în Setări (4–10) → pornește **autodistrugerea**: o numărătoare (10 s – 2 min) pe care o poți opri doar cu amprenta. La final, datele de pe telefon se șterg definitiv.
- Încercarea se numără înainte de verificare, iar numărătoarea continuă și dacă închizi aplicația. Aplicația poate fi deschisă într-o singură filă odată, ca limita să nu poată fi ocolită.

**Backup:** butonul 📤 din bara de sus → PIN + amprentă → îl trimiți în Drive prin meniul Partajează.

**Telefon nou:** Restaurează dintr-un backup → fișierul + cele 24 de cuvinte + PIN-ul de atunci → alegi PIN-ul nou și amprenta.

**PIN uitat:** cele 24 de cuvinte → PIN nou.

## Cum sunt protejate datele

| Ce | Cum |
|---|---|
| Seiful pe telefon | AES-256-GCM. Cheia se obține din **PIN (Argon2id, 64 MiB) + secretul amprentei** (WebAuthn PRF). Fără amândouă nu se deschide |
| Backup | Criptat cu o cheie publică ECDH P-256 + PIN. Cheia privată se deschide **doar cu cele 24 de cuvinte** (256 biți). |
| Telefonul și backup-ul | Telefonul păstrează doar cheia publică: **poate crea backup-uri, dar nu le poate deschide**. Cine sparge telefonul nu poate deschide backup-urile din Drive |
| Cele 24 de cuvinte | Nu sunt salvate nicăieri în aplicație. Afișate o singură dată |
| Atacuri din pagină | Content-Security-Policy strict, Trusted Types, fără `innerHTML`, fără conexiuni externe |
| Sesiune | Blocare la inactivitate și în fundal, ecran ascuns în aplicațiile recente, clipboard golit automat |

## Limite (spuse cinstit)
- **Backup-ul** nu poate fi deschis fără cele 24 de cuvinte, oricât de puternic ar fi calculatorul atacatorului. **Păstrează foaia cu cuvintele în siguranță**: cine o are + PIN-ul + fișierul îți poate deschide backup-ul. Dacă o pierzi, nici tu nu-l mai poți deschide.
- **Pe telefon**, Android acceptă PIN-ul telefonului în locul amprentei (limită a aplicațiilor web). Cineva care știe PIN-ul telefonului ȘI are cunoștințe tehnice avansate ar putea încerca PIN-ul aplicației pe un calculator, ocolind autodistrugerea. Argon2id face asta lent (ore/zile). După un furt: schimbă-ți parolele și apasă **Setări → Cheie nouă**.
- Limita de încercări și autodistrugerea funcționează în aplicație. Cine poate copia datele brute ale browserului (telefon deblocat + cunoștințe avansate) le poate ocoli și încerca PIN-uri pe calculator. De aceea contează amprenta și un PIN de 8 cifre.
- Activează **2FA pe contul GitHub**, ca nimeni să nu poată modifica aplicația.

## Actualizări
După orice modificare a codului, mărește `CACHE_VERSION` în `sw.js`, altfel telefonul păstrează versiunea veche din cache. Versiunea nouă se aplică după ce închizi complet aplicația și o redeschizi.

## Structură
```
index.html            pagina + Content-Security-Policy
app.js                interfața și logica
crypto.js             criptografia (Web Crypto + Argon2id)
words.js              lista de 2048 cuvinte BIP39
vendor/               Argon2id (hash-wasm, licență MIT)
style.css             stiluri
sw.js                 service worker (offline)
manifest.webmanifest  instalare ca aplicație
icons/                iconițe
```
