# Database Schema for KeyInfrastructure Project

## 1. Lista tabel z ich kolumnami, typami danych i ograniczeniami

### users
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **username**: VARCHAR(255) UNIQUE NOT NULL
- **password_hash**: VARCHAR(255) NOT NULL (HMAC-SHA256 hash hasła)
- **role**: ENUM('ADMIN', 'USER') NOT NULL DEFAULT 'USER'
- **created_at**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **last_login_at**: TIMESTAMPTZ (NULLABLE, aktualizowane przy logowaniu)

**Ograniczenia**:
- UNIQUE na username
- CHECK na role (tylko 'ADMIN' lub 'USER')

### certificates
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **user_id**: UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
- **serial_number**: VARCHAR(255) UNIQUE NOT NULL (kryptograficznie bezpieczny, generowany w Rust)
- **dn**: TEXT NOT NULL (np. "C=PL,CN=username,O=Organization,OU=Unit")
- **validity_period_days**: INTEGER NOT NULL CHECK (validity_period_days >= 1 AND validity_period_days <= 3650) (min 1 dzień, max 10 lat)
- **hash_algorithm**: ENUM('SHA-256', 'SHA-384', 'SHA-512') NOT NULL
- **status**: ENUM('ACTIVE', 'EXPIRED', 'REVOKED') NOT NULL DEFAULT 'ACTIVE'
- **expiration_date**: TIMESTAMPTZ NOT NULL (obliczane jako created_at + validity_period_days)
- **created_at**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **renewed_count**: INTEGER NOT NULL DEFAULT 0
- **renewal_date**: TIMESTAMPTZ (NULLABLE, aktualizowane przy odnowieniu)

**Ograniczenia**:
- UNIQUE na serial_number
- CHECK na validity_period_days (1-3650 dni)
- CHECK na status (tylko dozwolone wartości)

### private_keys
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **certificate_id**: UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE
- **encrypted_key**: BYTEA NOT NULL (klucz prywatny zaszyfrowany AES-256 z PIN-em użytkownika)
- **salt**: BYTEA NOT NULL (losowa sól dla szyfrowania)

**Ograniczenia**:
- UNIQUE na certificate_id (jeden klucz na certyfikat)

### revoked_certificates
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **certificate_id**: UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE
- **revocation_date**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **reason**: VARCHAR(255) (np. 'KEY_COMPROMISE', 'AFFILIATION_CHANGED')

**Ograniczenia**:
- UNIQUE na certificate_id (certyfikat może być odwołany tylko raz)

### certificate_authority
- **id**: UUID PRIMARY KEY DEFAULT gen_random_uuid()
- **private_key**: BYTEA NOT NULL (klucz prywatny CA, zaszyfrowany hasłem z ENV)
- **password_hash**: VARCHAR(255) NOT NULL (hash hasła CA)
- **created_at**: TIMESTAMPTZ NOT NULL DEFAULT NOW()

**Ograniczenia**:
- Tylko jeden wiersz (id stały, np. '00000000-0000-0000-0000-000000000001')

## 2. Relacje między tabelami

- **users do certificates**: Jeden-do-wielu (jeden użytkownik może mieć wiele certyfikatów)
- **certificates do private_keys**: Jeden-do-jednego (każdy certyfikat ma jeden klucz prywatny)
- **certificates do revoked_certificates**: Jeden-do-jednego (certyfikat może być odwołany tylko raz, jeśli w ogóle)
- **certificate_authority**: Samodzielna tabela (tylko jeden wpis dla CA)

## 3. Indeksy

- **users**:
  - UNIQUE INDEX na username (dla szybkiego wyszukiwania przy logowaniu)
  - INDEX na role (dla zapytań administracyjnych)

- **certificates**:
  - UNIQUE INDEX na serial_number (wymagane dla unikalności)
  - INDEX na user_id (dla zapytań użytkownika o swoje certyfikaty)
  - INDEX na expiration_date (dla powiadomień o wygaśnięciu)
  - COMPOSITE INDEX na (user_id, status) (optymalizacja zapytań użytkownika)
  - COMPOSITE INDEX na (expiration_date, status) (dla zapytań o wygasające certyfikaty)
  - PARTIAL INDEX na expiration_date WHERE status = 'ACTIVE' (tylko aktywne certyfikaty)

- **private_keys**:
  - INDEX na certificate_id (dla szybkiego dostępu do klucza)

- **revoked_certificates**:
  - INDEX na certificate_id (dla sprawdzeń odwołania)
  - INDEX na revocation_date (dla raportów)

## 4. Zasady PostgreSQL (RLS)

- **users**: Brak RLS (administratorzy zarządzają bezpośrednio)
- **certificates**: 
  - Użytkownicy widzą tylko swoje certyfikaty (WHERE user_id = current_user_id())
  - Administratorzy widzą wszystkie certyfikaty
- **private_keys**: 
  - Użytkownicy widzą tylko klucze swoich certyfikatów
  - Administratorzy widzą wszystkie klucze
- **revoked_certificates**: Podobnie jak certificates
- **certificate_authority**: Tylko administratorzy mają dostęp

## 5. Wszelkie dodatkowe uwagi lub wyjaśnienia dotyczące decyzji projektowych

- **Normalizacja**: Schemat jest w 3NF; denormalizacja nie jest wymagana, ponieważ wydajność jest zapewniona przez indeksy i partycjonowanie.
- **Partycjonowanie**: Tabela certificates jest partycjonowana miesięcznie po expiration_date dla lepszej wydajności zapytań o wygasające certyfikaty. Automatyczne tworzenie partycji i czyszczenie starszych niż 2 lata.
- **Szyfrowanie**: Klucze prywatne są szyfrowane AES-256 z PIN-em użytkownika jako kluczem (PIN nie przechowywany w bazie). Klucz CA jest szyfrowany hasłem z ENV.
- **UUID**: Użyte dla globalnej unikalności i bezpieczeństwa (trudniejsze do zgadnięcia niż sekwencyjne ID).
- **Status certyfikatów**: 'ACTIVE' dla ważnych, 'EXPIRED' dla wygasłych, 'REVOKED' dla odwołanych.
- **Rozwiązanie problemów**:
  - PIN: Nie przechowywany; używany tylko do szyfrowania PKCS#12 przy pobieraniu.
  - Pola DN: Standardowe (C, CN, O, OU, itp.), przechowywane jako ciąg tekstowy.
  - Kopia klucza: Zaszyfrowana kopia w private_keys.
  - Algorytm klucza: RSA 4096 (hardkodowany w backendzie).
  - Okres ważności: 1 dzień do 10 lat.
- **Wydajność**: Zoptymalizowana dla 100 użytkowników, 10 certyfikatów na użytkownika, 10 współbieżnych użytkowników poprzez indeksy i partycjonowanie.
- **Rozszerzenia PostgreSQL**: Wymagane: pgcrypto dla szyfrowania, uuid-ossp dla UUID.