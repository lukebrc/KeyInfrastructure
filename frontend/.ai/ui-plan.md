# UI Architecture for KeyInfrastructure

## 1. UI Structure Overview

The KeyInfrastructure application consists of two main functional sections: user portal and administrator panel. They share common login and registration pages, but after authentication, users are redirected to appropriate paths based on their role.

**Navigation structure:**
- **Public pages:** `/`, `/login`, `/register` — available to all unauthenticated users
- **User section:** `/dashboard` — main dashboard with certificates
- **Administrator section:** `/admin/*` — administrative panel for certificate and user management

**Authorization pattern:**
All protected paths are secured by Astro middleware, which verifies the validity of the JWT token from httpOnly cookie. When the session expires, the user is automatically redirected to the login page with an expired session message.

**API integration:**
The frontend communicates directly with the backend REST API (Rust/actix-web) via standard HTTP requests. The JWT token is sent in the `Authorization: Bearer <token>` header. For MVP, advanced caching is not required — data is fetched on every view load. The error handling system maps HTTP codes to readable messages for the user.

## 2. View List

### 2.1. View: Welcome Page

**Ścieżka:** `/`

**Główny cel:** 
Publiczna strona powitalna dla niezalogowanych użytkowników, prezentująca podstawowe informacje o systemie i umożliwiająca przejście do logowania lub rejestracji.

**Kluczowe informacje do wyświetlenia:**
- Nazwa systemu (KeyInfrastructure)
- Krótki opis funkcjonalności systemu
- Linki do logowania (`/login`) i rejestracji (`/register`)

**Kluczowe komponenty widoku:**
- `WelcomeHeader` — nagłówek z nazwą systemu
- `WelcomeContent` — opis systemu
- `NavigationLinks` — przyciski/linki do logowania i rejestracji

**UX, dostępność i względy bezpieczeństwa:**
- Responsywny układ z mobile-first approach
- Minimalistyczny design zachęcający do akcji
- Dla zalogowanych użytkowników: automatyczne przekierowanie na odpowiedni dashboard
- Brak wrażliwych danych na stronie publicznej

---

### 2.2. Widok: Rejestracja

**Ścieżka:** `/register`

**Główny cel:**
Umożliwienie nowym użytkownikom samodzielnej rejestracji w systemie poprzez podanie nazwy użytkownika, hasła.

**Kluczowe informacje do wyświetlenia:**
- Formularz rejestracji z polami:
  - Username (wymagane, unikalne)
  - Password (wymagane, minimum 8 znaków)
- Komunikaty walidacji po stronie klienta
- Komunikaty błędów z API (409 — użytkownik już istnieje, 400 — nieprawidłowe dane)

**Kluczowe komponenty widoku:**
- `RegisterForm` — formularz rejestracji (komponent React)
- `InputField` — pola tekstowe z walidacją
- `PasswordField` — pole hasła z możliwością pokazania/ukrycia
- `ErrorMessage` — wyświetlanie błędów walidacji i API
- `SuccessMessage` — komunikat po udanej rejestracji

**UX, dostępność i względy bezpieczeństwa:**
- Walidacja po stronie klienta przed wysłaniem formularza
- Wskazówki dotyczące wymagań (min. 8 znaków dla hasła)
- Po udanej rejestracji: automatyczne logowanie (POST /auth/login) i przekierowanie na `/dashboard`
- Formularz responsywny (kolumny na desktop, stack na mobile)
- Touch target minimum 44x44px dla przycisków

---

### 2.3. Widok: Logowanie

**Ścieżka:** `/login`

**Główny cel:**
Uwierzytelnienie użytkowników (zarówno USER jak i ADMIN) w systemie poprzez podanie nazwy użytkownika i hasła.

**Kluczowe informacje do wyświetlenia:**
- Formularz logowania z polami:
  - Username (wymagane)
  - Password (wymagane)
- Link do rejestracji dla nowych użytkowników
- Komunikaty błędów (401 — nieprawidłowe dane logowania)

**Kluczowe komponenty widoku:**
- `LoginForm` — formularz logowania (komponent React)
- `InputField` — pola tekstowe
- `PasswordField` — pole hasła
- `ErrorMessage` — wyświetlanie błędów uwierzytelniania
- `RegisterLink` — link do strony rejestracji

**UX, dostępność i względy bezpieczeństwa:**
- Po udanym logowaniu: przekierowanie na `/dashboard` (USER) lub `/admin/dashboard` (ADMIN) na podstawie roli z tokenu JWT
- Token JWT zapisywany w httpOnly cookie przez backend
- Komunikaty błędów nie ujawniają, czy użytkownik istnieje (bezpieczeństwo)
- Automatyczne przekierowanie zalogowanych użytkowników na odpowiedni dashboard
- Responsywny układ formularza

---

### 2.4. Widok: Dashboard użytkownika

**Ścieżka:** `/dashboard`

**Główny cel:**
Centralny widok dla użytkowników, prezentujący listę ich certyfikatów, status wygasających certyfikatów oraz umożliwiający zarządzanie certyfikatami (pobieranie, odnawianie).

**Kluczowe informacje do wyświetlenia:**
- **Banner ostrzegawczy** (jeśli istnieją wygasające certyfikaty):
  - Lista certyfikatów wygasających w ciągu 30 dni (z endpointu GET /certificates/expiring)
  - Wyróżnienie kolorystyczne (czerwony/żółty gradient)
  - Przycisk "Renew Now" dla każdego certyfikatu
  - Aktualizacja co 5-10 minut w tle
- **Tabela certyfikatów:**
  - Kolumny: serial_number, DN (skrócony), status (ACTIVE/REVOKED z kolorem), expiration_date (z wyróżnieniem wygasających)
  - Sortowanie domyślnie po expiration_date (rosnąco)
  - Filtrowanie po statusie (ACTIVE/REVOKED)
  - Paginacja (10-20 certyfikatów na stronę, domyślnie 10)
  - Przyciski akcji: "Renew" (dla aktywnych bliskich wygaśnięciu), "Download" (dla wszystkich aktywnych)
- Informacje o użytkowniku (opcjonalnie)
- Przycisk wylogowania

**Kluczowe komponenty widoku:**
- `ExpiringBanner` — sticky banner z wygasającymi certyfikatami (komponent React)
- `CertificateTable` — tabela certyfikatów z sortowaniem, filtrowaniem, paginacją (komponent React)
- `CertificateRow` — pojedynczy wiersz certyfikatu
- `StatusBadge` — badge statusu certyfikatu (ACTIVE/REVOKED)
- `DateDisplay` — wyświetlanie daty wygaśnięcia z wyróżnieniem
- `ActionButtons` — przyciski Renew i Download
- `DownloadCertificateModal` — modal do pobierania certyfikatu
- `UserHeader` — nagłówek z informacjami o użytkowniku
- `LogoutButton` — przycisk wylogowania

**UX, dostępność i względy bezpieczeństwa:**
- Banner nie może być całkowicie zamknięty (można tylko zminimalizować) — ważne dla bezpieczeństwa
- Banner aktualizowany w tle co 5-10 minut (polling GET /certificates/expiring)
- Tabela responsywna — scrollowalna poziomo na mobile
- Skeleton loading podczas pobierania danych
- Toast notifications dla operacji (odnawianie, pobieranie)
- Inline error messages dla błędów operacji
- Automatyczne przekierowanie na `/login` przy wygaśnięciu sesji (401)
- Wszystkie żądania API wymagają ważnego tokenu JWT

---

### 2.5. Widok: Dashboard administratora

**Ścieżka:** `/admin/dashboard`

**Główny cel:**
Centralny widok dla administratorów, prezentujący przegląd systemu i umożliwiający zarządzanie certyfikatami oraz użytkownikami.

**Kluczowe informacje do wyświetlenia:**
- Statystyki systemu (opcjonalnie):
  - Liczba użytkowników
  - Liczba certyfikatów (aktywnych, wygasłych, unieważnionych)
  - Certyfikaty wygasające w ciągu 30 dni
- Linki do głównych funkcji:
  - Tworzenie certyfikatu (`/admin/certificates/create`)
  - Zarządzanie certyfikatami (`/admin/certificates`)
  - Zarządzanie użytkownikami (jeśli dostępne)
- Przycisk wylogowania

**Kluczowe komponenty widoku:**
- `AdminHeader` — nagłówek z informacjami o administratorze
- `StatsCards` — karty ze statystykami (opcjonalnie)
- `AdminNavigation` — nawigacja do głównych funkcji
- `LogoutButton` — przycisk wylogowania

**UX, dostępność i względy bezpieczeństwa:**
- Tylko użytkownicy z rolą ADMIN mają dostęp
- Automatyczne przekierowanie na `/login` przy braku uprawnień (403)
- Responsywny układ z kafelkami nawigacyjnymi
- Skeleton loading podczas pobierania statystyk

---

### 2.6. Widok: Tworzenie certyfikatu (Admin)

**Ścieżka:** `/admin/certificates/create`

**Główny cel:**
Umożliwienie administratorowi utworzenia nowego certyfikatu dla wybranego użytkownika z pełną konfiguracją parametrów.

**Kluczowe informacje do wyświetlenia:**
- Formularz tworzenia certyfikatu:
  - **Select użytkownika** (wymagane) — lista wszystkich użytkowników z systemu
  - **Pole numeryczne:** `validity_period_days` (wymagane, 1-3650 dni, walidacja)
  - **Dropdown:** `hash_algorithm` (wymagane, opcje: SHA-256, SHA-384, SHA-512)
  - **Formularz DN (Distinguished Name):**
    - CN (Common Name) — wymagane
    - OU (Organizational Unit) — opcjonalne
    - O (Organization) — opcjonalne
    - L (Locality) — opcjonalne
    - ST (State/Province) — opcjonalne
    - C (Country) — opcjonalne
  - **Podgląd DN** — wyświetlenie sformatowanego DN przed zatwierdzeniem
- Komunikaty walidacji po stronie klienta
- Komunikaty błędów z API (400 — nieprawidłowe dane, 403 — brak uprawnień)
- Komunikat sukcesu z numerem seryjnym certyfikatu po utworzeniu

**Kluczowe komponenty widoku:**
- `CreateCertificateForm` — formularz tworzenia certyfikatu (komponent React)
- `UserSelect` — dropdown z listą użytkowników
- `NumberInput` — pole numeryczne z walidacją zakresu
- `SelectDropdown` — dropdown dla algorytmu hashowego
- `DNFormFields` — pola formularza DN
- `DNPreview` — podgląd sformatowanego DN
- `ErrorMessage` — wyświetlanie błędów walidacji i API
- `SuccessMessage` — komunikat sukcesu z numerem seryjnym
- `SubmitButton` — przycisk wysłania formularza

**UX, dostępność i względy bezpieczeństwa:**
- Walidacja po stronie klienta przed wysłaniem (POST /users/{user_id}/certificates)
- Wskazówki dotyczące wymagań i zakresów wartości
- Podgląd DN przed zatwierdzeniem zapobiega błędom
- Po udanym utworzeniu: opcja utworzenia kolejnego certyfikatu lub powrót do dashboardu
- Formularz responsywny (kolumny na desktop, stack na mobile)
- Toast notification po udanym utworzeniu
- Tylko użytkownicy z rolą ADMIN mają dostęp

---

### 2.7. Widok: Zarządzanie certyfikatami (Admin)

**Ścieżka:** `/admin/certificates`

**Główny cel:**
Przegląd wszystkich certyfikatów w systemie z możliwością unieważnienia (revoke) przez administratora.

**Kluczowe informacje do wyświetlenia:**
- **Tabela wszystkich certyfikatów:**
  - Kolumny: serial_number, użytkownik (username), DN (skrócony), status (ACTIVE/REVOKED), expiration_date, data utworzenia
  - Sortowanie po expiration_date (domyślnie)
  - Filtrowanie po statusie, użytkowniku
  - Paginacja (10-20 certyfikatów na stronę)
  - Przycisk akcji: "Revoke" (dla aktywnych certyfikatów)
- Modal potwierdzenia revokacji z polem "reason" (opcjonalne)

**Kluczowe komponenty widoku:**
- `AdminCertificateTable` — tabela certyfikatów z sortowaniem, filtrowaniem, paginacją (komponent React)
- `CertificateRow` — pojedynczy wiersz certyfikatu
- `RevokeButton` — przycisk unieważnienia
- `RevokeModal` — modal potwierdzenia z polem reason
- `StatusBadge` — badge statusu certyfikatu
- `FilterControls` — kontrole filtrowania i sortowania

**UX, dostępność i względy bezpieczeństwa:**
- Modal potwierdzenia przed revokacją zapobiega przypadkowym akcjom
- Toast notification po udanej revokacji
- Tabela responsywna — scrollowalna poziomo na mobile
- Tylko użytkownicy z rolą ADMIN mają dostęp
- Skeleton loading podczas pobierania danych

---

## 3. User Journey Map

### 3.1. Registration and First Login Flow (New User)

1. **Użytkownik odwiedza stronę główną (`/`)**
   - Widzi informacje o systemie
   - Kliknie przycisk "Zarejestruj się"

2. **Przejście do rejestracji (`/register`)**
   - Wypełnia formularz: username, password
   - Walidacja po stronie klienta sprawdza wymagania
   - Wysyła żądanie POST /users

3. **Po udanej rejestracji:**
   - Automatyczne logowanie: POST /auth/login z username i password
   - Token JWT zapisany w httpOnly cookie
   - Przekierowanie na `/dashboard`

4. **Dashboard użytkownika (`/dashboard`)**
   - Użytkownik widzi pustą listę certyfikatów (lub komunikat o braku certyfikatów)
   - Oczekuje na utworzenie certyfikatu przez administratora

### 3.2. Przepływ logowania (Istniejący użytkownik)

1. **Użytkownik odwiedza stronę główną (`/`) lub `/login`**
   - Wprowadza username i password
   - Wysyła żądanie POST /auth/login

2. **Po udanym logowaniu:**
   - Token JWT zapisany w httpOnly cookie
   - Przekierowanie na `/dashboard` (USER) lub `/admin/dashboard` (ADMIN) na podstawie roli

3. **Dashboard odpowiedni dla roli:**
   - USER: widok z certyfikatami i bannerem (jeśli są wygasające)
   - ADMIN: panel administracyjny z opcjami zarządzania

### 3.3. Przepływ zarządzania certyfikatami (Użytkownik)

1. **Użytkownik widzi certyfikaty na dashboardzie (`/dashboard`)**
   - Tabela certyfikatów z sortowaniem i filtrowaniem
   - Banner z wygasającymi certyfikatami (jeśli istnieją)

2. **Pobieranie certyfikatu:**
   - Użytkownik klika przycisk "Download" przy certyfikacie
   - Otwiera się modal z polem wpisania hasła
   - Użytkownik wprowadza hasło (min. 8 znaków)
   - Wysyła żądanie POST /certificates/{id}/download z password w body
   - Przeglądarka automatycznie pobiera plik `.p12` lub `.pfx`
   - W przypadku błędu 400 (Invalid password): wyświetla się komunikat błędu

3. **Odnawianie certyfikatu:**
   - Użytkownik widzi banner z wygasającym certyfikatem lub klika "Renew" w tabeli
   - Potwierdza akcję (opcjonalny modal potwierdzenia)
   - Wysyła żądanie PUT /certificates/{id}/renew
   - Toast notification potwierdza sukces
   - Tabela certyfikatów odświeża się automatycznie

### 3.4. Przepływ tworzenia certyfikatu (Administrator)

1. **Administrator loguje się i widzi dashboard (`/admin/dashboard`)**
   - Kliknie link/przycisk "Utwórz certyfikat"

2. **Przejście do formularza (`/admin/certificates/create`)**
   - Wybiera użytkownika z listy (select)
   - Ustawia `validity_period_days` (1-3650)
   - Wybiera `hash_algorithm` (SHA-256, SHA-384, SHA-512)
   - Wypełnia pola DN (CN wymagane, pozostałe opcjonalne)
   - Widzi podgląd DN przed zatwierdzeniem

3. **Wysłanie formularza:**
   - Walidacja po stronie klienta sprawdza wszystkie wymagania
   - Wysyła żądanie POST /users/{user_id}/certificates
   - Wyświetla się komunikat sukcesu z numerem seryjnym
   - Opcja utworzenia kolejnego certyfikatu lub powrót do dashboardu

### 3.5. Przepływ unieważniania certyfikatu (Administrator)

1. **Administrator przegląda certyfikaty (`/admin/certificates`)**
   - Widzi tabelę wszystkich certyfikatów z możliwością filtrowania

2. **Unieważnienie certyfikatu:**
   - Kliknie przycisk "Revoke" przy aktywnym certyfikacie
   - Otwiera się modal potwierdzenia z opcjonalnym polem "reason"
   - Potwierdza akcję
   - Wysyła żądanie PUT /certificates/{id}/revoke z reason w body
   - Toast notification potwierdza sukces
   - Status certyfikatu zmienia się na REVOKED w tabeli

### 3.6. Przepływ obsługi wygaśnięcia sesji

1. **Użytkownik wykonuje akcję wymagającą autoryzacji:**
   - Token JWT wygasł (1 godzina)
   - Backend zwraca 401 Unauthorized

2. **Automatyczne przekierowanie:**
   - Middleware Astro lub handler błędów wykrywa 401
   - Automatyczne przekierowanie na `/login`
   - Wyświetla się komunikat: "Sesja wygasła. Zaloguj się ponownie."

3. **Użytkownik loguje się ponownie:**
   - Wprowadza dane logowania
   - Otrzymuje nowy token JWT
   - Przekierowanie na poprzedni widok (jeśli możliwe) lub dashboard

## 4. Layout and Navigation Structure

### 4.1. Struktura nawigacji głównej

**Publiczne strony (dostępne bez autoryzacji):**
```
/                    → Strona główna (Welcome)
/login               → Logowanie
/register            → Rejestracja
```

**Sekcja użytkownika (wymagana autoryzacja, rola USER):**
```
/dashboard           → Dashboard użytkownika z certyfikatami
```

**Sekcja administratora (wymagana autoryzacja, rola ADMIN):**
```
/admin/dashboard              → Dashboard administratora
/admin/certificates/create    → Tworzenie certyfikatu
/admin/certificates           → Zarządzanie certyfikatami
```

### 4.2. Mechanizm autoryzacji i przekierowań

**Middleware Astro:**
- Chroni wszystkie ścieżki oprócz `/`, `/login`, `/register`
- Weryfikuje token JWT z httpOnly cookie
- Przy braku tokenu lub wygasłym tokenie: przekierowanie na `/login`
- Przy nieprawidłowej roli (np. USER próbuje wejść na `/admin/*`): błąd 403

**Automatyczne przekierowania:**
- Zalogowany użytkownik próbuje wejść na `/login` lub `/register`: przekierowanie na odpowiedni dashboard
- Po udanym logowaniu: przekierowanie na `/dashboard` (USER) lub `/admin/dashboard` (ADMIN)
- Po udanej rejestracji: automatyczne logowanie i przekierowanie na `/dashboard`

### 4.3. Nawigacja w interfejsie

**Dashboard użytkownika:**
- Nagłówek z informacjami o użytkowniku
- Przycisk wylogowania (góra prawy róg)
- Główna zawartość: banner (jeśli istnieje) + tabela certyfikatów

**Panel administratora:**
- Nagłówek z informacjami o administratorze
- Przycisk wylogowania (góra prawy róg)
- Sidebar lub nawigacja górna z linkami:
  - Dashboard
  - Utwórz certyfikat
  - Zarządzaj certyfikatami
- Główna zawartość zmienia się w zależności od wybranej sekcji

### 4.4. Breadcrumbs (opcjonalnie dla MVP)

Dla sekcji administratora można dodać breadcrumbs:
```
Admin > Dashboard
Admin > Certificates > Create
Admin > Certificates > List
```

## 5. Key Components

### 5.1. Komponenty uwierzytelniania

**`LoginForm` (React)**
- Formularz logowania z polami username i password
- Walidacja po stronie klienta
- Obsługa błędów 401
- Przekierowanie po udanym logowaniu

**`RegisterForm` (React)**
- Formularz rejestracji z polami username, password
- Walidacja wymagań (min. 8 znaków)
- Obsługa błędów 400, 409
- Automatyczne logowanie po rejestracji

**`AuthMiddleware` (Astro Middleware)**
- Weryfikacja tokenu JWT z httpOnly cookie
- Chronienie chronionych ścieżek
- Automatyczne przekierowanie na `/login` przy braku autoryzacji

### 5.2. Komponenty certyfikatów

**`ExpiringBanner` (React)**
- Sticky banner na górze dashboardu
- Wyświetla certyfikaty wygasające (GET /certificates/expiring)
- Aktualizacja co 5-10 minut (polling)
- Nie można całkowicie zamknąć (tylko zminimalizować)
- Przyciski "Renew Now" dla każdego certyfikatu
- Wyróżnienie kolorystyczne (czerwony/żółty gradient)

**`CertificateTable` (React)**
- Tabela certyfikatów z sortowaniem, filtrowaniem, paginacją
- Kolumny: serial_number, DN, status, expiration_date
- Przyciski akcji: Renew, Download
- Wyróżnienie wygasających certyfikatów
- Responsywna (scrollowalna poziomo na mobile)
- Integracja z GET /certificates (query params: page, limit, status, sort_by, order)

**`DownloadCertificateModal` (React)**
- Modal z polem password (min. 8 znaków)
- Przycisk pobierania i zamknięcia
- Obsługa POST /certificates/{id}/download
- Automatyczne pobieranie pliku `.p12`/.pfx
- Obsługa błędu 400 (Invalid password)

**`CertificateRow` (React)**
- Pojedynczy wiersz certyfikatu w tabeli
- Wyświetla serial_number, DN (skrócony), status, expiration_date
- Przyciski akcji (Renew, Download)
- Wyróżnienie kolorystyczne statusu i daty wygaśnięcia

**`StatusBadge` (React)**
- Badge statusu certyfikatu (ACTIVE/REVOKED)
- Różne kolory dla różnych statusów
- Dostępność: odpowiedni kontrast i czytelność

### 5.3. Komponenty formularzy

**`CreateCertificateForm` (React)**
- Formularz tworzenia certyfikatu dla administratora
- Pola: user select, validity_period_days, hash_algorithm, DN fields
- Walidacja po stronie klienta
- Podgląd DN przed zatwierdzeniem
- Obsługa POST /users/{user_id}/certificates
- Komunikaty błędów i sukcesu

**`DNFormFields` (React)**
- Pola formularza Distinguished Name
- CN (wymagane), OU, O, L, ST, C (opcjonalne)
- Walidacja i formatowanie

**`DNPreview` (React)**
- Podgląd sformatowanego DN przed zatwierdzeniem
- Format: "C=PL,CN=username,O=Organization,..."

**`UserSelect` (React)**
- Select dropdown z listą wszystkich użytkowników
- Wymaga endpointu GET /users (dla administratora) lub alternatywnego rozwiązania

### 5.4. Komponenty UI wspólne

**`ToastNotifications` (Shadcn/ui)**
- Toast notifications dla operacji (sukces, błąd)
- Używane dla: odnawianie certyfikatu, pobieranie, tworzenie, revokacja
- Automatyczne zamykanie po 5 sekundach (sukces) lub 10 sekundach (błąd)

**`ErrorMessage` (React)**
- Wyświetlanie błędów walidacji i API
- Inline error messages w formularzach
- Czytelne komunikaty dla użytkownika

**`SuccessMessage` (React)**
- Komunikaty sukcesu (np. po utworzeniu certyfikatu)
- Może być częścią toast notification

**`LoadingSkeleton` (React)**
- Skeleton loading podczas pobierania danych
- Używany w tabelach i listach

**`Button` (Shadcn/ui)**
- Wspólny komponent przycisku
- Warianty: primary, secondary, danger
- Touch target minimum 44x44px

**`InputField` (React)**
- Wspólne pole tekstowe z walidacją
- Wsparcie dla błędów i podpowiedzi

**`PasswordField` (React)**
- Pole hasła z możliwością pokazania/ukrycia
- Wskazówki dotyczące wymagań

**`SelectDropdown` (React)**
- Dropdown select z opcjami
- Wsparcie dla wyszukiwania (opcjonalnie)

### 5.5. Komponenty obsługi błędów

**`ErrorHandler` (Utility)**
- Centralny system obsługi błędów
- Mapowanie kodów HTTP na komunikaty:
  - 400: Błędy walidacji (konkretne komunikaty)
  - 401: Przekierowanie na /login z komunikatem
  - 403: "Brak uprawnień"
  - 404: "Nie znaleziono"
  - 409: "Użytkownik już istnieje"
- Obsługa błędów sieciowych (timeout, brak połączenia) z fallback UI

**`NetworkErrorFallback` (React)**
- Fallback UI dla błędów sieciowych
- Przycisk "Spróbuj ponownie"
- Komunikat o problemie z połączeniem

### 5.6. Komponenty nawigacji

**`NavigationHeader` (React/Astro)**
- Nagłówek z informacjami o użytkowniku
- Przycisk wylogowania
- Różne wersje dla USER i ADMIN

**`AdminNavigation` (React)**
- Nawigacja w panelu administratora
- Sidebar lub nawigacja górna z linkami
- Aktywne zaznaczenie bieżącej sekcji

**`LogoutButton` (React)**
- Przycisk wylogowania
- Czyszczenie tokenu JWT
- Przekierowanie na `/login`

---

## 6. PRD Requirements Mapping to UI Elements

### 6.1. User Management

**PRD:** "The system must allow new users to self-register with a username, password, and an 8-character minimum password."
- **Element UI:** `RegisterForm` na `/register` z walidacją password (min. 8 znaków)

**PRD:** "The system must authenticate users based on their username and password."
- **Element UI:** `LoginForm` na `/login` z polami username i password

### 6.2. Administrator Management

**PRD:** "Administrators must have an interface to create new certificates for users."
- **Element UI:** `CreateCertificateForm` na `/admin/certificates/create`

**PRD:** "This interface must allow the administrator to specify the certificate's validity period, hash algorithm (SHA-256, SHA-384, SHA-512), and all Distinguished Name (DN) fields."
- **Element UI:** Pola formularza: `validity_period_days`, `hash_algorithm` dropdown, `DNFormFields`

### 6.3. User-Facing Functionality

**PRD:** "The system must allow authenticated users to download their key/certificate pair in a PKCS#12 file protected by their password."
- **Element UI:** `DownloadCertificateModal` z polem password, integracja z POST /certificates/{id}/download

**PRD:** "The system must display a prominent banner to users whose certificate is near or past its expiration date, prompting them to renew."
- **Element UI:** `ExpiringBanner` na `/dashboard` z polling GET /certificates/expiring

**PRD:** "Users must be able to initiate the certificate renewal process."
- **Element UI:** Przycisk "Renew" w `CertificateTable` i `ExpiringBanner`, integracja z PUT /certificates/{id}/renew

### 6.4. Historia użytkownika

**"As a User, I want to register for an account..."**
- **Element UI:** `/register` → `RegisterForm` → automatyczne logowanie → `/dashboard`

**"As a User, I want to log in to the portal..."**
- **Element UI:** `/login` → `LoginForm` → przekierowanie na `/dashboard`

**"As a User, I want to be clearly notified when my certificate is about to expire..."**
- **Element UI:** `ExpiringBanner` na `/dashboard` z wyróżnieniem kolorystycznym

**"As a User, I want to download my certificate and private key securely..."**
- **Element UI:** Przycisk "Download" → `DownloadCertificateModal` z password → pobranie `.p12`/.pfx

**"As an Administrator, I want to log in to the system..."**
- **Element UI:** `/login` → `LoginForm` → przekierowanie na `/admin/dashboard`

**"As an Administrator, I want to create a new certificate for a user..."**
- **Element UI:** `/admin/certificates/create` → `CreateCertificateForm` → komunikat sukcesu z numerem seryjnym

---

## 7. User Pain Points Solutions

### 7.1. Problem: Użytkownik nie wie, że jego certyfikat wygasa

**Rozwiązanie UI:**
- `ExpiringBanner` na górze dashboardu z wyróżnieniem kolorystycznym
- Banner nie może być całkowicie zamknięty — zawsze widoczny
- Aktualizacja w tle co 5-10 minut
- Wyróżnienie w tabeli certyfikatów (kolorystyczne oznaczenie daty wygaśnięcia)

### 7.2. Problem: Użytkownik nie wie, jak pobrać certyfikat

**Rozwiązanie UI:**
- Wyraźny przycisk "Download" przy każdym aktywnym certyfikacie
- Modal z jasnymi instrukcjami dotyczącymi hasła
- Automatyczne pobieranie pliku po wprowadzeniu poprawnego hasła
- Czytelne komunikaty błędów przy nieprawidłowym haśle

### 7.3. Problem: Administrator popełnia błędy przy tworzeniu certyfikatu (np. błędny DN)

**Rozwiązanie UI:**
- Walidacja po stronie klienta przed wysłaniem formularza
- Podgląd DN przed zatwierdzeniem (`DNPreview`)
- Wskazówki dotyczące wymagań i zakresów wartości
- Czytelne komunikaty błędów z API

### 7.4. Problem: Użytkownik ma wiele certyfikatów i trudno znaleźć właściwy

**Rozwiązanie UI:**
- Tabela z sortowaniem po expiration_date (domyślnie)
- Filtrowanie po statusie (ACTIVE/REVOKED)
- Paginacja dla łatwego przeglądania
- Wyróżnienie kolorystyczne statusu i daty wygaśnięcia

### 7.5. Problem: Sesja wygasa i użytkownik traci pracę

**Rozwiązanie UI:**
- Automatyczne przekierowanie na `/login` z komunikatem o wygasłej sesji
- Opcjonalny timer odliczający czas do wygaśnięcia sesji (dla przyszłych wersji)
- Przycisk wylogowania dla kontroli użytkownika

### 7.6. Problem: Użytkownik zapomina hasło przy pobieraniu certyfikatu

**Rozwiązanie UI:**
- Czytelny komunikat błędu: "Nieprawidłowe hasło"
- Możliwość ponowienia próby bez zamknięcia modala
- Hasło ustawiane tylko podczas rejestracji — użytkownik musi go pamiętać (zgodnie z PRD, przypominanie hasła nie jest w zakresie MVP)

---

## 8. Error States and Edge Cases

### 8.1. Stany błędów API

**400 Bad Request:**
- Walidacja danych (formularze): inline error messages w polach formularza
- Invalid password przy pobieraniu: komunikat w modalu "Nieprawidłowe hasło. Spróbuj ponownie."

**401 Unauthorized:**
- Brak tokenu lub wygasły token: automatyczne przekierowanie na `/login` z komunikatem "Sesja wygasła. Zaloguj się ponownie."
- Nieprawidłowe dane logowania: komunikat "Nieprawidłowa nazwa użytkownika lub hasło" (bez ujawniania, czy użytkownik istnieje)

**403 Forbidden:**
- Brak uprawnień (np. USER próbuje wejść na `/admin/*`): komunikat "Brak uprawnień do wyświetlenia tej strony" + przekierowanie na `/dashboard`

**404 Not Found:**
- Certyfikat nie znaleziony: komunikat "Certyfikat nie został znaleziony"
- Użytkownik nie znaleziony: komunikat "Użytkownik nie został znaleziony"

**409 Conflict:**
- Użytkownik już istnieje przy rejestracji: komunikat "Nazwa użytkownika już istnieje. Wybierz inną."

**500 Internal Server Error:**
- Błąd serwera: komunikat "Wystąpił błąd serwera. Spróbuj ponownie później." + opcja ponowienia

### 8.2. Przypadki brzegowe

**Brak certyfikatów:**
- Dashboard użytkownika wyświetla komunikat: "Nie masz jeszcze żadnych certyfikatów. Administrator utworzy certyfikat dla Ciebie."
- Tabela certyfikatów wyświetla pusty stan z komunikatem

**Brak wygasających certyfikatów:**
- Banner nie jest wyświetlany
- Tabela certyfikatów normalnie funkcjonuje

**Błąd sieciowy (timeout, brak połączenia):**
- Fallback UI z komunikatem "Brak połączenia z serwerem. Sprawdź swoje połączenie internetowe."
- Przycisk "Spróbuj ponownie" dla ponowienia żądania

**Wielu certyfikatów wygasających:**
- Banner wyświetla wszystkie certyfikaty wygasające (lub tylko najbliższy termin z linkiem "Zobacz wszystkie")
- Tabela certyfikatów umożliwia sortowanie i filtrowanie

**Użytkownik próbuje odnowić już unieważniony certyfikat:**
- Przycisk "Renew" nie jest dostępny dla certyfikatów REVOKED
- Komunikat błędu 400: "Certyfikat nie może być odnowiony (status: REVOKED)"

**Administrator próbuje utworzyć certyfikat dla nieistniejącego użytkownika:**
- Walidacja po stronie klienta (select z listą użytkowników zapobiega temu)
- Komunikat błędu 404: "Użytkownik nie został znaleziony"

---

## 9. API Plan Compliance

Wszystkie widoki i komponenty są w pełni zgodne z planem API:

- **POST /users** → `RegisterForm`
- **POST /auth/login** → `LoginForm`
- **GET /users/{id}** → opcjonalnie w headerze dashboardu
- **POST /users/{user_id}/certificates** → `CreateCertificateForm`
- **GET /certificates** → `CertificateTable` (z query params: page, limit, status, sort_by, order)
- **GET /certificates/expiring** → `ExpiringBanner` (z query param: days=30)
- **PUT /certificates/{id}/renew** → przycisk "Renew" w `CertificateTable` i `ExpiringBanner`
- **POST /certificates/{id}/download** → `DownloadCertificateModal` (z password w body)
- **PUT /certificates/{id}/revoke** → przycisk "Revoke" w `AdminCertificateTable` (z reason w body)

**Uwaga:** Endpoint `GET /users` dla administratora (potrzebny w `UserSelect`) nie jest wymieniony w planie API. Należy to rozwiązać przez:
1. Dodanie endpointu `GET /users` do planu API (tylko dla ADMIN)
2. Lub alternatywne rozwiązanie (np. cache użytkowników podczas tworzenia certyfikatu)

---

## 10. Summary

The UI Architecture for KeyInfrastructure MVP provides:

- **Functionality Separation:** Separate paths for users and administrators with common login
- **Security:** JWT token in httpOnly cookie, middleware protecting paths, client-side validation
- **Usability:** Prominent notifications about expiring certificates, intuitive forms, clear error messages
- **Responsiveness:** Mobile-first approach with Tailwind CSS, touch targets 44x44px
- **API Integration:** Full mapping of PRD requirements and API plan to UI elements
- **Error Handling:** Central error handling system with readable messages and fallback UI

The architecture is ready for implementation in Astro 5 with React 19, Tailwind CSS 4, and Shadcn/ui.
