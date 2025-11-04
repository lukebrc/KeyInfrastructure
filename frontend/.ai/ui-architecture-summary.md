# Podsumowanie planowania architektury UI - KeyInfrastructure MVP

<conversation_summary>

<decisions>
1. **Struktura aplikacji:** Aplikacja będzie miała oddzielne ścieżki dla administratora i użytkownika, ale wspólne okno logowania. Oznacza to osobne sekcje `/admin/*` i `/dashboard` (dla użytkowników), przy zachowaniu wspólnego endpointu `/login`.

2. **Przepływ rejestracji i logowania:** Rejestracja dostępna publicznie na `/register` z formularzem (username, password, PIN min 8 znaków). Po udanej rejestracji automatyczne logowanie przez POST /auth/login i przekierowanie na dashboard. Wspólna strona logowania `/login` obsługująca obie role (USER/ADMIN) z czytelnymi komunikatami błędów.

3. **Zarządzanie tokenem JWT:** Token JWT przechowywany w httpOnly cookie (nie sessionStorage), zapewniający większe bezpieczeństwo przed atakami XSS. Automatyczne wylogowanie przy wygaśnięciu tokenu (401) z przekierowaniem na `/login`. Middleware w Astro chroniący wszystkie strony wymagające autoryzacji (oprócz `/login` i `/register`).

4. **Optymalizacja wydajności:** Domyślna optymalizacja w bazie danych wystarczy dla MVP. Brak konieczności implementacji zaawansowanych mechanizmów buforowania po stronie frontendu (React Query) - standardowe żądania API są akceptowalne.

5. **Responsywność i dostępność:** Mobile-first approach z Tailwind CSS. Wszystkie interaktywne elementy minimum 44x44px touch target. Formularze responsywne (kolumny na desktop, stack na mobile). Brak wymogu pełnej implementacji ARIA labels i keyboard navigation w MVP (można uprościć w porównaniu do pierwotnych zaleceń).
</decisions>

<matched_recommendations>
1. **Oddzielne ścieżki dla ról:** Rekomendacja dotycząca wspólnego portalu z warunkową nawigacją została odrzucona na rzecz oddzielnych ścieżek dla administratora i użytkownika, co zapewnia wyraźniejszą separację funkcjonalności.

2. **Automatyczne logowanie po rejestracji:** Zalecenie automatycznego logowania po rejestracji zostało zaakceptowane i będzie zaimplementowane.

3. **Dashboard z tabelą certyfikatów:** Zalecenie dotyczące tabeli/listy certyfikatów z sortowaniem, filtrowaniem i paginacją zostało w pełni zaakceptowane jako część dashboardu użytkownika.

4. **Banner ostrzegawczy:** Rekomendacja dotycząca sticky banneru z wygasającymi certyfikatami została zaakceptowana w całości - banner będzie wysoce widoczny, nie można go całkowicie zamknąć, z aktualizacją co 5-10 minut.

5. **Formularz tworzenia certyfikatu dla admina:** Wszystkie zalecenia dotyczące formularza w `/admin/certificates/create` zostały zaakceptowane, włączając walidację po stronie klienta i podgląd DN.

6. **Modal do pobierania PKCS#12:** Zalecenie dotyczące modala z polem PIN do pobierania certyfikatów zostało zaakceptowane, włączając bezpieczne zarządzanie PIN w pamięci.

7. **Centralny system obsługi błędów:** Zalecenie implementacji centralnego systemu obsługi błędów z toast notifications i inline error messages zostało w pełni zaakceptowane.

8. **Mobile-first i responsywność:** Podstawowe zalecenia dotyczące mobile-first approach i responsywności zostały zaakceptowane, choć bez pełnej implementacji wszystkich aspektów dostępności (ARIA, keyboard navigation).
</matched_recommendations>

<ui_architecture_planning_summary>

### a) Główne wymagania dotyczące architektury UI

**Struktura aplikacji:**
- Oddzielne ścieżki dla użytkowników (`/dashboard`, `/certificates/*`) i administratorów (`/admin/*`)
- Wspólna strona logowania (`/login`) obsługująca obie role
- Publiczna strona rejestracji (`/register`) dostępna dla nowych użytkowników

**Uwierzytelnianie i autoryzacja:**
- JWT token przechowywany w httpOnly cookie
- Middleware w Astro chroniący chronione ścieżki
- Automatyczne przekierowanie na `/login` przy wygaśnięciu sesji (401)
- Opcjonalny timer odliczający czas do wygaśnięcia sesji

**Integracja z API:**
- Bezpośrednia komunikacja z backend REST API (Rust/actix-web)
- Standardowe żądania HTTP bez zaawansowanego buforowania (dla MVP)
- Centralny system obsługi błędów z mapowaniem kodów HTTP na komunikaty użytkownika

### b) Kluczowe widoki, ekrany i przepływy użytkownika

**Przepływ użytkownika (USER):**
1. **Strona główna/Welcome** (`/`) - publiczna strona z linkami do logowania i rejestracji
2. **Rejestracja** (`/register`) - formularz: username, password, PIN (min 8 znaków) → automatyczne logowanie → przekierowanie na dashboard
3. **Logowanie** (`/login`) - formularz: username, password → przekierowanie na `/dashboard` (USER) lub `/admin/dashboard` (ADMIN)
4. **Dashboard użytkownika** (`/dashboard`):
   - Sticky banner z wygasającymi certyfikatami (jeśli istnieją) - wysoce widoczny, nie można całkowicie zamknąć, przycisk "Renew Now"
   - Tabela/listę certyfikatów z:
     - Sortowaniem po `expiration_date` (domyślnie rosnąco)
     - Filtrowaniem po statusie (ACTIVE/REVOKED)
     - Paginacją (10-20 certyfikatów na stronę)
     - Kolumny: serial_number, DN (skrócony), status (z kolorem), expiration_date (z wyróżnieniem wygasających)
     - Przyciski akcji: "Renew" (dla aktywnych bliskich wygaśnięciu), "Download" (dla wszystkich aktywnych)
5. **Odnawianie certyfikatu** - przepływ inicjowany z dashboardu (PUT /certificates/{id}/renew)
6. **Pobieranie certyfikatu** - modal z polem PIN → POST /certificates/{id}/download → automatyczne pobranie pliku .p12/.pfx

**Przepływ administratora (ADMIN):**
1. **Logowanie** (`/login`) - wspólne z użytkownikami, przekierowanie na `/admin/dashboard`
2. **Dashboard administratora** (`/admin/dashboard`) - przegląd systemu (szczegóły do określenia)
3. **Tworzenie certyfikatu** (`/admin/certificates/create`):
   - Formularz z polami:
     - Select użytkownika (lista wszystkich użytkowników)
     - Pole numeryczne: `validity_period_days` (1-3650 dni, walidacja)
     - Dropdown: `hash_algorithm` (SHA-256, SHA-384, SHA-512)
     - Formularz DN: CN (wymagane), OU, O, L, ST, C (opcjonalne)
   - Podgląd DN przed zatwierdzeniem
   - Walidacja po stronie klienta
   - Komunikat sukcesu z numerem seryjnym po utworzeniu
4. **Zarządzanie certyfikatami** - lista wszystkich certyfikatów z możliwością revokacji (PUT /certificates/{id}/revoke)

**Komponenty UI:**
- Tabele certyfikatów (z sortowaniem, filtrowaniem, paginacją)
- Formularze rejestracji i logowania
- Modal do pobierania certyfikatów (z polem PIN)
- Formularz tworzenia certyfikatu (admin)
- Banner ostrzegawczy (sticky, nie można całkowicie zamknąć)
- Toast notifications (Shadcn/ui) dla błędów operacyjnych
- Inline error messages w formularzach

### c) Strategia integracji z API i zarządzania stanem

**Endpointy API wykorzystywane w UI:**

**Uwierzytelnianie:**
- `POST /users` - rejestracja nowego użytkownika
- `POST /auth/login` - logowanie, zwraca JWT token
- `GET /users/{id}` - pobranie danych użytkownika

**Zarządzanie certyfikatami:**
- `GET /certificates` - lista certyfikatów użytkownika (paginacja, filtrowanie, sortowanie)
- `GET /certificates/expiring` - certyfikaty wygasające (dla bannera, parametr `days=30`)
- `PUT /certificates/{id}/renew` - odnowienie certyfikatu
- `POST /certificates/{id}/download` - pobranie PKCS#12 (wymaga PIN w body)
- `POST /users/{user_id}/certificates` - tworzenie certyfikatu (admin)
- `PUT /certificates/{id}/revoke` - revokacja certyfikatu (admin)

**Zarządzanie stanem:**
- Token JWT w httpOnly cookie (zarządzany przez backend lub przez Astro middleware)
- Stan uwierzytelniania weryfikowany przed każdym żądaniem API
- Brak zaawansowanego buforowania danych (dla MVP) - standardowe żądania przy każdym załadowaniu widoku
- Banner z wygasającymi certyfikatami: polling co 5-10 minut w tle

**Obsługa błędów:**
- Centralny system obsługi błędów z mapowaniem kodów HTTP:
  - `400` - błędy walidacji (konkretne komunikaty w formularzach)
  - `401` - brak autoryzacji (przekierowanie na `/login`)
  - `403` - brak uprawnień (komunikat "Brak uprawnień")
  - `404` - nie znaleziono (komunikat "Nie znaleziono")
  - `409` - konflikt (np. "Użytkownik już istnieje")
- Toast notifications (Shadcn/ui) dla błędów operacyjnych
- Inline error messages w formularzach
- Fallback UI dla błędów sieciowych (timeout, brak połączenia) z możliwością ponowienia żądania

### d) Kwestie dotyczące responsywności, dostępności i bezpieczeństwa

**Responsywność:**
- Mobile-first approach z Tailwind CSS
- Formularze: kolumny na desktop, stack na mobile
- Tabele certyfikatów: scrollowalne poziomo na mobile (lub przekształcone w karty w przyszłości)
- Banner ostrzegawczy: tekst skrócony na mobile, przycisk pełnej szerokości
- Wszystkie interaktywne elementy: minimum 44x44px touch target

**Dostępność (MVP - uproszczona):**
- Podstawowa responsywność zapewniona
- Touch target zgodny z wytycznymi mobilnymi
- Kolory z odpowiednim kontrastem
- Brak pełnej implementacji ARIA labels i keyboard navigation w MVP (można dodać w przyszłości)

**Bezpieczeństwo:**
- Token JWT w httpOnly cookie (ochrona przed XSS)
- Middleware w Astro chroniący chronione ścieżki
- Automatyczne wylogowanie przy wygaśnięciu sesji
- PIN nie przechowywany w localStorage ani state dłużej niż konieczne
- Walidacja po stronie klienta przed wysłaniem formularzy
- Secure handling danych binarnych (PKCS#12) przy pobieraniu

### e) Struktura techniczna i implementacja

**Stack technologiczny:**
- **Framework:** Astro 5 (server-side rendering, middleware)
- **Komponenty interaktywne:** React 19
- **Stylowanie:** Tailwind CSS 4
- **Komponenty UI:** Shadcn/ui (React components)
- **TypeScript:** 5 (typowanie statyczne)

**Struktura projektu (frontend):**
- `/src/pages/` - strony Astro (routing)
  - `/` - strona główna
  - `/login` - logowanie
  - `/register` - rejestracja
  - `/dashboard` - dashboard użytkownika
  - `/admin/*` - sekcja administratora
- `/src/components/` - komponenty (Astro + React)
  - Komponenty statyczne: Astro
  - Komponenty interaktywne: React (formularze, tabele, modale)
- `/src/middleware/` - middleware Astro (ochrona ścieżek, weryfikacja JWT)
- `/src/lib/` - serwisy i helpers (API client, error handling)
- `/src/types.ts` - wspólne typy TypeScript (DTOs, Entities)

**Kluczowe komponenty do implementacji:**
1. `AuthMiddleware` - middleware Astro do weryfikacji JWT
2. `LoginForm` - formularz logowania (React)
3. `RegisterForm` - formularz rejestracji (React)
4. `CertificateTable` - tabela certyfikatów z sortowaniem/filtrowaniem/paginacją (React)
5. `ExpiringBanner` - banner z wygasającymi certyfikatami (React)
6. `DownloadCertificateModal` - modal do pobierania z polem PIN (React)
7. `CreateCertificateForm` - formularz tworzenia certyfikatu dla admina (React)
8. `ErrorHandler` - centralny system obsługi błędów
9. `ToastNotifications` - komponent toastów (Shadcn/ui)

</ui_architecture_planning_summary>

<unresolved_issues>
1. **Endpoint do pobierania listy użytkowników dla admina:** W formularzu tworzenia certyfikatu potrzebny jest select z listą wszystkich użytkowników. W planie API nie ma endpointu `GET /users` dla administratora. Należy określić, czy taki endpoint będzie dostępny, czy lista użytkowników będzie pobierana w inny sposób.

2. **Szczegóły dashboardu administratora:** Zdecydowano o oddzielnej ścieżce `/admin/*` dla administratora, ale szczegóły zawartości dashboardu administratora (`/admin/dashboard`) nie zostały określone. Należy zdecydować, jakie informacje i statystyki powinny być wyświetlane.

3. **Mechanizm refresh token:** W odpowiedzi dotyczącej zarządzania JWT wspomniano o "refresh token mechanism", ale nie określono, czy będzie zaimplementowany w MVP. Plan API nie zawiera endpointu do odświeżania tokenów. Należy wyjaśnić, czy refresh token będzie częścią MVP, czy tylko automatyczne przekierowanie na `/login`.

4. **Walidacja PIN przy pobieraniu:** Endpoint `POST /certificates/{id}/download` zwraca błąd 400 przy nieprawidłowym PIN, ale nie określono, czy backend weryfikuje PIN względem tego zapisanego przy rejestracji, czy względem zaszyfrowanego klucza prywatnego. To ma wpływ na komunikaty błędów w UI.

5. **Format nazwy pliku PKCS#12:** Nie określono, czy nazwa pobieranego pliku powinna zawierać serial_number certyfikatu, DN, czy inną konwencję nazewnictwa (np. `certificate-{serial_number}.p12`).

6. **Ograniczenia paginacji:** Określono paginację 10-20 certyfikatów na stronę, ale nie określono domyślnej wartości ani maksymalnego limitu per page zgodnego z backend API (parametr `limit` w GET /certificates).

7. **Timeout dla polling bannera:** Określono aktualizację bannera co 5-10 minut, ale nie określono dokładnej wartości ani czy polling powinien się zatrzymać, gdy użytkownik nie jest aktywny (np. gdy aplikacja jest w tle).

8. **Obsługa wielu certyfikatów wygasających:** Banner pokazuje informacje o wygasających certyfikatach, ale nie określono, czy powinien wyświetlać wszystkie certyfikaty w jednym bannerze, czy tylko najbliższy termin wygaśnięcia z linkiem do pełnej listy.

</unresolved_issues>

</conversation_summary>
