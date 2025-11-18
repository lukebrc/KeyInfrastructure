### Plan Testów dla Aplikacji Backendowej

---

#### 1. Wprowadzenie i Zakres

Niniejszy dokument opisuje plan testów dla aplikacji backendowej, napisanej w języku Rust z wykorzystaniem frameworka `actix-web` i biblioteki `sqlx`. Celem testów jest weryfikacja poprawności implementacji wymagań funkcjonalnych i niefunkcjonalnych zdefiniowanych w dokumencie `prd_summary.md`, a także zapewnienie stabilności, bezpieczeństwa i wydajności systemu.

**Testy obejmą:**
*   Logikę biznesową aplikacji.
*   Punkty końcowe API (RESTful endpoints).
*   Integrację z bazą danych PostgreSQL.
*   Mechanizmy uwierzytelniania i autoryzacji.
*   Obsługę współbieżności i podstawowe testy wydajnościowe.

**Poza zakresem testów znajdują się:**
*   Testy interfejsu użytkownika (frontend).
*   Testy pełnego przepływu E2E z udziałem przeglądarki.
*   Testy infrastruktury (DigitalOcean, Docker).

#### 2. Cele Testów

*   **Weryfikacja Funkcjonalna:** Upewnienie się, że wszystkie wymagania funkcjonalne i historyjki użytkownika zostały zaimplementowane poprawnie.
*   **Weryfikacja Bezpieczeństwa:** Sprawdzenie kluczowych aspektów bezpieczeństwa, takich jak szyfrowanie, uwierzytelnianie i autoryzacja.
*   **Weryfikacja Wydajności:** Potwierdzenie, że backend spełnia zdefiniowane kryteria sukcesu dotyczące współbieżności i pojemności.
*   **Weryfikacja Obsługi Błędów:** Zapewnienie, że API w sposób przewidywalny i spójny obsługuje nieprawidłowe dane wejściowe i stany wyjątkowe.
*   **Weryfikacja Integracji:** Sprawdzenie poprawności współpracy między serwisem a bazą danych.

#### 3. Strategia Testowania

Zgodnie z dokumentem `prd_summary.md`, główny nacisk zostanie położony na testy integracyjne napisane w Rust.

*   **Testy Jednostkowe (Unit Tests):**
    *   **Cel:** Izolowane testowanie poszczególnych funkcji, zwłaszcza tych zawierających złożoną logikę (np. funkcje kryptograficzne, walidacja DN).
    *   **Narzędzia:** Wbudowany framework testowy Rust (`#[test]`).

*   **Testy Integracyjne (Integration Tests):**
    *   **Cel:** Testowanie współpracy między komponentami aplikacji, głównie na poziomie API. Będą symulować żądania HTTP do endpointów i weryfikować odpowiedzi oraz stan bazy danych.
    *   **Narzędzia:** `actix-web::test`, `sqlx` z funkcją `sqlx::test` do zarządzania transakcjami w testach, `tokio` do testów asynchronicznych.
    *   **Środowisko:** Osobna baza danych testowych, inicjalizowana przed uruchomieniem testów.

*   **Testy Obciążeniowe (Load Tests):**
    *   **Cel:** Weryfikacja kryterium sukcesu dotyczącego obsługi 10 współbieżnych użytkowników.
    *   **Narzędzia:** Można wykorzystać testy integracyjne w Rust z `tokio::spawn` do symulacji współbieżnych żądań lub zewnętrzne narzędzie jak `k6` lub `wrk`.

#### 4. Scenariusze Testowe

Poniższe scenariusze bazują na wymaganiach i historyjkach użytkownika.

##### 4.1. Zarządzanie Użytkownikami i Uwierzytelnianie

| ID Testu | Opis | Oczekiwany Rezultat | Priorytet | Typ Testu |
| :--- | :--- | :--- | :--- | :--- |
| **AUTH-01** | Rejestracja nowego użytkownika z poprawnymi danymi (unikalny username, hasło, PIN min. 8 znaków). | Użytkownik zostaje utworzony w bazie danych (status 201). Hasło jest zahashowane. | **Krytyczny** | Integracyjny |
| **AUTH-02** | Próba rejestracji z istniejącym `username`. | Serwer zwraca błąd 409 (Conflict). | Wysoki | Integracyjny |
| **AUTH-03** | Próba rejestracji z PIN-em krótszym niż 8 znaków. | Serwer zwraca błąd 400 (Bad Request) z komunikatem walidacyjnym. | Wysoki | Integracyjny |
| **AUTH-04** | Logowanie z poprawnymi danymi uwierzytelniającymi. | Serwer zwraca token JWT (status 200). | **Krytyczny** | Integracyjny |
| **AUTH-05** | Logowanie z niepoprawnym hasłem. | Serwer zwraca błąd 401 (Unauthorized). | **Krytyczny** | Integracyjny |
| **AUTH-06** | Dostęp do chronionego zasobu (np. `GET /certificates`) bez tokenu. | Serwer zwraca błąd 401 (Unauthorized). | **Krytyczny** | Integracyjny |
| **AUTH-07** | Dostęp do chronionego zasobu z wygasłym tokenem. | Serwer zwraca błąd 401 (Unauthorized). | Wysoki | Integracyjny |
| **AUTH-08** | Dostęp do zasobu administratora (`/admin/*`) przez zwykłego użytkownika. | Serwer zwraca błąd 403 (Forbidden). | **Krytyczny** | Integracyjny |

##### 4.2. Cykl Życia Certyfikatu

| ID Testu | Opis | Oczekiwany Rezultat | Priorytet | Typ Testu |
| :--- | :--- | :--- | :--- | :--- |
| **CERT-01** | Administrator tworzy certyfikat dla użytkownika z poprawnymi danymi (DN, validity, hash). | Certyfikat jest tworzony i zapisywany w bazie danych (status 201). Klucz prywatny jest szyfrowany PIN-em użytkownika i przechowywany. | **Krytyczny** | Integracyjny |
| **CERT-02** | Próba utworzenia certyfikatu dla nieistniejącego użytkownika. | Serwer zwraca błąd 404 (Not Found). | Wysoki | Integracyjny |
| **CERT-03** | Użytkownik pobiera swój certyfikat (PKCS#12) podając poprawny PIN. | Serwer zwraca plik binarny (status 200). Plik jest zaszyfrowany podanym PIN-em. | **Krytyczny** | Integracyjny |
| **CERT-04** | Użytkownik próbuje pobrać certyfikat podając niepoprawny PIN. | Serwer zwraca błąd 400 (Bad Request) z komunikatem o błędnym PIN-ie. | **Krytyczny** | Integracyjny |
| **CERT-05** | Użytkownik próbuje pobrać certyfikat innego użytkownika. | Serwer zwraca błąd 403 (Forbidden) lub 404 (Not Found). | **Krytyczny** | Integracyjny |
| **CERT-06**| Użytkownik inicjuje odnowienie certyfikatu. | Nowy certyfikat jest generowany, stary jest odpowiednio oznaczany (jeśli taka jest logika). | Wysoki | Integracyjny |
| **CERT-07** | Zapytanie do `GET /certificates/expiring` zwraca listę certyfikatów wygasających w ciągu N dni. | Lista zawiera poprawne certyfikaty. Jeśli brak, lista jest pusta. | Wysoki | Integracyjny |

##### 4.3. Testy Współbieżności i Wydajności

| ID Testu | Opis | Oczekiwany Rezultat | Priorytet | Typ Testu |
| :--- | :--- | :--- | :--- | :--- |
| **PERF-01** | Symulacja 10 jednoczesnych logowań różnych użytkowników. | Wszyscy użytkownicy pomyślnie otrzymują tokeny JWT bez błędów i w akceptowalnym czasie (< 500ms). | Wysoki | Obciążeniowy |
| **PERF-02** | Symulacja 10 jednoczesnych zapytań o listę certyfikatów (`GET /certificates`). | Wszystkie zapytania kończą się sukcesem (status 200) bez timeoutów. | Wysoki | Obciążeniowy |

#### 5. Środowisko Testowe i Narzędzia

*   **Język i Framework:** Rust, `actix-web`.
*   **Baza Danych:** Dedykowana instancja PostgreSQL dla testów, zarządzana przez `sqlx-cli` i `sqlx::test`.
*   **Narzędzia Budowania i CI:** GitHub Actions do automatycznego uruchamiania testów (`cargo test`) przy każdym pushu do repozytorium.
*   **Narzędzia Dodatkowe:** `k6` (opcjonalnie) do bardziej zaawansowanych testów obciążeniowych.

#### 6. Ryzyka i Plan Awaryjny

*   **Ryzyko:** Niejasność w obsłudze PIN-u po stronie serwera (zgodnie z `unresolved_issues`). Testy mogą ujawnić lukę w bezpieczeństwie lub błędny przepływ.
    *   **Plan:** Priorytetowe potraktowanie testów `CERT-03` i `CERT-04`. W przypadku wykrycia problemu, konieczna będzie konsultacja z zespołem deweloperskim w celu zmiany architektury.
*   **Ryzyko:** Brak zdefiniowanych ograniczeń dla pól DN i ważności certyfikatu.
    *   **Plan:** Użycie w testach szerokiego zakresu wartości (krótkich, długich, ze znakami specjalnymi) w celu odkrycia potencjalnych problemów z walidacją lub obsługą przez biblioteki kryptograficzne.

---