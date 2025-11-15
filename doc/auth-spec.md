# Specyfikacja Techniczna: Moduł Rejestracji i Logowania

Niniejszy dokument opisuje architekturę i implementację funkcjonalności rejestracji i logowania użytkowników dla projektu KeyInfrastructure, zgodnie z wymaganiami PRD i zdefiniowanym stosem technologicznym.

## 1. Architektura Interfejsu Użytkownika (Frontend)

Architektura UI opiera się na integracji stron generowanych przez Astro z interaktywnymi komponentami React, dostarczanymi przez bibliotekę `shadcn/ui`.

### 1.1. Zmiany w Strukturze Stron i Layoutów

Wprowadzone zostaną dwie główne ścieżki/layouty w aplikacji: dla użytkowników nieuwierzytelnionych (`/login`, `/register`) oraz uwierzytelnionych (`/dashboard`, `/admin/*`).

*   **Layout Nieuwierzytelniony (`src/layouts/PublicLayout.astro`):**
    *   Prosty layout zawierający podstawowy nagłówek z logo aplikacji oraz stopkę.
    *   Nie będzie zawierał nawigacji do chronionych części serwisu.
    *   Będzie używany przez strony `/login` i `/register`.

*   **Layout Uwierzytelniony (`src/layouts/AppLayout.astro`):**
    *   Rozszerzy istniejący layout aplikacji.
    *   Będzie zawierał nawigację specyficzną dla roli użytkownika (USER lub ADMIN), pobranej z tokenu JWT.
    *   W nagłówku znajdzie się nazwa zalogowanego użytkownika oraz przycisk "Wyloguj".

### 1.2. Nowe i Zmodyfikowane Strony (Astro)

*   **Strona Logowania (`src/pages/login.astro`):**
    *   **Cel:** Umożliwienie logowania użytkownikom i administratorom.
    *   **Struktura:** Wykorzysta `PublicLayout.astro`. Będzie renderować po stronie serwera kontener dla formularza logowania.
    *   **Komponenty:** Będzie osadzać kliencki komponent `<LoginForm client:load />`.
    *   **Logika:** Middleware Astro będzie automatycznie przekierowywać już zalogowanych użytkowników ze strony `/login` na odpowiedni dashboard (`/dashboard` lub `/admin/dashboard`).

*   **Strona Rejestracji (`src/pages/register.astro`):**
    *   **Cel:** Umożliwienie samodzielnej rejestracji nowym użytkownikom.
    *   **Struktura:** Wykorzysta `PublicLayout.astro`.
    *   **Komponenty:** Będzie osadzać kliencki komponent `<RegisterForm client:load />`.
    *   **Logika:** Podobnie jak strona logowania, będzie przekierowywać zalogowanych użytkowników.

### 1.3. Komponenty Interaktywne (React)

Komponenty te będą odpowiedzialne za całą interakcję z użytkownikiem, zarządzanie stanem formularza, walidację i komunikację z API.

*   **Komponent `RegisterForm` (`src/components/auth/RegisterForm.tsx`):**
    *   **Odpowiedzialność:** Zarządzanie stanem formularza rejestracji, walidacja i obsługa komunikacji z API.
    *   **Pola formularza:**
        *   `username`: `string`
        *   `password`: `string` (typ `password`)
        *   `pin`: `string` (typ `password`)
    *   **Walidacja (client-side, z użyciem biblioteki np. `zod`):**
        *   `username`: pole wymagane.
        *   `password`: pole wymagane, minimum 8 znaków.
        *   `pin`: pole wymagane, minimum 8 znaków.
    *   **Obsługa Błędów:**
        *   Wyświetlanie komunikatów walidacji pod odpowiednimi polami (np. "Hasło musi mieć co najmniej 8 znaków").
        *   Obsługa błędów z API:
            *   `409 Conflict`: Wyświetlenie komunikatu "Nazwa użytkownika jest już zajęta."
            *   `400 Bad Request`: Wyświetlenie ogólnego komunikatu o błędnych danych.
            *   `500 Internal Server Error`: Wyświetlenie komunikatu "Wystąpił błąd serwera. Spróbuj ponownie później."
    *   **Scenariusze:**
        1.  **Pomyślna rejestracja:** Po otrzymaniu odpowiedzi `201 Created` z `POST /users`, komponent automatycznie wywoła `POST /auth/login` z danymi użytkownika. Po pomyślnym zalogowaniu, nastąpi przekierowanie na stronę `/dashboard` za pomocą `window.location.href`.
        2.  **Nieudana rejestracja:** Wyświetlenie odpowiedniego komunikatu o błędzie (np. za pomocą komponentu `Toast` z `shadcn/ui`).

*   **Komponent `LoginForm` (`src/components/auth/LoginForm.tsx`):**
    *   **Odpowiedzialność:** Zarządzanie stanem formularza logowania i obsługa komunikacji z API.
    *   **Pola formularza:**
        *   `username`: `string`
        *   `password`: `string` (typ `password`)
    *   **Walidacja (client-side):**
        *   Wszystkie pola są wymagane.
    *   **Obsługa Błędów:**
        *   `401 Unauthorized`: Wyświetlenie komunikatu "Nieprawidłowa nazwa użytkownika lub hasło."
        *   Inne błędy (400, 500) będą obsługiwane analogicznie jak w formularzu rejestracji.
    *   **Scenariusze:**
        1.  **Pomyślne logowanie:** Po otrzymaniu odpowiedzi `200 OK` z `POST /auth/login` zawierającej token JWT, komponent dokona przeładowania strony (`window.location.reload()`). Backend ustawi token w ciasteczku `httpOnly`, a middleware Astro po przeładowaniu przekieruje użytkownika na właściwą stronę na podstawie roli w tokenie.
        2.  **Nieudane logowanie:** Wyświetlenie komunikatu o błędzie.

## 2. Logika Backendowa (Rust / actix-web)

Backend będzie odpowiedzialny za logikę biznesową, walidację po stronie serwera oraz bezpieczną komunikację z bazą danych.

### 2.1. Struktura Endpointów API

Zmiany będą dotyczyć istniejących endpointów z `rest-plan.md`.

*   **`POST /users` - Rejestracja użytkownika**
    *   **Model Danych (Request Body):**
        ```rust
        // src/models/dto.rs
        #[derive(Deserialize, Validate)]
        pub struct RegisterUserDto {
            #[validate(length(min = 1, message = "Username is required"))]
            pub username: String,
            #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
            pub password: String,
            #[validate(length(min = 8, message = "PIN must be at least 8 characters long"))]
            pub pin: String, // PIN nie jest zapisywany w bazie, używany tylko do szyfrowania klucza
        }
        ```
    *   **Logika:**
        1.  Walidacja `RegisterUserDto` przy użyciu `validator`.
        2.  Sprawdzenie, czy użytkownik o podanej nazwie już istnieje w tabeli `users`. Jeśli tak, zwróć `409 Conflict`.
        3.  Haszowanie hasła użytkownika (np. przy użyciu biblioteki `argon2` lub `bcrypt`).
        4.  Utworzenie nowego rekordu w tabeli `users` z `username`, `password_hash` i domyślną rolą `USER`.
        5.  Zwrócenie `201 Created`.
    *   **Obsługa Wyjątków:**
        *   Błąd walidacji -> `400 Bad Request`.
        *   Użytkownik istnieje -> `409 Conflict`.
        *   Błąd bazy danych -> `500 Internal Server Error`.

*   **`POST /auth/login` - Logowanie użytkownika**
    *   **Model Danych (Request Body):**
        ```rust
        // src/models/dto.rs
        #[derive(Deserialize, Validate)]
        pub struct LoginUserDto {
            #[validate(length(min = 1))]
            pub username: String,
            #[validate(length(min = 1))]
            pub password: String,
        }
        ```
    *   **Model Danych (Response Body):**
        ```rust
        // src/models/dto.rs
        #[derive(Serialize)]
        pub struct TokenDto {
            pub token: String,
        }
        ```
    *   **Logika:**
        1.  Walidacja `LoginUserDto`.
        2.  Wyszukanie użytkownika w tabeli `users` po `username`. Jeśli nie istnieje, zwróć `401 Unauthorized`.
        3.  Weryfikacja podanego hasła z hashem zapisanym w bazie (`password_hash`). Jeśli się nie zgadza, zwróć `401 Unauthorized`.
        4.  Wygenerowanie tokenu JWT zawierającego `user_id`, `username` i `role`.
        5.  Zaktualizowanie pola `last_login_at` dla użytkownika.
        6.  Zwrócenie `200 OK` z tokenem JWT w ciele odpowiedzi oraz ustawienie go w bezpiecznym ciasteczku `httpOnly`.
    *   **Obsługa Wyjątków:**
        *   Błąd walidacji -> `400 Bad Request`.
        *   Błędne dane logowania -> `401 Unauthorized`.
        *   Błąd generowania tokenu / błąd bazy danych -> `500 Internal Server Error`.

### 2.2. Walidacja Danych Wejściowych

Walidacja będzie realizowana na dwóch poziomach:
1.  **Frontend:** Podstawowa walidacja w czasie rzeczywistym w komponentach React, aby zapewnić natychmiastowy feedback dla użytkownika.
2.  **Backend:** Rygorystyczna walidacja po stronie serwera przy użyciu crate'a `validator` na modelach DTO. Jest to kluczowe zabezpieczenie przed zmanipulowanymi żądaniami.

## 3. System Autentykacji

System będzie oparty na bezstanowych tokenach JWT, co jest zgodne z architekturą REST i stosem technologicznym.

### 3.1. Generowanie i Zarządzanie Tokenem JWT

*   **Biblioteka:** `jsonwebtoken` w Rust.
*   **Klucz Sekretny:** Klucz do podpisywania tokenów będzie ładowany ze zmiennej środowiskowej (`JWT_SECRET`), aby uniknąć hardkodowania go w kodzie.
*   **Payload (Zawartość) Tokenu:**
    ```json
    {
      "sub": "user_id_uuid", // Subject (ID użytkownika)
      "username": "user_login",
      "role": "USER", // lub "ADMIN"
      "exp": 1678886400 // Timestamp wygaśnięcia (np. 1 godzina od wystawienia)
    }
    ```
*   **Przesyłanie Tokenu:** Po pomyślnym logowaniu, backend ustawi token w ciasteczku `httpOnly`, `Secure`, `SameSite=Strict`. Dzięki temu token będzie automatycznie dołączany do kolejnych żądań, a jednocześnie niedostępny dla skryptów JavaScript po stronie klienta, co chroni przed atakami XSS. Frontend nie musi zarządzać przechowywaniem tokenu.

### 3.2. Middleware Autoryzacyjny (actix-web)

Zostanie stworzony middleware dla `actix-web`, który będzie chronił zabezpieczone endpointy.

*   **Logika Middleware:**
    1.  Odczytanie tokenu JWT z ciasteczka w przychodzącym żądaniu.
    2.  Jeśli tokenu nie ma, zwróć `401 Unauthorized`.
    3.  Weryfikacja podpisu i daty wygaśnięcia tokenu przy użyciu `JWT_SECRET`.
    4.  Jeśli token jest nieprawidłowy lub wygasł, zwróć `401 Unauthorized`.
    5.  Jeśli token jest prawidłowy, zdekodowane dane (np. `user_id`, `role`) zostaną dołączone do żądania (np. jako `request extension`), aby były dostępne w handlerach endpointów.
    6.  Opcjonalnie, middleware może sprawdzać wymaganą rolę dla danego endpointu (np. `/admin/*` wymaga roli `ADMIN`) i zwrócić `403 Forbidden` w przypadku braku uprawnień.

### 3.3. Wylogowanie

Wylogowanie będzie realizowane przez usunięcie ciasteczka z tokenem.

*   **Endpoint `POST /auth/logout`:**
    *   Nie wymaga ciała żądania.
    *   **Logika:** Czyści ciasteczko `httpOnly` zawierające token JWT, ustawiając jego datę wygaśnięcia na przeszłą.
    *   **Odpowiedź:** `200 OK`.
*   **Interakcja na Frontendzie:** Przycisk "Wyloguj" w `AppLayout.astro` wywoła ten endpoint, a następnie przekieruje użytkownika na stronę `/login`.