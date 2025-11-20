# Technical Specification: Registration and Login Module

This document describes the architecture and implementation of user registration and login functionality for the KeyInfrastructure project, in accordance with PRD requirements and the defined technology stack.

## 1. User Interface Architecture (Frontend)

The UI architecture is based on integrating Astro-generated pages with interactive React components provided by the `shadcn/ui` library.

### 1.1. Changes in Page and Layout Structure

Two main paths/layouts will be introduced in the application: for unauthenticated users (`/login`, `/register`) and authenticated users (`/dashboard`, `/admin/*`).

*   **Unauthenticated Layout (`src/layouts/PublicLayout.astro`):**
    *   Simple layout containing a basic header with the application logo and footer.
    *   Will not contain navigation to protected parts of the service.
    *   Will be used by `/login` and `/register` pages.

*   **Authenticated Layout (`src/layouts/AppLayout.astro`):**
    *   Will extend the existing application layout.
    *   Will contain navigation specific to the user's role (USER or ADMIN), retrieved from the JWT token.
    *   The header will display the logged-in user's name and a "Logout" button.

### 1.2. New and Modified Pages (Astro)

*   **Login Page (`src/pages/login.astro`):**
    *   **Purpose:** Enable login for users and administrators.
    *   **Structure:** Will use `PublicLayout.astro`. Will render a container for the login form on the server side.
    *   **Components:** Will embed the client component `<LoginForm client:load />`.
    *   **Logic:** Astro middleware will automatically redirect already logged-in users from the `/login` page to the appropriate dashboard (`/dashboard` or `/admin/dashboard`).

*   **Registration Page (`src/pages/register.astro`):**
    *   **Purpose:** Enable self-registration for new users.
    *   **Structure:** Will use `PublicLayout.astro`.
    *   **Components:** Will embed the client component `<RegisterForm client:load />`.
    *   **Logic:** Similar to the login page, will redirect logged-in users.

### 1.3. Interactive Components (React)

These components will be responsible for all user interaction, form state management, validation, and API communication.

*   **`RegisterForm` Component (`src/components/auth/RegisterForm.tsx`):**
    *   **Responsibility:** Managing registration form state, validation, and handling API communication.
    *   **Form Fields:**
        *   `username`: `string`
        *   `password`: `string` (type `password`)
        *   `pin`: `string` (type `password`)
    *   **Validation (client-side, using a library like `zod`):**
        *   `username`: required field.
        *   `password`: required field, minimum 8 characters.
        *   `pin`: required field, minimum 8 characters.
    *   **Error Handling:**
        *   Display validation messages under appropriate fields (e.g., "Password must be at least 8 characters long").
        *   Handle API errors:
            *   `409 Conflict`: Display message "Username is already taken."
            *   `400 Bad Request`: Display general message about invalid data.
            *   `500 Internal Server Error`: Display message "A server error occurred. Please try again later."
    *   **Scenarios:**
        1.  **Successful registration:** After receiving a `201 Created` response from `POST /users`, the component will automatically call `POST /auth/login` with the user's credentials. After successful login, redirect to the `/dashboard` page using `window.location.href`.
        2.  **Failed registration:** Display an appropriate error message (e.g., using the `Toast` component from `shadcn/ui`).

*   **`LoginForm` Component (`src/components/auth/LoginForm.tsx`):**
    *   **Responsibility:** Managing login form state and handling API communication.
    *   **Form Fields:**
        *   `username`: `string`
        *   `password`: `string` (type `password`)
    *   **Validation (client-side):**
        *   All fields are required.
    *   **Error Handling:**
        *   `401 Unauthorized`: Display message "Invalid username or password."
        *   Other errors (400, 500) will be handled similarly to the registration form.
    *   **Scenarios:**
        1.  **Successful login:** After receiving a `200 OK` response from `POST /auth/login` containing the JWT token, the component will reload the page (`window.location.reload()`). The backend will set the token in an `httpOnly` cookie, and Astro middleware will redirect the user to the appropriate page based on the role in the token after reload.
        2.  **Failed login:** Display an error message.

## 2. Backend Logic (Rust / actix-web)

The backend will be responsible for business logic, server-side validation, and secure database communication.

### 2.1. API Endpoint Structure

Changes will affect existing endpoints from `rest-plan.md`.

*   **`POST /users` - User Registration**
    *   **Data Model (Request Body):**
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
    *   **Logic:**
        1.  Validate `RegisterUserDto` using `validator`.
        2.  Check if a user with the given username already exists in the `users` table. If so, return `409 Conflict`.
        3.  Hash the user's password (e.g., using the `argon2` or `bcrypt` library).
        4.  Create a new record in the `users` table with `username`, `password_hash`, and default role `USER`.
        5.  Return `201 Created`.
    *   **Exception Handling:**
        *   Validation error -> `400 Bad Request`.
        *   User exists -> `409 Conflict`.
        *   Database error -> `500 Internal Server Error`.

*   **`POST /auth/login` - User Login**
    *   **Data Model (Request Body):**
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
    *   **Data Model (Response Body):**
        ```rust
        // src/models/dto.rs
        #[derive(Serialize)]
        pub struct TokenDto {
            pub token: String,
        }
        ```
    *   **Logic:**
        1.  Validate `LoginUserDto`.
        2.  Search for the user in the `users` table by `username`. If not found, return `401 Unauthorized`.
        3.  Verify the provided password against the hash stored in the database (`password_hash`). If it doesn't match, return `401 Unauthorized`.
        4.  Generate a JWT token containing `user_id`, `username`, and `role`.
        5.  Update the `last_login_at` field for the user.
        6.  Return `200 OK` with the JWT token in the response body and set it in a secure `httpOnly` cookie.
    *   **Exception Handling:**
        *   Validation error -> `400 Bad Request`.
        *   Invalid login credentials -> `401 Unauthorized`.
        *   Token generation error / database error -> `500 Internal Server Error`.

### 2.2. Input Data Validation

Validation will be implemented at two levels:
1.  **Frontend:** Basic real-time validation in React components to provide immediate feedback to the user.
2.  **Backend:** Rigorous server-side validation using the `validator` crate on DTO models. This is a critical safeguard against manipulated requests.

## 3. Authentication System

The system will be based on stateless JWT tokens, which is consistent with REST architecture and the technology stack.

### 3.1. JWT Token Generation and Management

*   **Library:** `jsonwebtoken` in Rust.
*   **Secret Key:** The key for signing tokens will be loaded from an environment variable (`JWT_SECRET`) to avoid hardcoding it in the code.
*   **Token Payload (Contents):**
    ```json
    {
      "sub": "user_id_uuid", // Subject (User ID)
      "username": "user_login",
      "role": "USER", // or "ADMIN"
      "exp": 1678886400 // Expiration timestamp (e.g., 1 hour from issuance)
    }
    ```
*   **Token Transmission:** After successful login, the backend will set the token in an `httpOnly`, `Secure`, `SameSite=Strict` cookie. This ensures the token is automatically included in subsequent requests while being inaccessible to client-side JavaScript scripts, protecting against XSS attacks. The frontend does not need to manage token storage.

### 3.2. Authorization Middleware (actix-web)

Middleware will be created for `actix-web` to protect secured endpoints.

*   **Middleware Logic:**
    1.  Read the JWT token from the cookie in the incoming request.
    2.  If the token is missing, return `401 Unauthorized`.
    3.  Verify the token's signature and expiration date using `JWT_SECRET`.
    4.  If the token is invalid or expired, return `401 Unauthorized`.
    5.  If the token is valid, decoded data (e.g., `user_id`, `role`) will be attached to the request (e.g., as a `request extension`) to be available in endpoint handlers.
    6.  Optionally, the middleware can check the required role for a given endpoint (e.g., `/admin/*` requires the `ADMIN` role) and return `403 Forbidden` if permissions are lacking.

### 3.3. Logout

Logout will be implemented by removing the cookie containing the token.

*   **Endpoint `POST /auth/logout`:**
    *   Does not require a request body.
    *   **Logic:** Clears the `httpOnly` cookie containing the JWT token by setting its expiration date to the past.
    *   **Response:** `200 OK`.
*   **Frontend Interaction:** The "Logout" button in `AppLayout.astro` will call this endpoint and then redirect the user to the `/login` page.