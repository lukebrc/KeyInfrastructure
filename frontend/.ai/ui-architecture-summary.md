# UI Architecture Planning Summary - KeyInfrastructure MVP

<conversation_summary>

<decisions>
1.  **Application Structure:** The application will have separate paths for administrator and user, but a common login window. This means separate `/admin/*` and `/dashboard` (for users) sections, while maintaining a common `/login` endpoint.

2.  **Registration and Login Flow:** Publicly available registration at `/register` with a form (username, password). After successful registration, automatic login via POST /auth/login and redirection to the dashboard. A common login page `/login` handling both roles (USER/ADMIN) with clear error messages.

3.  **JWT Token Management:** JWT token stored in httpOnly cookie (not sessionStorage), providing greater security against XSS attacks. Automatic logout upon token expiration (401) with redirection to `/login`. Astro middleware protecting all pages requiring authorization (except `/login` and `/register`).

4.  **Performance Optimization:** Default database optimization is sufficient for MVP. No need to implement advanced frontend caching mechanisms (React Query) - standard API requests are acceptable.

5.  **Responsiveness and Accessibility:** Mobile-first approach with Tailwind CSS. All interactive elements a minimum of 44x44px touch target. Responsive forms (columns on desktop, stack on mobile). No requirement for full implementation of ARIA labels and keyboard navigation in MVP (can be simplified compared to initial recommendations).
    </decisions>

<matched_recommendations>

1.  **Separate Paths for Roles:** The recommendation for a common portal with conditional navigation was rejected in favor of separate paths for administrator and user, ensuring clearer functional separation.

2.  **Automatic Login After Registration:** The recommendation for automatic login after registration has been accepted and will be implemented.

3.  **Dashboard with Certificate Table:** The recommendation for a certificate table/list with sorting, filtering, and pagination has been fully accepted as part of the user dashboard.

4.  **Warning Banner:** The recommendation for a sticky banner with expiring certificates has been fully accepted - the banner will be highly visible, cannot be fully closed, with updates every 5-10 minutes.

5.  **Certificate Creation Form for Admin:** All recommendations for the form at `/admin/certificates/create` have been accepted, including client-side validation and DN preview.

6.  **PKCS#12 Download Modal:** The recommendation for a modal with a password field for downloading certificates has been accepted, including secure password management in memory.

7.  **Central Error Handling System:** The recommendation to implement a central error handling system with toast notifications and inline error messages has been fully accepted.

8.  **Mobile-first and Responsiveness:** Basic recommendations for mobile-first approach and responsiveness have been accepted, though without full implementation of all accessibility aspects (ARIA, keyboard navigation).
    </matched_recommendations>

<ui_architecture_planning_summary>

### a) Main UI Architecture Requirements

**Application Structure:**

- Separate paths for users (`/dashboard`, `/certificates/*`) and administrators (`/admin/*`)
- Common login page (`/login`) serving both roles
- Public registration page (`/register`) available for new users

**Authentication and Authorization:**

- JWT token stored in httpOnly cookie
- Astro middleware protecting secured paths
- Automatic redirection to `/login` upon session expiration (401)
- Optional timer counting down to session expiration

**API Integration:**

- Direct communication with backend REST API (Rust/actix-web)
- Standard HTTP requests without advanced caching (for MVP)
- Central error handling system mapping HTTP codes to user messages

### b) Key Views, Screens, and User Flows

**User Flow (USER):**

1.  **Homepage/Welcome** (`/`) - public page with links to login and registration
2.  **Registration** (`/register`) - form: username, password → automatic login → redirect to dashboard
3.  **Login** (`/login`) - form: username, password → redirect to `/dashboard` (USER) or `/admin/dashboard` (ADMIN)
4.  **User Dashboard** (`/dashboard`):
    - Sticky banner with expiring certificates (if any) - highly visible, cannot be fully closed, "Renew Now" button
    - Table/list of certificates with:
      - Sorting by `expiration_date` (default ascending)
      - Filtering by status (ACTIVE/REVOKED)
      - Pagination (10-20 certificates per page)
      - Columns: serial_number, DN (abbreviated), status (with color), expiration_date (with highlight for expiring)
      - Action buttons: "Renew" (for active certificates near expiration), "Download" (for all active)
5.  **Certificate Renewal** - flow initiated from dashboard (PUT /certificates/{id}/renew)
6.  **Certificate Download** - modal with password field → POST /certificates/{id}/pkcs12 → automatic download of .p12/.pfx file. Public certificate download via GET /certificates/{id}/download.

**Administrator Flow (ADMIN):**

1.  **Login** (`/login`) - common with users, redirect to `/admin/dashboard`
2.  **Administrator Dashboard** (`/admin/dashboard`) - system overview (details to be determined)
3.  **Certificate Creation** (`/admin/certificates/create`):
    - Form with fields:
      - User selection (list of all users)
      - Numeric field: `validity_period_days` (1-3650 days, validation)
      - Dropdown: `hash_algorithm` (SHA-256, SHA-384, SHA-512)
      - DN Form: CN (required), OU, O, L, ST, C (optional)
    - DN preview before submission
    - Client-side validation
    - Success message with serial number after creation
4.  **Certificate Management** - list of all certificates with revocation capability (PUT /certificates/{id}/revoke)

**UI Components:**

- Certificate tables (with sorting, filtering, pagination)
- Registration and login forms
- Certificate download modal (with password field)
- Certificate creation form (admin)
- Warning banner (sticky, cannot be fully closed)
- Toast notifications (Shadcn/ui) for operational errors
- Inline error messages in forms

### c) API Integration and State Management Strategy

**API Endpoints Used in UI:**

**Authentication:**

- `POST /users` - register new user
- `POST /auth/login` - login, returns JWT token
- `GET /users/{id}` - retrieve user data

**Certificate Management:**

- `GET /certificates` - list of user certificates (pagination, filtering, sorting)
- `GET /certificates/expiring` - expiring certificates (for banner, `days=30` parameter)
- `PUT /certificates/{id}/renew` - renew certificate
- `GET /certificates/{id}/download` - download public certificate (CRT)
- `POST /certificates/{id}/pkcs12` - download PKCS#12 (requires password in body)
- `POST /users/{user_id}/certificates` - create certificate (admin)
- `PUT /certificates/{id}/revoke` - revoke certificate (admin)

**State Management:**

- JWT token in httpOnly cookie (managed by backend or Astro middleware)
- Authentication status verified before each API request
- No advanced data caching (for MVP) - standard requests on each view load
- Expiring certificates banner: polling every 5-10 minutes in the background

**Error Handling:**

- Central error handling system with HTTP code mapping:
  - `400` - validation errors (specific messages in forms)
  - `401` - unauthorized (redirect to `/login`)
  - `403` - insufficient permissions (message "No permissions")
  - `404` - not found (message "Not Found")
  - `409` - conflict (e.g., "User already exists")
- Toast notifications (Shadcn/ui) for operational errors
- Inline error messages in forms
- Fallback UI for network errors (timeout, no connection) with retry option

### d) Responsiveness, Accessibility, and Security Considerations

**Responsiveness:**

- Mobile-first approach with Tailwind CSS
- Forms: columns on desktop, stack on mobile
- Certificate tables: horizontally scrollable on mobile (or converted to cards in the future)
- Warning banner: abbreviated text on mobile, full-width button
- All interactive elements: minimum 44x44px touch target

**Accessibility (MVP - simplified):**

- Basic responsiveness ensured
- Touch target compliant with mobile guidelines
- Colors with adequate contrast
- No full implementation of ARIA labels and keyboard navigation in MVP (can be added in the future)

**Security:**

- JWT token in httpOnly cookie (XSS protection)
- Astro middleware protecting secured paths
- Automatic logout upon session expiration
- Password not stored in localStorage or state longer than necessary
- Client-side validation before form submission
- Secure handling of binary data (PKCS#12) during download

### e) Technical Structure and Implementation

**Technology Stack:**

- **Framework:** Astro 5 (server-side rendering, middleware)
- **Interactive Components:** React 19
- **Styling:** Tailwind CSS 4
- **UI Components:** Shadcn/ui (React components)
- **TypeScript:** 5 (static typing)

**Project Structure (frontend):**

- `/src/pages/` - Astro pages (routing)
  - `/` - homepage
  - `/login` - login
  - `/register` - registration
  - `/dashboard` - user dashboard
  - `/admin/*` - administrator section
- `/src/components/` - components (Astro + React)
  - Static components: Astro
  - Interactive components: React (forms, tables, modals)
- `/src/middleware/` - Astro middleware (path protection, JWT verification)
- `/src/lib/` - services and helpers (API client, error handling)
- `/src/types.ts` - common TypeScript types (DTOs, Entities)

**Key Components to Implement:**

1.  `AuthMiddleware` - Astro middleware for JWT verification
2.  `LoginForm` - login form (React)
3.  `RegisterForm` - registration form (React)
4.  `CertificateTable` - certificate table with sorting/filtering/pagination (React)
5.  `ExpiringBanner` - expiring certificates banner (React)
6.  `DownloadCertificateModal` - download modal with password field (React)
7.  `CreateCertificateForm` - admin certificate creation form (React)
8.  `ErrorHandler` - central error handling system
9.  `ToastNotifications` - toast components (Shadcn/ui)

</ui_architecture_planning_summary>

<unresolved_issues>

1.  **Endpoint for retrieving user list for admin:** The certificate creation form requires a select with a list of all users. The API plan does not include a `GET /users` endpoint for the administrator. It needs to be determined whether such an endpoint will be available, or if the user list will be retrieved in another way.

2.  **Administrator dashboard details:** A separate `/admin/*` path for the administrator has been decided, but the content details of the administrator dashboard (`/admin/dashboard`) have not been determined. It needs to be decided what information and statistics should be displayed.

3.  **Refresh token mechanism:** The JWT management response mentioned a "refresh token mechanism" but did not specify whether it would be implemented in MVP. The API plan does not include an endpoint for refreshing tokens. It needs to be clarified whether the refresh token will be part of MVP, or only automatic redirection to `/login`.

4.  **Password validation during download:** The `POST /certificates/{id}/pkcs12` endpoint returns a 400 error for an incorrect password, but it was not specified whether the backend verifies the password against the one saved during registration, or against the encrypted private key. This impacts error messages in the UI.

5.  **PKCS#12 file name format:** It was not specified whether the downloaded file name should contain the certificate serial_number, DN, or another naming convention (e.g., `certificate-{serial_number}.p12`).

6.  **Pagination limits:** Pagination of 10-20 certificates per page was specified, but the default value or the maximum limit per page consistent with the backend API ( `limit` parameter in GET /certificates) was not specified.

7.  **Timeout for banner polling:** The banner update was specified as every 5-10 minutes, but the exact value or whether polling should stop when the user is inactive (e.g., when the application is in the background) was not specified.

8.  **Handling multiple expiring certificates:** The banner displays information about expiring certificates, but it was not specified whether it should display all certificates in one banner, or only the nearest expiration date with a link to the full list.

</unresolved_issues>

</conversation_summary>
