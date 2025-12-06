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

**Path:** `/`

**Main Goal:** 
A public welcome page for unauthenticated users, presenting basic information about the system and allowing navigation to login or registration.

**Key Information to Display:**
- System name (KeyInfrastructure)
- Brief description of system functionality
- Links to login (`/login`) and registration (`/register`)

**Key View Components:**
- `WelcomeHeader` — header with system name
- `WelcomeContent` — system description
- `NavigationLinks` — buttons/links for login and registration

**UX, Accessibility, and Security Considerations:**
- Responsive layout with mobile-first approach
- Minimalist design encouraging action
- For logged-in users: automatic redirection to the appropriate dashboard
- No sensitive data on the public page

---

### 2.2. View: Registration

**Path:** `/register`

**Main Goal:**
Enable new users to self-register in the system by providing a username and password.

**Key Information to Display:**
- Registration form with fields:
  - Username (required, unique)
  - Password (required, minimum 8 characters)
- Client-side validation messages
- API error messages (409 — user already exists, 400 — invalid data)

**Key View Components:**
- `RegisterForm` — registration form (React component)
- `InputField` — text fields with validation
- `PasswordField` — password field with show/hide functionality
- `ErrorMessage` — display validation and API errors
- `SuccessMessage` — message after successful registration

**UX, Accessibility, and Security Considerations:**
- Client-side validation before form submission
- Hints regarding requirements (min. 8 characters for password)
- After successful registration: automatic login (POST /auth/login) and redirection to `/dashboard`
- Responsive form (columns on desktop, stack on mobile)
- Touch target minimum 44x44px for buttons

---

### 2.3. View: Login

**Path:** `/login`

**Main Goal:**
Authenticate users (both USER and ADMIN) in the system by providing a username and password.

**Key Information to Display:**
- Login form with fields:
  - Username (required)
  - Password (required)
- Link to registration for new users
- Error messages (401 — invalid login credentials)

**Key View Components:**
- `LoginForm` — login form (React component)
- `InputField` — text fields
- `PasswordField` — password field
- `ErrorMessage` — display authentication errors
- `RegisterLink` — link to registration page

**UX, Accessibility, and Security Considerations:**
- After successful login: redirection to `/dashboard` (USER) or `/admin/dashboard` (ADMIN) based on the role from the JWT token
- JWT token saved in httpOnly cookie by the backend
- Error messages do not reveal if a user exists (security)
- Automatic redirection of logged-in users to the appropriate dashboard
- Responsive form layout

---

### 2.4. View: User Dashboard

**Path:** `/dashboard`

**Main Goal:**
Central view for users, presenting a list of their certificates, the status of expiring certificates, and enabling certificate management (downloading, renewing).

**Key Information to Display:**
- **Warning banner** (if expiring certificates exist):
  - List of certificates expiring within 30 days (from GET /certificates/expiring endpoint)
  - Color highlighting (red/yellow gradient)
  - "Renew Now" button for each certificate
  - Updates every 5-10 minutes in the background
- **Certificate table:**
  - Columns: serial_number, DN (abbreviated), status (ACTIVE/REVOKED with color), expiration_date (with highlight for expiring)
  - Default sorting by expiration_date (ascending)
  - Filtering by status (ACTIVE/REVOKED)
  - Pagination (10-20 certificates per page, default 10)
  - Action buttons: "Renew" (for active certificates near expiration), "Download" (for all active)
- User information (optional)
- Logout button

**Key View Components:**
- `ExpiringBanner` — sticky banner with expiring certificates (React component)
- `CertificateTable` — certificate table with sorting, filtering, pagination (React component)
- `CertificateRow` — single certificate row
- `StatusBadge` — certificate status badge (ACTIVE/REVOKED)
- `DateDisplay` — display of expiration date with highlighting
- `ActionButtons` — Renew and Download buttons
- `DownloadCertificateModal` — certificate download modal
- `UserHeader` — header with user information
- `LogoutButton` — logout button

**UX, Accessibility, and Security Considerations:**
- Banner cannot be fully closed (can only be minimized) — important for security
- Banner updated in the background every 5-10 minutes (polling GET /certificates/expiring)
- Responsive table — horizontally scrollable on mobile
- Skeleton loading during data retrieval
- Toast notifications for operations (renewal, download)
- Inline error messages for operation errors
- Automatic redirection to `/login` upon session expiration (401)
- All API requests require a valid JWT token

---

### 2.5. View: Administrator Dashboard

**Path:** `/admin/dashboard`

**Main Goal:**
Central view for administrators, presenting a system overview and enabling certificate and user management.

**Key Information to Display:**
- System statistics (optional):
  - Number of users
  - Number of certificates (active, expired, revoked)
  - Certificates expiring within 30 days
- Links to main functions:
  - Create certificate (`/admin/certificates/create`)
  - Manage certificates (`/admin/certificates`)
  - Manage users (if available)
- Logout button

**Key View Components:**
- `AdminHeader` — header with administrator information
- `StatsCards` — cards with statistics (optional)
- `AdminNavigation` — navigation to main functions
- `LogoutButton` — logout button

**UX, Accessibility, and Security Considerations:**
- Only users with ADMIN role have access
- Automatic redirection to `/login` if unauthorized (403)
- Responsive layout with navigation tiles
- Skeleton loading during statistics retrieval

---

### 2.6. View: Certificate Creation (Admin)

**Path:** `/admin/certificates/create`

**Main Goal:**
Enable the administrator to create a new certificate for a selected user with full parameter configuration.

**Key Information to Display:**
- Certificate creation form:
  - **User Select** (required) — list of all users in the system
  - **Numeric field:** `validity_period_days` (required, 1-3650 days, validation)
  - **Dropdown:** `hash_algorithm` (required, options: SHA-256, SHA-384, SHA-512)
  - **DN (Distinguished Name) Form:**
    - CN (Common Name) — required
    - OU (Organizational Unit) — optional
    - O (Organization) — optional
    - L (Locality) — optional
    - ST (State/Province) — optional
    - C (Country) — optional
  - **DN Preview** — display of formatted DN before submission
- Client-side validation messages
- API error messages (400 — invalid data, 403 — insufficient permissions)
- Success message with certificate serial number after creation

**Key View Components:**
- `CreateCertificateForm` — certificate creation form (React component)
- `UserSelect` — dropdown with user list
- `NumberInput` — numeric field with range validation
- `SelectDropdown` — dropdown for hash algorithm
- `DNFormFields` — DN form fields
- `DNPreview` — formatted DN preview
- `ErrorMessage` — display validation and API errors
- `SuccessMessage` — success message with serial number
- `SubmitButton` — form submission button

**UX, Accessibility, and Security Considerations:**
- Client-side validation before submission (POST /users/{user_id}/certificates)
- Hints regarding requirements and value ranges
- DN preview before submission prevents errors
- After successful creation: option to create another certificate or return to dashboard
- Responsive form (columns on desktop, stack on mobile)
- Toast notification after successful creation
- Only users with ADMIN role have access

---

### 2.7. View: Certificate Management (Admin)

**Path:** `/admin/certificates`

**Main Goal:**
Overview of all certificates in the system with the ability to revoke them by the administrator.

**Key Information to Display:**
- **Table of all certificates:**
  - Columns: serial_number, user (username), DN (abbreviated), status (ACTIVE/REVOKED), expiration_date, creation date
  - Default sorting by expiration_date
  - Filtering by status, user
  - Pagination (10-20 certificates per page)
  - Action button: "Revoke" (for active certificates)
- Revocation confirmation modal with an "reason" field (optional)

**Key View Components:**
- `AdminCertificateTable` — certificate table with sorting, filtering, pagination (React component)
- `CertificateRow` — single certificate row
- `RevokeButton` — revoke button
- `RevokeModal` — confirmation modal with reason field
- `StatusBadge` — certificate status badge
- `FilterControls` — filtering and sorting controls

**UX, Accessibility, and Security Considerations:**
- Confirmation modal before revocation prevents accidental actions
- Toast notification after successful revocation
- Responsive table — horizontally scrollable on mobile
- Only users with ADMIN role have access
- Skeleton loading during data retrieval

---

## 3. User Journey Map

### 3.1. Registration and First Login Flow (New User)

1.  **User visits the homepage (`/`)**
    - Sees system information
    - Clicks "Register" button

2.  **Navigates to registration (`/register`)**
    - Fills out the form: username, password
    - Client-side validation checks requirements
    - Sends POST /users request

3.  **After successful registration:**
    - Automatic login: POST /auth/login with username and password
    - JWT token saved in httpOnly cookie
    - Redirected to `/dashboard`

4.  **User Dashboard (`/dashboard`)**
    - User sees an empty list of certificates (or a message about no certificates)
    - Waits for an administrator to create a certificate

### 3.2. Login Flow (Existing User)

1.  **User visits the homepage (`/`) or `/login`**
    - Enters username and password
    - Sends POST /auth/login request

2.  **After successful login:**
    - JWT token saved in httpOnly cookie
    - Redirected to `/dashboard` (USER) or `/admin/dashboard` (ADMIN) based on role

3.  **Dashboard appropriate for the role:**
    - USER: view with certificates and banner (if expiring)
    - ADMIN: administrative panel with management options

### 3.3. Certificate Management Flow (User)

1.  **User sees certificates on the dashboard (`/dashboard`)**
    - Certificate table with sorting and filtering
    - Banner with expiring certificates (if any)

2.  **Downloading a certificate:**
    - User clicks the "Download" button next to a certificate
    - A modal opens with a password input field
    - User enters password (min. 8 characters)
    - Sends POST /certificates/{id}/download request with password in body
    - Browser automatically downloads the `.p12` or `.pfx` file
    - In case of 400 error (Invalid password): an error message is displayed

3.  **Renewing a certificate:**
    - User sees a banner with an expiring certificate or clicks "Renew" in the table
    - Confirms the action (optional confirmation modal)
    - Sends PUT /certificates/{id}/renew request
    - Toast notification confirms success
    - Certificate table refreshes automatically

### 3.4. Certificate Creation Flow (Administrator)

1.  **Administrator logs in and sees the dashboard (`/admin/dashboard`)**
    - Clicks "Create Certificate" link/button

2.  **Navigates to the form (`/admin/certificates/create`)**
    - Selects a user from the list (select)
    - Sets `validity_period_days` (1-3650)
    - Selects `hash_algorithm` (SHA-256, SHA-384, SHA-512)
    - Fills in DN fields (CN required, others optional)
    - Sees a preview of the DN before submission

3.  **Form Submission:**
    - Client-side validation checks all requirements
    - Sends POST /users/{user_id}/certificates request
    - Success message with serial number is displayed
    - Option to create another certificate or return to dashboard

### 3.5. Certificate Revocation Flow (Administrator)

1.  **Administrator views certificates (`/admin/certificates`)**
    - Sees a table of all certificates with filtering capability

2.  **Revoking a certificate:**
    - Clicks the "Revoke" button next to an active certificate
    - A confirmation modal opens with an optional "reason" field
    - Confirms the action
    - Sends PUT /certificates/{id}/revoke request with reason in body
    - Toast notification confirms success
    - Certificate status changes to REVOKED in the table

### 3.6. Session Expiration Handling Flow

1.  **User performs an action requiring authorization:**
    - JWT token expired (1 hour)
    - Backend returns 401 Unauthorized

2.  **Automatic Redirection:**
    - Astro middleware or error handler detects 401
    - Automatic redirection to `/login`
    - Message is displayed: "Session expired. Please log in again."

3.  **User logs in again:**
    - Enters login credentials
    - Receives a new JWT token
    - Redirected to the previous view (if possible) or dashboard

## 4. Layout and Navigation Structure

### 4.1. Main Navigation Structure

**Public Pages (accessible without authorization):**
```
/                    → Homepage (Welcome)
/login               → Login
/register            → Registration
```

**User Section (authorization required, USER role):**
```
/dashboard           → User dashboard with certificates
```

**Administrator Section (authorization required, ADMIN role):**
```
/admin/dashboard              → Administrator dashboard
/admin/certificates/create    → Create certificate
/admin/certificates           → Manage certificates
```

### 4.2. Authorization and Redirection Mechanism

**Astro Middleware:**
- Protects all paths except `/`, `/login`, `/register`
- Verifies JWT token from httpOnly cookie
- If token is missing or expired: redirect to `/login`
- If role is invalid (e.g., USER tries to access `/admin/*`): 403 error

**Automatic Redirections:**
- Logged-in user tries to access `/login` or `/register`: redirect to the appropriate dashboard
- After successful login: redirect to `/dashboard` (USER) or `/admin/dashboard` (ADMIN)
- After successful registration: automatic login and redirect to `/dashboard`

### 4.3. In-Interface Navigation

**User Dashboard:**
- Header with user information
- Logout button (top right corner)
- Main content: banner (if any) + certificate table

**Administrator Panel:**
- Header with administrator information
- Logout button (top right corner)
- Sidebar or top navigation with links:
  - Dashboard
  - Create Certificate
  - Manage Certificates
- Main content changes depending on the selected section

### 4.4. Breadcrumbs (optional for MVP)

For the administrator section, breadcrumbs can be added:
```
Admin > Dashboard
Admin > Certificates > Create
Admin > Certificates > List
```

## 5. Key Components

### 5.1. Authentication Components

**`LoginForm` (React)**
- Login form with username and password fields
- Client-side validation
- Handles 401 errors
- Redirects after successful login

**`RegisterForm` (React)**
- Registration form with username and password fields
- Validates requirements (min. 8 characters)
- Handles 400, 409 errors
- Automatic login after registration

**`AuthMiddleware` (Astro Middleware)**
- Verifies JWT token from httpOnly cookie
- Protects secured paths
- Automatic redirection to `/login` if unauthorized

### 5.2. Certificate Components

**`ExpiringBanner` (React)**
- Sticky banner at the top of the dashboard
- Displays expiring certificates (GET /certificates/expiring)
- Updates every 5-10 minutes (polling)
- Cannot be fully closed (only minimized)
- "Renew Now" buttons for each certificate
- Color highlighting (red/yellow gradient)

**`CertificateTable` (React)**
- Certificate table with sorting, filtering, pagination
- Columns: serial_number, DN, status, expiration_date
- Action buttons: Renew, Download
- Highlighting of expiring certificates
- Responsive (horizontally scrollable on mobile)
- Integration with GET /certificates (query params: page, limit, status, sort_by, order)

**`DownloadCertificateModal` (React)**
- Modal with password field (min. 8 characters)
- Download and close buttons
- Handles POST /certificates/{id}/download
- Automatic download of `.p12`/.pfx file
- Handles 400 error (Invalid password)

**`CertificateRow` (React)**
- Single certificate row in the table
- Displays serial_number, DN (abbreviated), status, expiration_date
- Action buttons (Renew, Download)
- Color highlighting of status and expiration date

**`StatusBadge` (React)**
- Certificate status badge (ACTIVE/REVOKED)
- Different colors for different statuses
- Accessibility: appropriate contrast and readability

### 5.3. Form Components

**`CreateCertificateForm` (React)**
- Administrator certificate creation form
- Fields: user select, validity_period_days, hash_algorithm, DN fields
- Client-side validation
- DN preview before submission
- Handles POST /users/{user_id}/certificates
- Error and success messages

**`DNFormFields` (React)**
- Distinguished Name form fields
- CN (required), OU, O, L, ST, C (optional)
- Walidacja i formatowanie
- Validation and formatting

**`DNPreview` (React)**
- Preview of formatted DN before submission
- Format: "C=PL,CN=username,O=Organization,..."

**`UserSelect` (React)**
- Select dropdown with a list of all users
- Requires GET /users endpoint (for administrator) or an alternative solution

### 5.4. Common UI Components

**`ToastNotifications` (Shadcn/ui)**
- Toast notifications for operations (success, error)
- Used for: certificate renewal, download, creation, revocation
- Automatic closing after 5 seconds (success) or 10 seconds (error)

**`ErrorMessage` (React)**
- Displays validation and API errors
- Inline error messages in forms
- Readable messages for the user

**`SuccessMessage` (React)**
- Success messages (e.g., after certificate creation)
- Can be part of toast notification

**`LoadingSkeleton` (React)**
- Skeleton loading during data retrieval
- Used in tables and lists

**`Button` (Shadcn/ui)**
- Common button component
- Variants: primary, secondary, danger
- Touch target minimum 44x44px

**`InputField` (React)**
- Common text field with validation
- Support for errors and hints

**`PasswordField` (React)**
- Password field with show/hide functionality
- Hints regarding requirements

**`SelectDropdown` (React)**
- Dropdown select with options
- Support for searching (optional)

### 5.5. Error Handling Components

**`ErrorHandler` (Utility)**
- Central error handling system
- Maps HTTP codes to messages:
  - 400: Validation errors (specific messages)
  - 401: Redirect to /login with message
  - 403: "No permissions"
  - 404: "Not found"
  - 409: "User already exists"
- Handles network errors (timeout, no connection) with fallback UI

**`NetworkErrorFallback` (React)**
- Fallback UI for network errors
- "Try Again" button
- Message about connection problem

### 5.6. Navigation Components

**`NavigationHeader` (React/Astro)**
- Header with user information
- Logout button
- Different versions for USER and ADMIN

**`AdminNavigation` (React)**
- Navigation in the administrator panel
- Sidebar or top navigation with links
- Active highlighting of the current section

**`LogoutButton` (React)**
- Logout button
- Clears JWT token
- Redirects to `/login`

---

## 6. PRD Requirements Mapping to UI Elements

### 6.1. User Management

**PRD:** "The system must allow new users to self-register with a username, password, and an 8-character minimum password."
- **UI Element:** `RegisterForm` at `/register` with password validation (min. 8 characters)

**PRD:** "The system must authenticate users based on their username and password."
- **UI Element:** `LoginForm` at `/login` with username and password fields

### 6.2. Administrator Management

**PRD:** "Administrators must have an interface to create new certificates for users."
- **UI Element:** `CreateCertificateForm` at `/admin/certificates/create`

**PRD:** "This interface must allow the administrator to specify the certificate's validity period, hash algorithm (SHA-256, SHA-384, SHA-512), and all Distinguished Name (DN) fields."
- **UI Element:** Form fields: `validity_period_days`, `hash_algorithm` dropdown, `DNFormFields`

### 6.3. User-Facing Functionality

**PRD:** "The system must allow authenticated users to download their key/certificate pair in a PKCS#12 file protected by their password."
- **UI Element:** `DownloadCertificateModal` with password field, integration with POST /certificates/{id}/download

**PRD:** "The system must display a prominent banner to users whose certificate is near or past its expiration date, prompting them to renew."
- **UI Element:** `ExpiringBanner` at `/dashboard` with polling GET /certificates/expiring

**PRD:** "Users must be able to initiate the certificate renewal process."
- **UI Element:** "Renew" button in `CertificateTable` and `ExpiringBanner`, integration with PUT /certificates/{id}/renew

### 6.4. User Story

**"As a User, I want to register for an account..."**
- **UI Element:** `/register` → `RegisterForm` → automatic login → `/dashboard`

**"As a User, I want to log in to the portal..."**
- **UI Element:** `/login` → `LoginForm` → redirect to `/dashboard`

**"As a User, I want to be clearly notified when my certificate is about to expire..."**
- **UI Element:** `ExpiringBanner` at `/dashboard` with color highlighting

**"As a User, I want to download my certificate and private key securely..."**
- **UI Element:** "Download" button → `DownloadCertificateModal` with password → download of `.p12`/.pfx

**"As an Administrator, I want to log in to the system..."**
- **UI Element:** `/login` → `LoginForm` → redirect to `/admin/dashboard`

**"As an Administrator, I want to create a new certificate for a user..."**
- **UI Element:** `/admin/certificates/create` → `CreateCertificateForm` → success message with serial number

---

## 7. User Pain Points Solutions

### 7.1. Problem: User doesn't know their certificate is expiring

**UI Solution:**
- `ExpiringBanner` at the top of the dashboard with color highlighting
- Banner cannot be fully closed — always visible
- Updates in the background every 5-10 minutes
- Highlighting in the certificate table (color-coded expiration date)

### 7.2. Problem: User doesn't know how to download a certificate

**UI Solution:**
- Clear "Download" button next to each active certificate
- Modal with clear instructions regarding the password
- Automatic file download after entering the correct password
- Readable error messages for incorrect passwords

### 7.3. Problem: Administrator makes mistakes when creating a certificate (e.g., incorrect DN)

**UI Solution:**
- Client-side validation before form submission
- DN preview before submission (`DNPreview`)
- Hints regarding requirements and value ranges
- Readable API error messages

### 7.4. Problem: User has many certificates and it's hard to find the right one

**UI Solution:**
- Table with sorting by expiration_date (default)
- Filtering by status (ACTIVE/REVOKED)
- Pagination for easy browsing
- Color highlighting of status and expiration date

### 7.5. Problem: Session expires and user loses work

**UI Solution:**
- Automatic redirection to `/login` with a message about expired session
- Optional timer counting down to session expiration (for future versions)
- Logout button for user control

### 7.6. Problem: User forgets password when downloading a certificate

**UI Solution:**
- Clear error message: "Invalid password"
- Ability to retry without closing the modal
- Password set only during registration — user must remember it (according to PRD, password recovery is not in MVP scope)

---

## 8. Error States and Edge Cases

### 8.1. API Error States

**400 Bad Request:**
- Data validation (forms): inline error messages in form fields
- Invalid password during download: "Invalid password. Please try again." message in the modal

**401 Unauthorized:**
- Missing or expired token: automatic redirection to `/login` with message "Session expired. Please log in again."
- Invalid login credentials: message "Invalid username or password" (without revealing if user exists)

**403 Forbidden:**
- Insufficient permissions (e.g., USER tries to access `/admin/*`): message "No permissions to view this page" + redirect to `/dashboard`

**404 Not Found:**
- Certificate not found: message "Certificate not found"
- User not found: message "User not found"

**409 Conflict:**
- User already exists during registration: message "Username already exists. Please choose another."

**500 Internal Server Error:**
- Server error: message "A server error occurred. Please try again later." + retry option

### 8.2. Edge Cases

**No Certificates:**
- User dashboard displays message: "You don't have any certificates yet. An administrator will create a certificate for you."
- Certificate table displays empty state with a message

**No Expiring Certificates:**
- Banner is not displayed
- Certificate table functions normally

**Network Error (timeout, no connection):**
- Fallback UI with message "No connection to the server. Please check your internet connection."
- "Try Again" button to retry the request

**Many Expiring Certificates:**
- Banner displays all expiring certificates (or only the nearest deadline with a "See all" link)
- Certificate table allows sorting and filtering

**User tries to renew an already revoked certificate:**
- "Renew" button is not available for REVOKED certificates
- 400 error message: "Certificate cannot be renewed (status: REVOKED)"

**Administrator tries to create a certificate for a non-existent user:**
- Client-side validation (user list select prevents this)
- 404 error message: "User not found"

---

## 9. API Plan Compliance

All views and components are fully compliant with the API plan:

- **POST /users** → `RegisterForm`
- **POST /auth/login** → `LoginForm`
- **GET /users/{id}`** → optionally in dashboard header
- **POST /users/{user_id}/certificates** → `CreateCertificateForm`
- **GET /certificates** → `CertificateTable` (with query params: page, limit, status, sort_by, order)
- **GET /certificates/expiring** → `ExpiringBanner` (with query param: days=30)
- **PUT /certificates/{id}/renew** → "Renew" button in `CertificateTable` and `ExpiringBanner`
- **POST /certificates/{id}/download** → `DownloadCertificateModal` (with password in body)
- **PUT /certificates/{id}/revoke** → "Revoke" button in `AdminCertificateTable` (with reason in body)

**Note:** The `GET /users` endpoint for the administrator (needed in `UserSelect`) is not listed in the API plan. This should be resolved by:
1.  Adding the `GET /users` endpoint to the API plan (for ADMIN only)
2.  Or an alternative solution (e.g., caching users during certificate creation)

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