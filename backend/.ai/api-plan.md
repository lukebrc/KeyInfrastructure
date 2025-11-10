# REST API Plan

## 1. Resources
- Users: Corresponds to the `users` table, managing user accounts including registration, authentication, and role management.
- Certificates: Corresponds to the `certificates` table, handling certificate creation, retrieval, renewal, and revocation. Includes related `private_keys` and `revoked_certificates` for secure key management and revocation tracking.

## 2. Endpoints

### Users Resource
- **Method**: POST
- **URL Path**: /users
- **Description**: Register a new user.
- **Query Parameters**: None
- **Request JSON Structure**: {"username": "string", "password": "string", "pin": "string (min 8 chars)"}
- **Response JSON Structure**: {"id": "uuid", "username": "string", "role": "string", "created_at": "timestamp"}
- **Success Codes and Messages**: 201 Created - "User registered successfully"
- **Error Codes and Messages**: 400 Bad Request - "Invalid input data", 409 Conflict - "Username already exists"

- **Method**: POST
- **URL Path**: /auth/login
- **Description**: Authenticate a user and return a JWT token.
- **Query Parameters**: None
- **Request JSON Structure**: {"username": "string", "password": "string"}
- **Response JSON Structure**: {"token": "string", "user": {"id": "uuid", "username": "string", "role": "string"}}
- **Success Codes and Messages**: 200 OK
- **Error Codes and Messages**: 401 Unauthorized - "Invalid credentials"

- **Method**: GET
- **URL Path**: /users/{id}
- **Description**: Retrieve user details (self or admin).
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: {"id": "uuid", "username": "string", "role": "string", "created_at": "timestamp", "last_login_at": "timestamp"}
- **Success Codes and Messages**: 200 OK
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 404 Not Found - "User not found"

### Certificates Resource
- **Method**: POST
- **URL Path**: /users/{user_id}/certificates
- **Description**: Create a new certificate for a user (admin only).
- **Query Parameters**: None
- **Request JSON Structure**: {"validity_period_days": "integer", "hash_algorithm": "string (SHA-256|SHA-384|SHA-512)", "dn": "string"}
- **Response JSON Structure**: {"id": "uuid", "serial_number": "string", "dn": "string", "status": "string", "expiration_date": "timestamp", "created_at": "timestamp"}
- **Success Codes and Messages**: 201 Created - "Certificate created"
- **Error Codes and Messages**: 403 Forbidden - "Admin access required", 400 Bad Request - "Invalid DN or parameters"

- **Method**: GET
- **URL Path**: /certificates
- **Description**: List certificates for the authenticated user, with pagination, filtering, and sorting.
- **Query Parameters**: page=integer, limit=integer, status=string, sort_by=string (e.g., expiration_date), order=asc|desc
- **Request JSON Structure**: None
- **Response JSON Structure**: {"certificates": [{"id": "uuid", "serial_number": "string", "dn": "string", "status": "string", "expiration_date": "timestamp", "renewed_count": "integer"}], "total": "integer", "page": "integer"}
- **Success Codes and Messages**: 200 OK - "Certificates retrieved"
- **Error Codes and Messages**: 401 Unauthorized - "Authentication required"

- **Method**: GET
- **URL Path**: /certificates/expiring
- **Description**: Get certificates expiring soon for the authenticated user.
- **Query Parameters**: days=integer (default 30)
- **Request JSON Structure**: None
- **Response JSON Structure**: {"certificates": [{"id": "uuid", "expiration_date": "timestamp"}]}
- **Success Codes and Messages**: 200 OK - "Expiring certificates retrieved"
- **Error Codes and Messages**: 401 Unauthorized - "Authentication required"

- **Method**: PUT
- **URL Path**: /certificates/{id}/renew
- **Description**: Renew a certificate (user only for own certificates).
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: {"id": "uuid", "expiration_date": "timestamp", "renewed_count": "integer", "renewal_date": "timestamp"}
- **Success Codes and Messages**: 200 OK - "Certificate renewed"
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 404 Not Found - "Certificate not found", 400 Bad Request - "Certificate not renewable"

- **Method**: POST
- **URL Path**: /certificates/{id}/download
- **Description**: Download PKCS#12 file for the certificate (user only for own).
- **Query Parameters**: None
- **Request JSON Structure**: {"pin": "string"}
- **Response JSON Structure**: Binary PKCS#12 file
- **Success Codes and Messages**: 200 OK - "File downloaded"
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 400 Bad Request - "Invalid PIN", 404 Not Found - "Certificate not found"

- **Method**: PUT
- **URL Path**: /certificates/{id}/revoke
- **Description**: Revoke a certificate (admin only).
- **Query Parameters**: None
- **Request JSON Structure**: {"reason": "string"}
- **Response JSON Structure**: {"id": "uuid", "status": "REVOKED", "revocation_date": "timestamp"}
- **Success Codes and Messages**: 200 OK - "Certificate revoked"
- **Error Codes and Messages**: 403 Forbidden - "Admin access required", 404 Not Found - "Certificate not found"

## 3. Authentication and Authorization
- **Mechanism**: JWT-based authentication. Users log in via POST /auth/login, receiving a JWT token. The token is included in Authorization header as Bearer for subsequent requests.
- **Implementation Details**: Tokens expire after 1 hour. Role-based access: 'USER' can access own data, 'ADMIN' can access all. Admins created via direct DB manipulation. Rate limiting: 10 requests per minute per user to handle concurrency.

## 4. Validation and Business Logic
- **Validation Conditions**:
  - Users: Username must be unique, password hashed, role must be 'ADMIN' or 'USER', PIN min 8 chars during registration.
  - Certificates: Serial number unique, status 'ACTIVE' or 'REVOKED', DN required, validity period 1 day to 10 years, hash algorithm one of SHA-256/384/512.
  - Private Keys: Encrypted with user's PIN, stored securely.
  - Revoked Certificates: One per certificate, reason optional.
- **Business Logic Implementation**: Registration validates PIN length and uniqueness. Certificate creation generates keys via internal CA, signs with root CA key (password from ENV). Renewal updates expiration and count. Download decrypts key with PIN and packages PKCS#12. Notifications via expiring endpoint for frontend banner. Revocation updates status and logs reason. All operations enforce RLS-like access via JWT claims.