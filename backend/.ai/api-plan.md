# REST API Plan

## 1. Resources
- Users: Corresponds to the `users` table, managing user accounts including registration, authentication, and role management.
- Certificates: Corresponds to the `certificates` and `certificate_requests` table, handling certificate creation, retrieval, renewal, and revocation. Includes related `private_keys` and `revoked_certificates` for secure key management and revocation tracking.

## 2. Endpoints

### Users Resource
- **Method**: POST
- **URL Path**: /users
- **Description**: Register a new user.
- **Query Parameters**: None
- **Request JSON Structure**: {"username": "string", "password": "string"}
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
- **URL Path**: /auth/verify
- **Description**: Verify the validity of a JWT token provided in the Authorization header.
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: {"valid": "boolean", "role": "string" (optional), "userId": "string" (optional)}
- **Success Codes and Messages**: 200 OK - Returns whether the token is valid, and if so, the user's role and ID.
- **Error Codes and Messages**: 200 OK - with `{"valid": false, "role": null, "userId": null}` if the token is missing, malformed, or invalid.

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
- **URL Path**: /users/{user_id}/certificates/request
- **Description**: Order new certificate generation for a user (admin only).
- **Query Parameters**: None
- **Request JSON Structure**: {"validity_period_days": "integer", "hash_algorithm": "string (SHA-256|SHA-384|SHA-512)", "dn": "string"}
- **Response JSON Structure**: {"id": "uuid", "serial_number": "string", "dn": "string", "status": "string", "expiration_date": "timestamp", "created_at": "timestamp"}
- **Success Codes and Messages**: 201 Created - "Certificate created"
- **Error Codes and Messages**: 403 Forbidden - "Admin access required", 400 Bad Request - "Invalid DN or parameters"

- **Method**: GET
- **URL Path**: /users/{user_id}/certificates/list
- **Description**: List certificates for the authenticated user, with pagination, filtering, and sorting.
- **Query Parameters**: page=integer, limit=integer, status=string, sort_by=string (e.g., expiration_date), order=asc|desc
- **Request JSON Structure**: None
- **Response JSON Structure**: {"certificates": [{"id": "uuid", "serial_number": "string", "dn": "string", "status": "string", "expiration_date": "timestamp", "renewed_count": "integer"}], "total": "integer", "page": "integer"}
- **Success Codes and Messages**: 200 OK - "Certificates retrieved"
- **Error Codes and Messages**: 401 Unauthorized - "Authentication required"

- **Method**: GET
- **URL Path**: /users/{user_id}/certificates/pending
- **Description**: Get pending certificate requests for the authenticated user.
- **Request JSON Structure**: None
- **Response JSON Structure**: {"certificates": [{"id": "uuid", "valid_days": "integer"}]}
- **Success Codes and Messages**: 200 OK - "List of certificate requests for user"
- **Error Codes and Messages**: 401 Unauthorized - "Authentication required"

- **Method**: GET
- **URL Path**: /users/{user_id}/certificates/expiring
- **Description**: Get certificates expiring soon for the authenticated user. For regular users, it returns their own expiring certificates. For admins, it returns expiring certificates for the specified user.
- **Query Parameters**: days=integer (default 30)
- **Request JSON Structure**: None
- **Response JSON Structure**: {"certificates": [{"id": "uuid", "serial_number": "string", "dn": "string", "status": "string", "expiration_date": "timestamp", "renewed_count": "integer"}], "total": "integer", "page": "integer"}
- **Success Codes and Messages**: 200 OK - "Expiring certificates retrieved"
- **Error Codes and Messages**: 401 Unauthorized - "Authentication required"

- **Method**: PUT
- **URL Path**: /users/{user_id}/certificates/{id}/renew
- **Description**: Renew a certificate (user only for own certificates).
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: {"id": "uuid", "expiration_date": "timestamp", "renewed_count": "integer", "renewal_date": "timestamp"}
- **Success Codes and Messages**: 200 OK - "Certificate renewed"
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 404 Not Found - "Certificate not found", 400 Bad Request - "Certificate not renewable"

- **Method**: GET
- **URL Path**: /users/{user_id}/certificates/{id}/download
- **Description**: Download public certificate file (CRT/PEM).
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: Binary CRT/PEM file
- **Success Codes and Messages**: 200 OK - "File downloaded"
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 404 Not Found - "Certificate not found"

- **Method**: POST
- **URL Path**: /users/{user_id}/certificates/{id}/pkcs12
- **Description**: Download PKCS#12 file for the certificate (user can only download his own keys/certificates).
- **Query Parameters**: None
- **Request JSON Structure**: {"password": "string"}
- **Response JSON Structure**: Binary PKCS#12 file
- **Success Codes and Messages**: 200 OK - "File downloaded"
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 400 Bad Request - "Invalid password", 404 Not Found - "Certificate not found"

- **Method**: POST
- **URL Path**: /users/{user_id}/certificates/{id}/generate
- **Description**: Generate certificate from a PENDING certificate request (user can only generate their own certificates).
- **Query Parameters**: None
- **Request JSON Structure**: None
- **Response JSON Structure**: {"id": "uuid", "status": "ACTIVE", "serial_number": "string", "pfx": String}
- **Error Codes and Messages**: 403 Forbidden - "Access denied", 404 Not Found - "Certificate not found", 400 Bad Request - "Certificate not in PENDING status"
- **Request JSON Structure**: {"password": "string"}
- **Error Codes and Messages**: 200 OK - "Certificate generated successfully, 403 Forbidden - "Access denied", 400 Bad Request - "Invalid password", 404 Not Found - "Certificate not found"

- **Method**: PUT
- **URL Path**: /users/{user_id}/certificates/{id}/revoke
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
  - Users: Username must be unique, password hashed, role must be 'ADMIN' or 'USER', password min 8 chars during registration.
  - Certificates: Serial number unique, status 'PENDING', 'ACTIVE' or 'REVOKED', DN required, validity period 1 day to 10 years, hash algorithm one of SHA-256/384/512.
  - Private Keys: Encrypted with user's password, stored securely.
  - Revoked Certificates: One per certificate, reason optional.
- **Business Logic Implementation**: Registration validates password length and username uniqueness. Certificate creation by admin creates PENDING certificates. Users can generate certificates from PENDING requests, which creates keys via internal CA, signs with root CA key (password from ENV), and changes status to ACTIVE. Renewal updates expiration and count. Download decrypts key with password and packages PKCS#12. Notifications via expiring endpoint for frontend banner. Revocation updates status and logs reason. All operations enforce RLS-like access via JWT claims.
