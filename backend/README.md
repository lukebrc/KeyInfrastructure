# KeyInfrastructure Backend

REST web service written in Rust that provides APIs for generating and automatically renewing certificates and keys for a network of nodes/devices. This service serves requests from web-admin and web-user frontends, as well as other clients.

## Overview

The backend provides a RESTful API for:
- User registration and authentication
- Certificate generation and management
- Certificate renewal and revocation
- PKCS#12 file generation for secure key/certificate downloads
- Internal Certificate Authority (CA) operations

## Project Structure

```
backend/
├── src/
│   ├── main.rs          # Application entry point and server setup
│   └── auth.rs          # Authentication and user registration handlers
├── test/                # Integration tests
├── Cargo.toml           # Rust dependencies and project configuration
└── README.md            # This file
```

## Features

### User Management
- Self-registration with username, password, and PIN (minimum 8 characters)
- JWT-based authentication
- Role-based access control (USER, ADMIN)

### Certificate Management
- Certificate creation by administrators with configurable parameters:
  - Validity period (1 day to 10 years)
  - Hash algorithm (SHA-256, SHA-384, SHA-512)
  - Distinguished Name (DN) fields
- Certificate renewal initiated by users
- Certificate revocation by administrators
- Encrypted private key backup storage

### Certificate Authority
- Self-hosted root CA for signing user certificates
- Password-protected CA private key (loaded from environment variable)

## Technology Stack

- **Framework**: Actix-web 4.x
- **Database**: PostgreSQL (via SQLx)
- **Authentication**: JWT tokens
- **Password Hashing**: Argon2
- **Certificate Operations**: (to be implemented)

## Requirements

- Rust 1.70+ (Edition 2024)
- PostgreSQL database
- Environment variables configured (see Configuration section)

## Building

```bash
# Build the project
cargo build

# Build for production (release mode)
cargo build --release
```

## Running

```bash
# Run in development mode
cargo run

# Run in release mode
cargo run --release
```

The server will start on `0.0.0.0:8080` by default.

## Configuration

The backend requires the following environment variables:

- `DATABASE_URL`: PostgreSQL connection string (e.g., `postgresql://user:password@localhost/keyinfrastructure`)
- `CA_PRIVATE_KEY_PASSWORD`: Password for the root CA private key (required for certificate operations)
- `JWT_SECRET`: Secret key for JWT token signing (required for authentication)

You can use a `.env` file in the backend directory (automatically loaded via `dotenvy`):

```env
DATABASE_URL=postgresql://user:password@localhost/keyinfrastructure
CA_PRIVATE_KEY_PASSWORD=your_ca_password
JWT_SECRET=your_jwt_secret_key
```

## API Documentation

### Authentication Endpoints

#### Register User
- **Method**: `POST`
- **Path**: `/users`
- **Description**: Register a new user account
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string",
    "pin": "string (min 8 chars)"
  }
  ```
- **Response** (201 Created):
  ```json
  {
    "id": "uuid",
    "username": "string",
    "role": "string",
    "created_at": "timestamp"
  }
  ```
- **Error Codes**: 
  - `400 Bad Request`: Invalid input data
  - `409 Conflict`: Username already exists

#### Login
- **Method**: `POST`
- **Path**: `/login`
- **Description**: Authenticate a user and receive a JWT token
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "token": "string",
    "user": {
      "id": "uuid",
      "username": "string",
      "role": "string"
    }
  }
  ```
- **Error Codes**: 
  - `401 Unauthorized`: Invalid credentials

### User Endpoints

#### Get User Details
- **Method**: `GET`
- **Path**: `/users/{id}`
- **Description**: Retrieve user details (self or admin only)
- **Headers**: `Authorization: Bearer <token>`
- **Response** (200 OK):
  ```json
  {
    "id": "uuid",
    "username": "string",
    "role": "string",
    "created_at": "timestamp",
    "last_login_at": "timestamp"
  }
  ```
- **Error Codes**: 
  - `401 Unauthorized`: Authentication required
  - `403 Forbidden`: Access denied
  - `404 Not Found`: User not found

### Certificate Endpoints

#### Create Certificate
- **Method**: `POST`
- **Path**: `/users/{user_id}/certificates`
- **Description**: Create a new certificate for a user (admin only)
- **Headers**: `Authorization: Bearer <token>`
- **Request Body**:
  ```json
  {
    "validity_period_days": "integer",
    "hash_algorithm": "string (SHA-256|SHA-384|SHA-512)",
    "dn": "string"
  }
  ```
- **Response** (201 Created):
  ```json
  {
    "id": "uuid",
    "serial_number": "string",
    "dn": "string",
    "status": "string",
    "expiration_date": "timestamp",
    "created_at": "timestamp"
  }
  ```
- **Error Codes**: 
  - `400 Bad Request`: Invalid DN or parameters
  - `403 Forbidden`: Admin access required

#### List Certificates
- **Method**: `GET`
- **Path**: `/certificates`
- **Description**: List certificates for the authenticated user with pagination, filtering, and sorting
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**: 
  - `page` (integer): Page number
  - `limit` (integer): Items per page
  - `status` (string): Filter by status
  - `sort_by` (string): Sort field (e.g., `expiration_date`)
  - `order` (string): Sort order (`asc` or `desc`)
- **Response** (200 OK):
  ```json
  {
    "certificates": [
      {
        "id": "uuid",
        "serial_number": "string",
        "dn": "string",
        "status": "string",
        "expiration_date": "timestamp",
        "renewed_count": "integer"
      }
    ],
    "total": "integer",
    "page": "integer"
  }
  ```
- **Error Codes**: 
  - `401 Unauthorized`: Authentication required

#### Get Expiring Certificates
- **Method**: `GET`
- **Path**: `/certificates/expiring`
- **Description**: Get certificates expiring soon for the authenticated user
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**: 
  - `days` (integer, default 30): Number of days ahead to check
- **Response** (200 OK):
  ```json
  {
    "certificates": [
      {
        "id": "uuid",
        "expiration_date": "timestamp"
      }
    ]
  }
  ```
- **Error Codes**: 
  - `401 Unauthorized`: Authentication required

#### Renew Certificate
- **Method**: `PUT`
- **Path**: `/certificates/{id}/renew`
- **Description**: Renew a certificate (user only for own certificates)
- **Headers**: `Authorization: Bearer <token>`
- **Response** (200 OK):
  ```json
  {
    "id": "uuid",
    "expiration_date": "timestamp",
    "renewed_count": "integer",
    "renewal_date": "timestamp"
  }
  ```
- **Error Codes**: 
  - `400 Bad Request`: Certificate not renewable
  - `403 Forbidden`: Access denied
  - `404 Not Found`: Certificate not found

#### Download Certificate
- **Method**: `POST`
- **Path**: `/certificates/{id}/download`
- **Description**: Download PKCS#12 file for the certificate (user only for own)
- **Headers**: `Authorization: Bearer <token>`
- **Request Body**:
  ```json
  {
    "pin": "string"
  }
  ```
- **Response** (200 OK): Binary PKCS#12 file
- **Content-Type**: `application/x-pkcs12`
- **Error Codes**: 
  - `400 Bad Request`: Invalid PIN
  - `403 Forbidden`: Access denied
  - `404 Not Found`: Certificate not found

#### Revoke Certificate
- **Method**: `PUT`
- **Path**: `/certificates/{id}/revoke`
- **Description**: Revoke a certificate (admin only)
- **Headers**: `Authorization: Bearer <token>`
- **Request Body**:
  ```json
  {
    "reason": "string"
  }
  ```
- **Response** (200 OK):
  ```json
  {
    "id": "uuid",
    "status": "REVOKED",
    "revocation_date": "timestamp"
  }
  ```
- **Error Codes**: 
  - `403 Forbidden`: Admin access required
  - `404 Not Found`: Certificate not found

## Authentication & Authorization

### JWT Authentication
- Tokens are issued via `POST /login`
- Tokens expire after 1 hour
- Include token in subsequent requests: `Authorization: Bearer <token>`

### Role-Based Access Control
- **USER**: Can access own data and certificates
- **ADMIN**: Can access all users and certificates, create certificates, revoke certificates

Administrator accounts must be created via direct database manipulation.

### Rate Limiting
- 10 requests per minute per user to handle concurrency requirements

## Validation & Business Logic

### User Validation
- Username must be unique
- Password is hashed with Argon2
- Role must be 'ADMIN' or 'USER'
- PIN minimum 8 characters during registration

### Certificate Validation
- Serial number must be unique
- Status must be 'ACTIVE' or 'REVOKED'
- Distinguished Name (DN) is required
- Validity period: 1 day to 10 years
- Hash algorithm: SHA-256, SHA-384, or SHA-512

### Private Key Storage
- Private keys are encrypted with the user's PIN
- Encrypted keys are stored securely in the database

## Testing

Integration tests are provided in the `test/` directory to validate:
- User registration and login flows
- Concurrent user operations (handling 10 concurrent users)
- Certificate validity checks
- End-to-end user lifecycle scenarios

Run tests with:
```bash
cargo test
```

## Development

### Code Formatting & Linting

```bash
# Format code
cargo fmt

# Lint with clippy
cargo clippy --lib --bins -- -D "clippy::correctness" -D "clippy::suspicious" -D "clippy::perf" -W "clippy::style" -W "clippy::complexity"
```

## Related Documentation

- [Main Project README](../README.md)
- [Product Requirements Document](../.ai/prd.md)
- [API Plan](.ai/api-plan.md)
- [Backend Coding Guidelines](AGENTS.md)
