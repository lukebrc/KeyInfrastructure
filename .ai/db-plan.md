# Database Schema for KeyInfrastructure Project

## 1. List of tables with their columns, data types, and constraints

### users
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **username**: VARCHAR(255) UNIQUE NOT NULL
- **password_hash**: VARCHAR(255) NOT NULL (HMAC-SHA256 hash hasła)
- **role**: ENUM('ADMIN', 'USER') NOT NULL DEFAULT 'USER'
- **created_at**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **last_login_at**: TIMESTAMPTZ (NULLABLE, aktualizowane przy logowaniu)

**Constraints**:
- UNIQUE on username
- CHECK on role (only 'ADMIN' or 'USER')

### certificates
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **user_id**: UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
- **serial_number**: VARCHAR(255) UNIQUE NOT NULL (cryptographically secure, generated in Rust)
- **dn**: TEXT NOT NULL (e.g., "C=PL,CN=username,O=Organization,OU=Unit")
- **status**: ENUM('ACTIVE', 'REVOKED') NOT NULL DEFAULT 'ACTIVE'
- **expiration_date**: TIMESTAMPTZ NOT NULL (calculated as created_at + validity_period_days)
- **created_at**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **renewed_count**: INTEGER NOT NULL DEFAULT 0
- **renewal_date**: TIMESTAMPTZ (NULLABLE, updated on renewal)

**Constraints**:
- UNIQUE on serial_number
- CHECK on status (only allowed values)

### private_keys
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **certificate_id**: UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE
- **encrypted_key**: BYTEA NOT NULL (private key encrypted with AES-256 using user's PIN)
- **salt**: BYTEA NOT NULL (random salt for encryption)

**Constraints**:
- UNIQUE on certificate_id (one key per certificate)

### revoked_certificates
- **id**: UUID PRIMARY KEY (generowane automatycznie)
- **certificate_id**: UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE
- **revocation_date**: TIMESTAMPTZ NOT NULL DEFAULT NOW()
- **reason**: VARCHAR(255) (e.g., 'KEY_COMPROMISE', 'AFFILIATION_CHANGED')

**Constraints**:
- UNIQUE on certificate_id (certificate can be revoked only once)

## 2. Relationships between tables

- **users to certificates**: One-to-many (one user can have multiple certificates)
- **certificates to private_keys**: One-to-one (each certificate has one private key)
- **certificates to revoked_certificates**: One-to-one (certificate can be revoked only once, if at all)

## 3. Indexes

- **users**:
  - UNIQUE INDEX on username (for fast lookup during login)
  - INDEX on role (for administrative queries)

- **certificates**:
  - UNIQUE INDEX on serial_number (required for uniqueness)
  - INDEX on user_id (for user queries about their certificates)
  - INDEX on expiration_date (for expiration notifications)
  - COMPOSITE INDEX on (user_id, status) (optimization for user queries)
  - COMPOSITE INDEX on (expiration_date, status) (for queries about expiring certificates)
  - PARTIAL INDEX on expiration_date WHERE status = 'ACTIVE' (only active certificates)

- **private_keys**:
  - INDEX on certificate_id (for fast key access)

- **revoked_certificates**:
  - INDEX on certificate_id (for revocation checks)
  - INDEX on revocation_date (for reports)

## 4. PostgreSQL Row-Level Security (RLS) Policies

- **users**: No RLS (administrators manage directly)
- **certificates**: 
  - Users see only their own certificates (WHERE user_id = current_user_id())
  - Administrators see all certificates
- **private_keys**: 
  - Users see only keys for their certificates
  - Administrators see all keys
- **revoked_certificates**: Similar to certificates

## 5. Additional notes and explanations regarding design decisions

- **Normalization**: Schema is in 3NF; denormalization is not required as performance is ensured through indexes.
- **Encryption**: Private keys are encrypted with AES-256 using user's PIN as the key (PIN not stored in database). CA key is encrypted with password from ENV.
- **UUID**: Used for global uniqueness and security (harder to guess than sequential IDs).
- **Certificate status**: 'ACTIVE' for valid, 'EXPIRED' for expired, 'REVOKED' for revoked.
- **Problem resolution**:
  - PIN: Not stored; used only for PKCS#12 encryption during download.
  - DN fields: Standard (C, CN, O, OU, etc.), stored as text string.
  - Key backup: Encrypted copy in private_keys.
  - Key algorithm: RSA 4096 (hardcoded in backend).
  - Validity period: 1 day to 10 years.
- **Performance**: Optimized for 100 users, 10 certificates per user, 10 concurrent users through indexes.
- **PostgreSQL extensions**: Required: pgcrypto for encryption, uuid-ossp for UUID.
