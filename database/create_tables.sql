-- Database Schema Creation Script for KeyInfrastructure Project
-- This script creates all necessary tables, indexes, and security policies for PostgreSQL.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create ENUM types
CREATE TYPE user_role AS ENUM ('ADMIN', 'USER');
CREATE TYPE certificate_status AS ENUM ('ACTIVE', 'REVOKED');

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'USER',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS certificate_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dn TEXT NOT NULL,
    validity_period_days INTEGER NOT NULL CHECK (validity_period_days >= 1 AND validity_period_days <= 3650),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY REFERENCES certificate_requests(id),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    serial_number VARCHAR(255) UNIQUE NOT NULL,
    status certificate_status NOT NULL DEFAULT 'ACTIVE',
    expiration_date TIMESTAMPTZ NOT NULL,
    renewed_count INTEGER NOT NULL DEFAULT 0,
    certificate_der BYTEA,
    renewal_date TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS private_keys (
    id UUID PRIMARY KEY REFERENCES certificates(id),
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    encrypted_key BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    UNIQUE (certificate_id)
);

CREATE TABLE IF NOT EXISTS revoked_certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    revocation_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason VARCHAR(255),
    UNIQUE (certificate_id)
);

-- Create indexes for performance

-- Indexes for users
CREATE UNIQUE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_role ON users (role);

-- Indexes for certificates
CREATE UNIQUE INDEX idx_certificates_serial_number ON certificates (serial_number);
CREATE INDEX idx_certificates_user_id ON certificates (user_id);
CREATE INDEX idx_certificates_expiration_date ON certificates (expiration_date);
CREATE INDEX idx_certificates_user_status ON certificates (user_id, status);
CREATE INDEX idx_certificates_expiration_status ON certificates (expiration_date, status);
-- Partial index for active certificates only
CREATE INDEX idx_certificates_active_expiration ON certificates (expiration_date) WHERE status = 'ACTIVE';

-- Indexes for private_keys
CREATE INDEX idx_private_keys_certificate_id ON private_keys (certificate_id);

-- Indexes for revoked_certificates
CREATE INDEX idx_revoked_certificates_certificate_id ON revoked_certificates (certificate_id);
CREATE INDEX idx_revoked_certificates_revocation_date ON revoked_certificates (revocation_date);

-- Enable Row Level Security (RLS) and create policies

-- Enable RLS on relevant tables
ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE private_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_certificates ENABLE ROW LEVEL SECURITY;

-- Policies for certificates
-- Users can only see their own certificates
CREATE POLICY user_certificates ON certificates FOR ALL USING (
    user_id = current_setting('app.current_user_id', true)::UUID
);
-- Admins can see all certificates
CREATE POLICY admin_certificates ON certificates FOR ALL USING (
    EXISTS (SELECT 1 FROM users WHERE id = current_setting('app.current_user_id', true)::UUID AND role = 'ADMIN')
);

-- Policies for private_keys (similar to certificates)
CREATE POLICY user_private_keys ON private_keys FOR ALL USING (
    EXISTS (SELECT 1 FROM certificates WHERE certificates.id = private_keys.certificate_id AND certificates.user_id = current_setting('app.current_user_id', true)::UUID)
);
CREATE POLICY admin_private_keys ON private_keys FOR ALL USING (
    EXISTS (SELECT 1 FROM users WHERE id = current_setting('app.current_user_id', true)::UUID AND role = 'ADMIN')
);

-- Policies for revoked_certificates (similar to certificates)
CREATE POLICY user_revoked_certificates ON revoked_certificates FOR ALL USING (
    EXISTS (SELECT 1 FROM certificates WHERE certificates.id = revoked_certificates.certificate_id AND certificates.user_id = current_setting('app.current_user_id', true)::UUID)
);
CREATE POLICY admin_revoked_certificates ON revoked_certificates FOR ALL USING (
    EXISTS (SELECT 1 FROM users WHERE id = current_setting('app.current_user_id', true)::UUID AND role = 'ADMIN')
);

-- INSERT INTO users (username, password_hash, role, created_at, last_login_at)
--     VALUES('admin', '$2b$12$SoOS5Rb8Eqt9gUXEoJ3D3Objyd13ipwTe4t0aBFQqXCEhl7QZF.32', --admin123
--         'ADMIN', CURRENT_TIMESTAMP, null);

-- Additional notes:
-- 1. RLS: The policies assume a custom setting 'app.current_user_id' is set by the application (e.g., via SET LOCAL).
--    Adjust based on your authentication mechanism (e.g., using JWT or session-based user context).
-- 2. Security: Ensure that only trusted roles can set 'app.current_user_id'. Use pgcrypto for encryption functions in the application.
-- 3. Performance: Monitor query performance and adjust indexes as needed. Consider additional composite indexes for common queries.
