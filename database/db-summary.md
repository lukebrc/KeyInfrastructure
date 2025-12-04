# Database Planning Summary for KeyInfrastructure Project

## Overview
This document summarizes the iterative planning process for designing a PostgreSQL database schema for the KeyInfrastructure project, a certificate and key management system for network devices. The planning involved multiple rounds of questions and recommendations to address ambiguities, performance considerations, security requirements, and scalability needs for an MVP supporting 100 users with up to 10 certificates each.

## Key Planning Phases

### Phase 1: Initial Assessment
The first phase identified core entities (users, certificates, private keys, roles) and raised questions about authentication, certificate management, security, and performance. Key decisions included:
- Simple role-based access with admin/user roles
- Stateless JWT authentication
- Separate storage for certificates and private keys
- AES-256 encryption for private key backups
- Monthly table partitioning by expiration date

### Phase 2: Detailed Refinement
Based on initial responses, the second phase delved deeper into implementation specifics:
- ENUM types for roles with ADMIN/USER values
- HMAC-SHA256 password hashing in Rust backend
- Secure random serial number generation with uniqueness validation
- Separate revoked_certificates table for CRL management
- BYTEA storage for binary certificate and key data
- RLS policies for data isolation
- Optimized indexing and materialized views for performance

### Phase 3: Final Schema Synthesis
The final phase consolidated all decisions into a comprehensive database architecture:
- UUID primary keys for global uniqueness
- Proper foreign key relationships with CASCADE rules
- TIMESTAMPTZ for timezone-aware timestamps
- Connection pooling configuration (5-20 connections)
- Automated partition management with 2-year retention
- PostgreSQL functions for certificate expiration queries

## Core Database Schema Decisions

### User Management
- **Roles**: ENUM type (ADMIN, USER) with direct column updates
- **Authentication**: HMAC-SHA256 hashing, JWT tokens, no session storage
- **Security**: RLS policies ensuring users see only their certificates

### Certificate Management
- **Storage**: Separate tables for certificates and private_keys
- **Serial Numbers**: Cryptographically secure random values with uniqueness constraints
- **Renewal**: Version counter, renewal date, and admin tracking
- **DN Fields**: Single TEXT column for flexible DN storage

### Security & Encryption
- **Private Keys**: AES-256 encrypted, stored as BYTEA with separate salt column
- **PIN**: Not stored in database, used only for PKCS#12 encryption
- **CRL**: Separate table for revoked certificates with revocation dates

### Performance & Scalability
- **Partitioning**: Monthly partitions by expiration_date with automated cleanup
- **Indexing**: Composite and partial indexes for efficient queries
- **Connection Pooling**: Configured for 10 concurrent users with timeout handling
- **Query Optimization**: Functions for expiring certificate alerts (7-day window)

### Data Integrity & Constraints
- **Primary Keys**: UUID across all tables
- **Foreign Keys**: Proper relationships with CASCADE options
- **Constraints**: UNIQUE on usernames and certificate serials, CHECK on PIN length
- **Timestamps**: TIMESTAMPTZ for all date fields

## Unresolved Issues
Several implementation details remain to be specified:
- Exact salt length for password hashing
- CRL storage format (BYTEA vs TEXT)
- Key versioning implementation for encryption upgrades
- Certificate status ENUM values
- Admin certificate assignment workflow
- Specific connection validation queries
- PostgreSQL function signatures
- Partition maintenance scheduling
- Backup encryption strategies
- Database-level error handling requirements

## Technical Implementation
- **Database**: PostgreSQL with pgcrypto extension
- **Backend Integration**: Rust with sqlx for type-safe queries
- **Storage**: Binary formats for certificates and encrypted keys
- **Migration**: Automated scripts with rollback procedures
- **Monitoring**: Expiration alerts and performance tracking

This planning process resulted in a robust, scalable database design that balances security, performance, and maintainability for the certificate management system's MVP requirements.
