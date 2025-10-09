# Product Requirements Documents - KeyInfrastructure

## Product overview

This project is used for generating and automatically renewing certificates and keys for a network of nodes/devices (ie. PC, smartphone and other with web browser and network).

## User problem

Generating and refreshing certificates for greater network is problematic for administrator. Especially making sure that certificate didn't expire. This project automates some tasks concerning generation and renewal.

## Functional requirements of the project
*   **User Management:**
    *   The system must allow new users to self-register with a username, password, and an 8-character minimum PIN.
    *   The system must authenticate users based on their username and password.
*   **Administrator Management:**
    *   The system must support a single administrator role with full privileges.
    *   Administrator accounts must be manageable via direct database manipulation.
*   **Certificate Generation & Management:**
    *   Administrators must have an interface to create new certificates for users.
    *   This interface must allow the administrator to specify the certificate's validity period, hash algorithm (SHA-256, SHA-384, SHA-512), and all Distinguished Name (DN) fields.
    *   The system must store an encrypted backup of the user's private key in the database.
*   **User-Facing Functionality:**
    *   The system must allow authenticated users to download their key/certificate pair in a PKCS#12 file protected by their PIN.
    *   The system must display a prominent banner to users whose certificate is near or past its expiration date, prompting them to renew.
    *   Users must be able to initiate the certificate renewal process.
*   **Internal Certificate Authority:**
    *   The system must operate its own root CA to sign all user certificates.
    *   The root CA's private key must be accessible to the application, secured by a password loaded from an environment variable.

## Key user stories and use cases
*   **As a User,** I want to register for an account by providing my credentials and a PIN so that I can have my certificates managed by the system.
*   **As a User,** I want to log in to the portal with my username and password to access my certificate information.
*   **As a User,** I want to be clearly notified when my certificate is about to expire so I can take action to renew it.
*   **As a User,** I want to download my certificate and private key securely packaged in a file that is protected by my PIN.
*   **As an Administrator,** I want to log in to the system to manage users and their certificates.
*   **As an Administrator,** I want to create a new certificate for a user by specifying all its required parameters to meet our organizational standards.

## Important criterias of success and measurement methods
*   **Concurrency:** The system must handle 10 concurrent users.
    *   **Measurement:** This will be validated via Rust integration tests that simulate concurrent user logins and certificate validity checks.
*   **Capacity:** The system must support at least 100 total users, with at least 10 keys/certificates per user.
    *   **Measurement:** Verified by database capacity and application performance under load from integration tests.
*   **Core Functionality:** The user registration, login, and certificate download/renewal flows must be fully functional.
    *   **Measurement:** Successful completion of the end-to-end user lifecycle scenarios in the Rust integration tests.
*   **Usability:** The certificate expiration notification must be effective at prompting users to renew.
    *   **Measurement:** While difficult to quantify in the MVP, a successful design will be one that is clear, prominent, and provides a direct call to action.

## What is NOT in the MVP scope
- The method of storing private keys and certificates by the user.
- The transfer of temporary passwords from the administrator to the user.
- Communication between the client and the administrator.
- The situation where a user forgets their password or PIN.

