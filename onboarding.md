# Onboarding Guide: KeyInfrastructure Project

Welcome to the KeyInfrastructure project! This document provides a comprehensive overview to get you started.

## 1. Project Overview

This project is used for generating and automatically renewing certificates and keys for a network of nodes/devices (e.g., PCs, smartphones, and other devices with a web browser and network access). It automates the generation and renewal process to prevent certificate expiration.

## 2. Tech Stack

-   **Frontend:** Astro with React for interactive components.
    -   **Frameworks:** Astro 5, React 19
    -   **Language:** TypeScript 5
    -   **Styling:** Tailwind CSS 4
    -   **Components:** Shadcn/ui
-   **Backend:** Rust with actix-web and sqlx.
    -   **Database:** PostgreSQL
    -   **Features:** Built-in user authentication.
-   **CI/CD & Hosting:**
    -   **CI/CD:** GitHub Actions

## 3. Project Structure

The project is organized into three main sub-projects:

-   `frontend/`: The web interface for administrators and users.
-   `backend/`: A REST web service written in Rust, which serves requests from the frontend and other potential clients.
-   `database/`: Contains all files and scripts related to the database schema and management.

## 4. Core Functionality

-   **User Management:** Users can self-register with a username and password. The system authenticates users based on these credentials.
-   **Administrator Management:** A single administrator role has full privileges. Admin accounts are managed directly via the database.
-   **Certificate Generation:** Administrators can create new certificates for users, specifying the validity period, hash algorithm (SHA-256, SHA-384, SHA-512), and all Distinguished Name (DN) fields.
-   **Key Management:** The system stores an encrypted backup of each user's private key in the database.
-   **User-Facing Features:**
    -   Authenticated users can download their key/certificate pair as a PKCS#12 file, protected by their password.
    -   A prominent banner notifies users when their certificate is near or past its expiration date, prompting them to renew.
    -   Users can initiate the certificate renewal process themselves.
-   **Internal Certificate Authority (CA):** The system operates its own root CA to sign all user certificates. The root CA's private key is secured by a password loaded from an environment variable.

## 5. Development Guidelines

### Commit & Pull Request Guidelines

-   Follow the **Conventional Commits** pattern (e.g., `feat: add user registration`, `fix: correct certificate parsing`).
-   Keep commits tightly scoped.
-   Pull requests should link to any tracked task, summarize changes, and include relevant output or screenshots.

### General Coding Practices

-   Favor elegant, maintainable solutions.
-   Focus comments on the 'why,' not the 'what.'
-   Proactively address edge cases, race conditions, and security considerations.

### Frontend (React)

-   Use functional components with hooks.
-   Use `React.memo()` for expensive components.
-   Utilize `React.lazy()` and `Suspense` for code-splitting.
-   Use `useCallback` for event handlers passed to child components.
-   Use `useMemo` for expensive calculations.

### Database (PostgreSQL)

-   Use connection pooling to manage database connections efficiently.
-   Implement JSONB columns for semi-structured data where appropriate.
-   Use materialized views for complex, frequently accessed read-only data.

### CI/CD (GitHub Actions)

-   Use `env:` variables and secrets attached to jobs instead of global workflow configurations.
-   Use `npm ci` for installing Node.js dependencies.
-   Extract common steps into composite actions.
-   Ensure you are using the latest major versions for all public actions.

## 6. Unresolved MVP Issues

These are known issues and ambiguities that need to be addressed:

1.  **PIN/Password Handling:** The workflow for accessing the user's password to encrypt the PKCS#12 file upon download needs to be securely defined, as the user only enters it at registration.
2.  **Administrator DN Fields:** The specific fields that constitute the Distinguished Name (e.g., Common Name, Organization) have not been defined.
3.  **Key Backup Definition:** The requirement for key backup is ambiguous—it's unclear if this means a database backup or a separate escrow mechanism.
4.  **Hardcoded Algorithm:** The specific hardcoded key algorithm (e.g., RSA 4096) has not been specified.
5.  **Certificate Validity Constraints:** The minimum and maximum allowed values for the certificate validity period are undefined.
