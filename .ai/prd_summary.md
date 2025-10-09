<conversation_summary>
<decisions>
1.  **User Registration:** Users will register via a simple form with a username and password. Email verification will not be implemented for the MVP.
2.  **PIN Management:** A PIN of at least 8 characters will be set by the user only during the registration phase. It will be used to password-protect the downloaded PKCS#12 file.
3.  **Key Storage & Security:** Private keys will be backed up on the server, encrypted with the user's PIN. The risk of a user brute-forcing the downloaded file is accepted, and no server-side lockout mechanism for PIN attempts will be implemented.
4.  **Administrator Role:** A single administrator role will exist. Admins are created by adding them directly to the database. They are responsible for manually filling in the Distinguished Name (DN) for each new certificate.
5.  **Certificate Configuration:** Administrators can set the certificate validity period and choose a hash algorithm from SHA-256, SHA-384, or SHA-512. The key algorithm is hardcoded.
6.  **Certificate Lifecycle:** Renewal is initiated by the user. An eye-catching banner will notify logged-in users of pending or actual certificate expiration. The consequences of an expired certificate are outside the scope of this project.
7.  **Certificate Authority (CA):** The system will use its own self-hosted root CA. The root CA's private key will be password-protected, with the password supplied via an environment variable. The associated risk is accepted for the MVP.
8.  **Testing:** Integration tests will be written in Rust to cover registration, login, and concurrent certificate validity checks.
</decisions>

<matched_recommendations>
1.  **Separation of Concerns (Password vs. PIN):** The decision to use a password for authentication and a separate PIN for cryptographic operations is a core security principle that has been adopted. This correctly separates access control from data protection.
2.  **Clear Renewal Workflow:** The plan to use a prominent, non-dismissible banner to notify users about certificate expiration is a critical UI/UX feature that will guide users and prevent lockouts.
3.  **Standardized Delivery Format:** Using the PIN to protect the PKCS#12 file simplifies the user experience by reducing the number of secrets the user needs to manage, directly matching the recommendation.
4.  **Secure Algorithm Choices:** Providing administrators with a choice of modern, secure hash functions (SHA-256, SHA-384, SHA-512) ensures that the generated certificates meet current security standards.
5.  **Focused MVP Testing:** While the initial recommendation was for broader testing, the decision to focus integration tests on the most critical paths (registration, login, concurrency) provides a solid baseline for MVP quality assurance.
6.  **Offline Root CA Security (Future-proofing):** Although an environment variable is used for the MVP, the recommendation to eventually move the root CA private key to an air-gapped machine and store it offline remains the most important long-term security goal for the project.
</matched_recommendations>

<prd_planning_summary>
### a) Main functional requirements of the project
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

### b) Key user stories and use cases
*   **As a User,** I want to register for an account by providing my credentials and a PIN so that I can have my certificates managed by the system.
*   **As a User,** I want to log in to the portal with my username and password to access my certificate information.
*   **As a User,** I want to be clearly notified when my certificate is about to expire so I can take action to renew it.
*   **As a User,** I want to download my certificate and private key securely packaged in a file that is protected by my PIN.
*   **As an Administrator,** I want to log in to the system to manage users and their certificates.
*   **As an Administrator,** I want to create a new certificate for a user by specifying all its required parameters to meet our organizational standards.

### c) Important criterias of success and measurement methods
*   **Concurrency:** The system must handle 10 concurrent users.
    *   **Measurement:** This will be validated via Rust integration tests that simulate concurrent user logins and certificate validity checks.
*   **Capacity:** The system must support at least 100 total users, with at least 10 keys/certificates per user.
    *   **Measurement:** Verified by database capacity and application performance under load from integration tests.
*   **Core Functionality:** The user registration, login, and certificate download/renewal flows must be fully functional.
    *   **Measurement:** Successful completion of the end-to-end user lifecycle scenarios in the Rust integration tests.
*   **Usability:** The certificate expiration notification must be effective at prompting users to renew.
    *   **Measurement:** While difficult to quantify in the MVP, a successful design will be one that is clear, prominent, and provides a direct call to action.

</prd_planning_summary>

<unresolved_issues>
1.  **PIN Handling Contradiction:** The user sets the PIN only at registration. However, the system needs this PIN later to encrypt the PKCS#12 file upon download. How does the server access the PIN at download time without the user re-entering it and without storing it insecurely? This is the most critical unresolved workflow issue.
2.  **Administrator DN Fields:** It is specified that the admin "will fill DN of certificate each time." The exact fields that constitute the Distinguished Name (e.g., Common Name, Organization, Organizational Unit, etc.) have not been defined.
3.  **Key Backup Definition:** The requirement that the "key must be backuped" is ambiguous. It is unclear if this simply refers to the database backup of the encrypted key blob or if a separate key escrow or backup mechanism is required.
4.  **Hardcoded Algorithm Specification:** The specific hardcoded key algorithm (e.g., RSA 4096, ECDSA P-256) has not been specified. This must be documented.
5.  **Certificate Validity Constraints:** The acceptable minimum and maximum values for the certificate validity period that an administrator can set are undefined.
</unresolved_issues>
</conversation_summary>