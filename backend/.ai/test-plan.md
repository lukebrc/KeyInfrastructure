### Test Plan for the Backend Application

#### 1. Introduction and Scope

This document describes the test plan for the backend application, written in Rust using the `actix-web` framework and the `sqlx` library. The goal of the tests is to verify the correct implementation of functional and non-functional requirements defined in the `prd_summary.md` document, as well as to ensure the stability, security, and performance of the system.

**Tests will cover:**
*   Application business logic.
*   API endpoints (RESTful endpoints).
*   Integration with the PostgreSQL database.
*   Authentication and authorization mechanisms.
*   Concurrency handling and basic performance tests.

**Out of scope for these tests are:**
*   User interface (frontend) tests.
*   Full E2E flow tests involving a browser.
*   Infrastructure tests (DigitalOcean, Docker).

#### 2. Test Objectives

*   **Functional Verification:** To ensure that all functional requirements and user stories have been implemented correctly.
*   **Security Verification:** To check key security aspects, such as encryption, authentication, and authorization.
*   **Performance Verification:** To confirm that the backend meets the defined success criteria for concurrency and capacity.
*   **Error Handling Verification:** To ensure that the API handles invalid input and exceptional states in a predictable and consistent manner.
*   **Integration Verification:** To check the correctness of the interaction between the service and the database.

#### 3. Testing Strategy

According to the `prd_summary.md` document, the main focus will be on integration tests written in Rust.

*   **Unit Tests:**
    *   **Objective:** Isolated testing of individual functions, especially those containing complex logic (e.g., cryptographic functions, DN validation).
    *   **Tools:** Rust's built-in test framework (`#[test]`).

*   **Integration Tests:**
    *   **Objective:** Testing the interaction between application components, mainly at the API level. They will simulate HTTP requests to endpoints and verify the responses and the state of the database.
    *   **Tools:** `actix-web::test`, `sqlx` with the `sqlx::test` feature for managing transactions in tests, `tokio` for asynchronous tests.
    *   **Environment:** A separate test database, initialized before running the tests.

*   **Load Tests:**
    *   **Objective:** Verification of the success criterion regarding handling 10 concurrent users.
    *   **Tools:** Rust integration tests with `tokio::spawn` can be used to simulate concurrent requests, or an external tool like `k6` or `wrk`.

#### 4. Test Scenarios

The following scenarios are based on the requirements and user stories.

##### 4.1. User Management and Authentication

| Test ID   | Description                                                                          | Expected Result                                                              | Priority  | Test Type     |
| :-------- | :----------------------------------------------------------------------------------- | :--------------------------------------------------------------------------- | :-------- | :------------ |
| **AUTH-01** | Register a new user with valid data (unique username, password, PIN min. 8 chars). | User is created in the database (status 201). The password is hashed.       | **Critical**  | Integration   |
| **AUTH-02** | Attempt to register with an existing `username`.                                     | The server returns a 409 (Conflict) error.                                   | High      | Integration   |
| **AUTH-03** | Attempt to register with a PIN shorter than 8 characters.                            | The server returns a 400 (Bad Request) error with a validation message.      | High      | Integration   |
| **AUTH-04** | Log in with correct credentials.                                                     | The server returns a JWT token (status 200).                                 | **Critical**  | Integration   |
| **AUTH-05** | Log in with an incorrect password.                                                   | The server returns a 401 (Unauthorized) error.                               | **Critical**  | Integration   |
| **AUTH-06** | Access a protected resource (e.g., `GET /certificates`) without a token.            | The server returns a 401 (Unauthorized) error.                               | **Critical**  | Integration   |
| **AUTH-07** | Access a protected resource with an expired token.                                   | The server returns a 401 (Unauthorized) error.                               | High      | Integration   |
| **AUTH-08** | Access an admin resource (`/admin/*`) as a regular user.                             | The server returns a 403 (Forbidden) error.                                  | **Critical**  | Integration   |

##### 4.2. Certificate Lifecycle

| Test ID   | Description                                                                          | Expected Result                                                                                      | Priority  | Test Type     |
| :-------- | :----------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------- | :-------- | :------------ |
| **CERT-01** | Administrator creates a certificate requests for a user with valid data (DN, validity, hash). | The certificate order is created and saved to the database (status 201). | **Critical**  | Integration   |
| **CERT-02** | Attempt to create a certificate for a non-existent user.                             | The server returns a 404 (Not Found) error.                                                          | High      | Integration   |
| **CERT-03** | User get list of available certificate requests | The server returns a list of pending requests (status 200). | High      | Integration   |
| **CERT-04** | User generate certificate basing on pending certificate request                      | The server generates a certificate for user (status 200). | **Critical** | Integration   |
| **CERT-04-UNIT** | Unit test for certificate generation cryptographic logic (key generation, certificate building, signing with CA) | Key and certificate generated correctly, signed by CA, valid structure. | **Critical** | Unit |
| **CERT-05** | User downloads their certificate (PKCS#12) by providing the correct PIN.             | The server returns a binary file (status 200). The file is encrypted with the provided PIN.         | **Critical**  | Integration   |
| **CERT-06** | User attempts to download a certificate by providing an incorrect PIN.               | The server returns a 400 (Bad Request) error with a message about the incorrect PIN.               | **Critical**  | Integration   |
| **CERT-07** | User attempts to download another user's certificate.                                | The server returns a 403 (Forbidden) or 404 (Not Found) error.                                       | **Critical**  | Integration   |
| **CERT-08** | User initiates certificate renewal.                                                  | A new certificate is generated, the old one is marked accordingly (if that is the logic).          | High      | Integration   |
| **CERT-09A** | A normal user queries `GET /certificates/expiring` to get a list of their own certificates expiring within N days. | The list contains only the current user's certificates that are expiring. If there are none, the list is empty. | High      | Integration   |
| **CERT-09B** | An ADMIN user queries `GET /certificates/expiring` to get a list of all certificates expiring within N days. | The list contains all certificates expiring within N days from all users. If there are none, the list is empty. | High      | Integration   |
| **CERT-10** | Administrator revokes a certificate using `PUT /certificates/{id}/revoke` with a reason. | The server returns 200 OK. The certificate status is changed to REVOKED, revocation_date is set, and the certificate is recorded in revoked_certificates table. | **Critical**  | Integration   |
| **CERT-11** | A regular user attempts to revoke a certificate. | The server returns a 403 (Forbidden) error with message "Admin access required". | **Critical**  | Integration   |
| **CERT-12** | Attempt to revoke a non-existent certificate. | The server returns a 404 (Not Found) error with message "Certificate not found". | High      | Integration   |

##### 4.3. Concurrency and Performance Tests

| Test ID   | Description                                                                     | Expected Result                                                                      | Priority | Test Type  |
| :-------- | :------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------- | :------- | :--------- |
| **PERF-01** | Simulate 10 concurrent logins of different users.                               | All users successfully receive JWT tokens without errors and in an acceptable time (< 500ms). | High     | Load Test  |
| **PERF-02** | Simulate 10 concurrent requests for the list of certificates (`GET /certificates`). | All requests complete successfully (status 200) without timeouts.                      | High     | Load Test  |

#### 5. Test Environment and Tools

*   **Language and Framework:** Rust, `actix-web`.
*   **Database:** Dedicated PostgreSQL instance for tests, managed by `sqlx-cli` and `sqlx::test`.
*   **Build and CI Tools:** GitHub Actions for automatically running tests (`cargo test`) on every push to the repository.
*   **Additional Tools:** `k6` (optional) for more advanced load testing.

#### 6. Risks and Contingency Plan

*   **Risk:** Ambiguity in handling the PIN on the server-side (as per `unresolved_issues`). Tests may reveal a security vulnerability or an incorrect flow.
*   **Plan:** Prioritize tests `CERT-03` and `CERT-04`. If a problem is detected, consultation with the development team will be necessary to change the architecture.
*   **Risk:** Lack of defined constraints for DN and certificate validity fields.
*   **Plan:** Use a wide range of values in tests (short, long, with special characters) to uncover potential validation or handling issues by cryptographic libraries.
