You are an experienced product manager whose task is to help create a comprehensive Product Requirements Document (PRD) based on the provided information. Your goal is to generate a list of questions and recommendations that will be used in subsequent prompting to create a complete PRD.

Please carefully review the following information:

<project_description>
##  Main problem

Generating and automatically renewing certificates and keys for a network of nodes/devices (ie. PC, smartphone and other with web browser and network).

## Minimum Viable Product (MVP) Scope
- Administrator mode: specifying the data of generated keys/certificates and, if necessary, manually replacing them.
- User mode: logging in and registering to the system, and possibly replacing the current certificate(s).
- Administrator and user profile page.
- A database with a copy of the keys (encrypted with the user's PIN) and the user's current certificates.

## What is NOT in the MVP scope
- The method of storing private keys and certificates by the user.
- The transfer of temporary passwords from the administrator to the user.
- Communication between the client and the administrator.
- The situation where a user forgets their password or PIN.

##  Success criteria
- The system can handle 10 concurrent users, and a total of at least 100.
- For each user, we must support at least 10 keys/certificates.
- The user can log in and set their PIN.
</project_description>

Analyze the information provided, focusing on aspects relevant to PRD creation. Consider the following questions:
<prd_analysis>
1. Identify the main problem that the product is intended to solve.
2. Define the key functionalities of the MVP.
3. Consider potential user stories and paths of product usage.
4. Think about success criteria and how to measure them.
5. Assess design constraints and their impact on product development.
</prd_analysis>

Based on your analysis, generate a list of 10 questions and recommendations in a combined form (question + recommendation). These should address any ambiguities, potential issues, or areas where more information is needed to create an effective PRD. Consider questions about:

1. Details of the user's problem
2. Prioritization of functionality
3. Expected user experience
4. Measurable success indicators
5. Potential risks and challenges
6. Schedule and resources

<questions>
List your questions and recommendations here, numbered for clarity:

For example:
1. Are you planning to introduce paid subscriptions from the start of the project?

Recommendation: The first phase of the project could focus on free features to attract users, and paid features could be introduced at a later stage.
</questions>

Continue this process, generating new questions and recommendations based on the user's responses, until the user explicitly asks for a summary.

Remember to focus on clarity, relevance, and accuracy of results. Do not include any additional comments or explanations beyond the specified output format.

Analytical work should be done in the thinking block. The final output should consist solely of questions and recommendations and should not duplicate or repeat any work done in the prd_analysis section.

Output date from first round should be in format:
<prd_planning_output>
<questions_round_1>
[questions numbered]
</questions_round_1>

<recommendations_round_1>
[List your recommendations numbered]
</recommendations_round_1>
</prd_planning_output>

After receiving answers to first round of questions, generate secound round of questions and recomendations in following structure:
<prd_planning_output>

<questions_round_2>
[Your questions numbered]
</questions_round_2>

<recommendations_round_2>
[List your recommendations numbered]
</recommendations_round_2>
</prd_planning_output>



<questions_round_1>
1. How will users register for the system and receive their initial credentials if the transfer of temporary passwords from the administrator is out of scope?
   Recommendation: Implement a self-service registration flow where users can sign up using a corporate email address. The system can send a verification link to
   confirm their identity, after which they can set their own password.

2. The plan is to store private keys in a central database, encrypted with a user's PIN. This poses a significant security risk. Is this a mandatory requirement?
   Recommendation: Avoid storing private keys on the server. A more secure approach is to generate the key pair in the user's browser. The private key never
   leaves the user's machine, and only the public key and the signed certificate are stored on the server.

3. The main problem states "automatically renewing certificates," but the user MVP scope mentions "possibly replacing the current certificate(s)." Which of
  these reflects the actual MVP requirement?
  Recommendation: For the MVP, focus on a user-initiated renewal/replacement process. This simplifies the initial build while still providing the core
  functionality. Automatic renewal can be prioritized as a fast-follow feature post-MVP.

4. What specific parameters and data will the administrator be able to define when generating keys and certificates (e.g., key algorithm, key size, validity
      period, subject distinguished name)?
  Recommendation: Create a set of default certificate templates (e.g., "Standard User," "Device Certificate") with pre-filled, secure values. Allow
  administrators to override these specific fields only when necessary.

5. How will a user receive their generated private key and certificate?
  Recommendation: After generation, the system should provide the key and certificate to the user as a direct download from the browser, perhaps packaged in
  a standard format like PKCS#12.

6. What is the intended user authentication method for logging in, and how does it relate to the PIN?
  Recommendation: Use a standard password-based mechanism for user login (authentication). The PIN should be a separate secret, known only to the user, used
  exclusively for encrypting/decrypting their private keys if they are stored locally or in the database.

7. How will the first administrator account be created and provisioned?
  Recommendation: For the initial setup, create the first administrator account via a command-line interface (CLI) script that runs on the server. This is
  more secure than a public-facing "create admin" page.

8. Will the system act as its own self-signed Certificate Authority (CA), or will it integrate with an existing enterprise or public CA?
  Recommendation: For the MVP, the system should function as its own root CA. This simplifies the architecture and avoids dependencies on external services,
  which can be added later.

9. How will the success criterion of supporting 10 concurrent users be tested and measured?
  Recommendation: Define specific performance tests for key user flows (login, certificate generation). Use a load testing tool to simulate concurrent
  sessions and measure server response times and resource utilization to ensure they remain within acceptable limits.

10. What happens when a user's certificate expires? Is there a grace period, or is access immediately revoked?
  Recommendation: Implement a notification system. The system should email users, for example, 30, 15, and 5 days before a certificate expires, prompting
  them to log in and renew it. For the MVP, access can be blocked immediately upon expiration.
</questions_round_1>

<responses_round_1>

1. User will register with simple register form without verification link. I accept risk of fake email.

2. For now this simple encryption is enough. It may be changed in the future, but key must be backuped.

3. Process of renewing is initiated by user, but he gets a remainder when he's logged and his certificate is near or after expiration.

4. Administrator will be able to define validity period and hash algorithm. Key algorithm will be hardcoded for now.

5. User will receive PKCS12 with key and certificate.

6. User will login on simple web login page. PIN won't be stored in the database.

7. Database will be initialized with admin accounts. For now adding admin in database is the only way of adding administrator.

8. System will have its own root CA.

9. There will be integration tests written in RUST

10. There will be grace period. For now it will be set to 1/48 of certificate validity.

</responses_round_1>

<questions_round_2>
   1. When the user downloads the PKCS#12 file, what password is it protected with? Is it their main login password, their PIN, or a new, separately generated
      password?

   2. What are the specific, allowed options for the hash algorithm (e.g., SHA-256, SHA-512), and what are the minimum/maximum allowed values for the
      certificate validity period that an admin can set?

   3. What specific actions can a user perform during the grace period after their certificate has expired? Does the certificate remain functional for
      authentication, or does the grace period only allow them to log in to the portal to renew?

   4. How will the root CA's own private key be generated and secured? Who will have access to it, and what is the plan for its lifecycle management?

   5. Regarding the certificate renewal reminder, what should the user interface for this notification look like, and where should it be displayed within the
      application?

   6. What are the complexity requirements for the user's PIN (e.g., minimum length, character types)?

   7. What user information will be collected during registration (e.g., full name, email) to be potentially included in the certificate's subject fields?

   8. What are the critical user scenarios that the integration tests must successfully validate?

   9. Will all administrators have the same level of permissions, or are different roles (e.g., super-admin, read-only admin) envisioned?

   10. What is the system's behavior if a user repeatedly enters an incorrect PIN? Will there be a rate-limiting or account lockout mechanism to prevent
       brute-force attacks?
</questions_round_2>

<recommendations_round_2>
   1. Use the user's PIN as the password for the downloaded PKCS#12 file. This simplifies the number of secrets a user must manage. The application should
      prompt the user for their PIN only when an operation requiring key access (like this download) is initiated.

   2. Document the hardcoded key algorithm (e.g., RSA 4096). For the administrator's choice, provide a dropdown menu of modern, secure hash algorithms (e.g.,
      SHA-256, SHA-384, SHA-512) and enforce a sensible maximum certificate validity period (e.g., 397 days) to align with current best practices.

   3. The grace period should only allow the user to log into the web portal to renew their certificate. For all other external services, the certificate should
      be treated as invalid the moment it expires to maintain a clear security posture.

   4. The root CA private key should be generated and stored on a physically isolated, air-gapped machine. Access should be restricted to a minimum number of
      trusted personnel. This key should only be used to sign a small number of intermediate CA certificates, which will then handle the day-to-day signing of
      user certificates.

   5. Display a prominent, non-dismissible banner at the top of all authenticated pages when a user's certificate is within its renewal window (e.g., starting
      30 days before expiry) or in the grace period. This banner should clearly state the certificate's status and provide a direct link to the renewal page.

   6. Enforce a minimum PIN length of 6-8 digits. Provide clear instructions in the UI that this PIN protects their backed-up keys and should be treated with
      the same care as a primary password.

   7. During registration, collect the user's full name and email address. Use this information to pre-fill the corresponding fields for the certificate
      request, which an administrator can then review and approve.

   8. The integration tests must, at a minimum, cover the complete user lifecycle: user registration, login, setting the PIN, requesting and downloading a new
      certificate, and renewing an existing certificate. Admin-side validation of user data should also be included.

   9. For the MVP, a single administrator role with full permissions is acceptable. However, the system's architecture (e.g., the database schema) should be
      designed to support Role-Based Access Control (RBAC) from the outset to easily add more granular roles in the future.

   10. Implement a server-side rate-limiting mechanism. After 5 consecutive incorrect PIN entries, lock the ability to perform any cryptographic operations for
       that user for a progressively increasing duration (e.g., 1 minute, then 5 minutes, etc.). This is a critical defense against brute-force attacks on the
       encrypted keys.
</recommendations_round_2>

<answers_round_2>
1. with PIN

2. SHA-256, SHA-384 and SHA512

3. User logs with login and password, not certificate. Consequences of expired certificate are outside of this project.

4. CA's private key root password will be protected with password passed in environment variable. I accept risk of this operation on the first phase.

5. There shoud be eye-catching banner when user logs in.

6. It should have at least 8 characters

7. Administrator will fill DN of certificate each time he creates new one.

8. Integration test must cover register, logging in and concurrent checks for certificate validity.

9. There will be just one admin role.

10. User will enter PIN only in the register phase. When he'll receive pkcs12, he may try to break it. I accept the risk.
</answers_round_2>

  That's all. Now create summary of plenned PRD (Product Requirements Document) for MVP. Your task is:
  1. Summary history of the conversation, focusing on decisions connected with PRD planning
  2. Adjust recommendations with anserws in conversation history. Identify which recommendations are important basing on the discussion.
  3. Create detailed summary of discussion which contains:
   a) Main functional requirements of the project
   b) Key user stories and use cases
   c) Important criterias of success and measurement methods
   d) All not-solved issues and fields which needs additional explaining
  4. Format results in agree with format:

  <conversation_summary>
  <decisions>
  [Decisions taken by the user. Numbered]
  </decisions>

  <matched_recommendations>
  [List of most important recommendations matching the discussion. Numbered]
  </matched_recommendations>

  <prd_planning_summary>
  [Detailed summary of discussion with elements listed in step 3]
  </prd_planning_summary>

  <unresolved_issues>
  [All unresolved or needing additional explaining issues]
  </unresolved_issues>

  Result should be in markdown format and be clear, concise and have valuable informations needed in phase of creating PRD.
