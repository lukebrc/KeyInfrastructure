# Application - KeyInfrastructure (MVP)

##  Main problem

Generating and automatically renewing certificates and keys for a network of nodes/devices (ie. PC, smartphone and other with web browser and network).

## Minimum Viable Product (MVP) Scope
- Administrator mode: specifying the data of generated keys/certificates and, if necessary, manually replacing them.
- User mode: logging in and registering to the system, and possibly replacing the current certificate(s).
- Administrator and user profile page.
- A database with a copy of the keys (encrypted with the user's password) and the user's current certificates.

## What is NOT in the MVP scope
- The method of storing private keys and certificates by the user.
- The transfer of temporary passwords from the administrator to the user.
- Communication between the client and the administrator.
- The situation where a user forgets their password.

##  Success criteria
- The system can handle 10 concurrent users, and a total of at least 100.
- For each user, we must support at least 10 keys/certificates.
- The user can log in.
