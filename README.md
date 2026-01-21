# KeyInfrastructure

This project is used for generating and automatically renewing certificates and keys for a network of nodes/devices (ie. PC, smartphone and other with web browser and network).

## Project Structure & Module Organization

Project consists of subprojects:
- **frontend** - web frontend concerning administrator and functionality.
- **backend** - REST webservice written in RUST, which serves requests from `web-admin` and `web-user` and optionaly other clients.
- **database** - all files and scripts concerning database.

## First run

1. Install docker and rust (with cargo) in version at least 1.70
2. Set environment variables (if not set, default ones will be used):
* `CA_PASSWORD` - password for openssl CA private key
* `JWT_SECRET` - password for JWT (Json-Web-Token) mechanism
* `DATABASE_URL` - url and password for  database connection
3. Execute `./prepare_environment.sh`
4. Start application with `docker-compose up` (or `docker compose up`)
5. Open application in web browser in http://localhost:3000
6. Register new user or login to default admin user (user: admin, password: admin123)
