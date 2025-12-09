# KeyInfrastructure

This project is used for generating and automatically renewing certificates and keys for a network of nodes/devices (ie. PC, smartphone and other with web browser and network).

## Project Structure & Module Organization

Project consists of subprojects:
- **frontend** - web frontend concerning administrator and functionality.
- **backend** - REST webservice written in RUST, which serves requests from `web-admin` and `web-user` and optionaly other clients.
- **database** - all files and scripts concerning database.

