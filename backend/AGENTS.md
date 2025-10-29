# Repository Guidelines

## Build, Test, and Development Commands
Run `cargo build` before contributing. Use `cargo test` to execute the Rust test suite.

### Linting and Formatting
```bash
# Format code
cargo fmt

# Lint with clippy (critical issues only)
cargo clippy --lib --bins -- -D "clippy::correctness" -D "clippy::suspicious" -D "clippy::perf" -W "clippy::style" -W "clippy::complexity"
```

## Coding Style & Naming Conventions

### General Principles
- **Modular Design**: Single responsibility per module
- **Async/Await**: Use throughout for database operations
- **Error Handling**: Use `thiserror` for custom error types with user-friendly messages
- **User Interaction**: MANDATORY - Use `inquire` crate for ALL user prompts (Select, Confirm, Text, MultiSelect)

### Naming Conventions
- **Structs/Enums**: PascalCase (e.g., `Database`, `Command`, `Config`)
- **Functions/Methods**: snake_case (e.g., `connect_to_database`, `parse_command`)
- **Variables**: snake_case (e.g., `connection_url`, `config_path`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `DEFAULT_TIMEOUT`)
- **Modules**: snake_case (e.g., `database`, `commands`, `config`)

### Imports and Dependencies
- Group imports: std, external crates, local modules
- Use explicit imports, avoid glob imports (`use::*`)
- Keep dependency features minimal and explicit
- **CRITICAL**: Never remove the `strum` crate dependency (essential for enum iteration)

