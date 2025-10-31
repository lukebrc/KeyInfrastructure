# Authentication API Tests

This directory contains curl-based integration tests for the authentication endpoints (`/login` and `/register`).

## Prerequisites

- The backend server must be running on `http://localhost:8080` (or provide a different URL)
- curl must be installed
- The database must be set up and accessible

## Test Scripts

### `test_register.sh`
Tests the `/register` endpoint with the following scenarios:
- Successful registration (201 Created)
- Attempt to register existing user (409 Conflict)
- Missing required fields (400/422 Bad Request)
- Invalid JSON (400 Bad Request)
- Empty fields

### `test_login.sh`
Tests the `/login` endpoint with the following scenarios:
- Successful login (200 OK)
- Wrong password (401 Unauthorized)
- Non-existent user (401 Unauthorized)
- Missing required fields (400/422 Bad Request)
- Invalid JSON (400 Bad Request)
- Empty fields

**Note**: `test_login.sh` assumes that a test user exists. Run `test_register.sh` first to create the test user.

### `test_all.sh`
Runs both register and login tests in sequence.

## Usage

### Make scripts executable:
```bash
chmod +x test_register.sh test_login.sh test_all.sh
```

### Run individual test suites:
```bash
# Test register endpoint
./test_register.sh

# Test login endpoint (requires test user to exist)
./test_login.sh

# Or with custom base URL
./test_register.sh http://localhost:3000
./test_login.sh http://localhost:3000
```

### Run all tests:
```bash
./test_all.sh

# Or with custom base URL
./test_all.sh http://localhost:3000
```

## Expected Behavior

The scripts will:
- Display colored output (green for pass, red for fail, yellow for test info)
- Show HTTP status codes and response bodies
- Validate that responses match expected behavior based on the API implementation

## Cleaning Up

After running tests, you may want to remove the test user from the database:

```sql
DELETE FROM users WHERE username = 'testuser';
```

Or run the tests in a test database environment to avoid polluting your development database.

