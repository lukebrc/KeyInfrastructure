# KeyInfrastructure frontend

Web frontend for KeyInfrastructure system.

## Tech Stack

- [Astro](https://astro.build/) v5.13.7 - Modern web framework for building fast, content-focused websites
- [React](https://react.dev/) v19.1.1 - UI library for building interactive components
- [TypeScript](https://www.typescriptlang.org/) v5 - Type-safe JavaScript
- [Tailwind CSS](https://tailwindcss.com/) v4.1.13 - Utility-first CSS framework

## Prerequisites

- Node.js v22.14.0 (as specified in `.nvmrc`)
- npm (comes with Node.js)

## Getting Started

1. Clone the repository:

```bash
git clone git@github.com:lukebrc/KeyInfrastructure.git # or https://github.com/lukebrc/KeyInfrastructure
cd KeyInfrastructure/frontend
```

2. Install dependencies:

```bash
npm install
```

3. Run the development server:

```bash
npm run dev
```

4. Build for production:

```bash
npm run build
```

## Configuration

Before starting the development server, you need to configure the application.

1.  Create a `.env` file by copying the example file:

    ```bash
    cp .env.example .env
    ```

2.  The `.env` file contains the `BACKEND_URL` variable, which points to the backend server. By default, it is set to:

    ```
    BACKEND_URL=http://localhost:8080
    ```

    You can change this value if your backend is running on a different address or port.

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint issues
- `npm run format` - Format files with Prettier

## Project Structure

```md
.
├── src/
│ ├── components/ # UI components (Astro & React)
│ ├── layouts/ # Astro layouts
│ ├── lib/ # Helper functions and API logic
│ ├── middleware/ # Astro middleware
│ ├── pages/ # Astro pages
│ │ └── api/ # API endpoints
│ ├── styles/ # Global styles
│ └── types.ts # TypeScript types
├── public/ # Public assets
```

## AI Development Support

This project is configured with AI development tools to enhance the development experience, providing guidelines for:

- Project structure
- Coding practices
- Frontend development
- Styling with Tailwind
- Accessibility best practices
- Astro and React guidelines

### Cursor IDE

The project includes AI rules in `.cursor/rules/` directory that help Cursor IDE understand the project structure and provide better code suggestions, including frontend-specific guidelines for Astro, React, and Tailwind CSS.

## Features

- User registration with username and password
- User authentication via login
- Certificate download as password-protected PKCS#12 file
- Expiration notification banner with renewal prompt
- Administrator interface for certificate generation with configurable validity and hash algorithm (SHA-256/SHA-384/SHA-512)
- Self-hosted root CA with password-protected key via environment variable

## Contributing

Please follow the AI guidelines and coding practices defined in the AI configuration files when contributing to this project.
