interface ImportMetaEnv {
  readonly BACKEND_URL: string;
  // more env variables...
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

// Astro middleware context
declare namespace App {
  interface Locals {
    user?: {
      id: string;
      role: string;
      token: string;
    };
  }
}
