// User Role
export type UserRole = "USER" | "ADMIN";

// User DTOs
export interface User {
  id: string;
  username: string;
  role: UserRole;
  created_at: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
  role: UserRole;
}

// Certificate DTOs
export type CertificateStatus = "ACTIVE" | "REVOKED";

export interface Certificate {
  id: string;
  serial_number: string;
  user_id: string;
  username?: string; // Included when fetching certificates for admin
  dn: string;
  status: CertificateStatus;
  expiration_date: string;
  created_at: string;
  revoked_at?: string;
  revocation_reason?: string;
}

export interface CreateCertificateRequest {
  user_id: string;
  validity_period_days: number; // 1-3650
  hash_algorithm: "SHA-256" | "SHA-384" | "SHA-512";
  distinguished_name: DistinguishedName;
}

export interface DistinguishedName {
  cn: string; // Common Name - required
  ou?: string; // Organizational Unit - optional
  o?: string; // Organization - optional
  l?: string; // Locality - optional
  st?: string; // State/Province - optional
  c?: string; // Country - optional
}

export interface RenewCertificateRequest {
  validity_period_days?: number; // Optional, defaults to original validity period
}

export interface RevokeCertificateRequest {
  reason?: string; // Optional revocation reason
}

export interface DownloadCertificateRequest {
  password: string;
}

// API Error Response
export interface ApiError {
  message: string;
  code?: string;
  details?: Record<string, unknown>;
}

// Pagination
export interface PaginationParams {
  page?: number;
  limit?: number;
  sort_by?: string;
  order?: "asc" | "desc";
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}
