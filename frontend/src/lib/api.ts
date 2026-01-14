import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  User,
  Certificate,
  CreateCertificateRequest,
  RenewCertificateRequest,
  RevokeCertificateRequest,
  DownloadCertificateRequest,
  PaginationParams,
  PaginatedResponse,
  ApiError,
} from "@/types";

// All API calls go through proxy routes for security (backend URL is not exposed to client)
// Authentication is handled by proxy routes via httpOnly cookies

// Helper function to handle API errors
async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorMessage = "An error occurred";
    try {
      const errorData: ApiError = await response.json();
      errorMessage = errorData.message || errorMessage;
    } catch {
      // If response is not JSON, use status text
      errorMessage = response.statusText || errorMessage;
    }

    const error: ApiError = {
      message: errorMessage,
    };

    // Handle specific status codes
    if (response.status === 401) {
      // Clear token and redirect to login (but not if already on login page)
      if (typeof document !== "undefined") {
        document.cookie = "auth_token=; path=/; max-age=0";
        // Only redirect if not already on login or register page
        const currentPath = window.location.pathname;
        if (currentPath !== "/login" && currentPath !== "/register") {
          window.location.href = "/login?message=Session expired. Please log in again.";
        }
      }
    }

    throw error;
  }

  // Handle empty responses (204 No Content)
  if (response.status === 204 || response.headers.get("content-length") === "0") {
    return {} as T;
  }

  return response.json();
}

// API Client
export const api = {
  // Authentication
  async login(request: LoginRequest): Promise<LoginResponse> {
    // Use Astro API route as proxy to backend
    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // Include cookies
      body: JSON.stringify(request),
    });

    return handleResponse<LoginResponse>(response);
  },

  async register(request: RegisterRequest): Promise<User> {
    // Use Astro API route as proxy to backend
    const response = await fetch("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(request),
    });

    return handleResponse<User>(response);
  },

  async logout(): Promise<void> {
    try {
      // Try to call logout endpoint (if exists)
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
      }).catch(() => {
        // Ignore errors if endpoint doesn't exist
      });
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Clear token cookie
      if (typeof document !== "undefined") {
        document.cookie = "auth_token=; path=/; max-age=0";
      }
    }
  },

  // Users
  async getCurrentUser(): Promise<User> {
    // Use proxy API route
    const response = await fetch("/api/auth/me", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<User>(response);
  },

  async getUsers(): Promise<User[]> {
    // Use proxy API route
    const response = await fetch("/api/users", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<User[]>(response);
  },

  // Certificates
  async getCertificates(params?: PaginationParams & { status?: string }): Promise<PaginatedResponse<Certificate>> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.append("page", params.page.toString());
    if (params?.limit) queryParams.append("limit", params.limit.toString());
    if (params?.status) queryParams.append("status", params.status);
    if (params?.sort_by) queryParams.append("sort_by", params.sort_by);
    if (params?.order) queryParams.append("order", params.order);

    // Use proxy API route
    const url = `/api/certificates${queryParams.toString() ? `?${queryParams.toString()}` : ""}`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<PaginatedResponse<Certificate>>(response);
  },

  async getUserCertificates(userId: string, params?: PaginationParams & { status?: string }): Promise<PaginatedResponse<Certificate>> {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.append("page", params.page.toString());
    if (params?.limit) queryParams.append("limit", params.limit.toString());
    if (params?.status) queryParams.append("status", params.status);
    if (params?.sort_by) queryParams.append("sort_by", params.sort_by);
    if (params?.order) queryParams.append("order", params.order);

    // Use proxy API route for user-specific certificates
    const url = `/api/users/${userId}/certificates${queryParams.toString() ? `?${queryParams.toString()}` : ""}`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<PaginatedResponse<Certificate>>(response);
  },

  async getExpiringCertificates(days: number = 30): Promise<Certificate[]> {
    // Use proxy API route
    const response = await fetch(`/api/certificates/expiring?days=${days}`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<Certificate[]>(response);
  },

  async getPendingCertificates(): Promise<Certificate[]> {
    // Use proxy API route
    const response = await fetch("/api/certificates/pending", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<Certificate[]>(response);
  },

  async createCertificate(userId: string, request: CreateCertificateRequest): Promise<Certificate> {
    // Use proxy API route
    const response = await fetch(`/api/users/${userId}/certificates`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(request),
    });

    return handleResponse<Certificate>(response);
  },

  async renewCertificate(certificateId: string, request?: RenewCertificateRequest): Promise<Certificate> {
    // Use proxy API route
    const response = await fetch(`/api/certificates/${certificateId}/renew`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: request ? JSON.stringify(request) : undefined,
    });

    return handleResponse<Certificate>(response);
  },

  async revokeCertificate(certificateId: string, request?: RevokeCertificateRequest): Promise<Certificate> {
    // Use proxy API route
    const response = await fetch(`/api/certificates/${certificateId}/revoke`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: request ? JSON.stringify(request) : undefined,
    });

    return handleResponse<Certificate>(response);
  },

  async generateCertificate(certificateId: string): Promise<Certificate> {
    // Use proxy API route
    const response = await fetch(`/api/certificates/${certificateId}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    return handleResponse<Certificate>(response);
  },

  async downloadCertificate(certificateId: string, request: DownloadCertificateRequest): Promise<Blob> {
    // Use proxy API route
    const response = await fetch(`/api/certificates/${certificateId}/download`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      await handleResponse<ApiError>(response);
      throw new Error("Failed to download certificate");
    }

    return response.blob();
  },
};
