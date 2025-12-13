import type { APIContext } from "astro";

/**
 * Validates backend URL configuration and throws an error if not configured
 * @param context - The Astro API context (for logging)
 * @returns The backend URL
 * @throws Error with message when backend URL is not configured
 */
export function validateBackendUrl(context?: APIContext): string {
  const backendUrl = import.meta.env.BACKEND_URL;

  if (!backendUrl) {
    const errorMessage = "Backend URL not configured";
    console.error(errorMessage);
    throw new Error(errorMessage);
  }

  return backendUrl;
}

/**
 * Extracts and validates authentication token from request cookies
 * @param request - The incoming request
 * @returns The authentication token
 * @throws Error with message when token is not present
 */
export function validateAuthToken(request: Request): string {
  const cookieHeader = request.headers.get("cookie");
  const token = cookieHeader?.split("; ").find((c) => c.startsWith("auth_token="))?.split("=")[1];

  if (!token) {
    const errorMessage = "Not authenticated";
    console.error(errorMessage);
    throw new Error(errorMessage);
  }

  return token;
}

/**
 * Creates a standardized error response for API routes
 * @param message - The error message
 * @param status - The HTTP status code (default: 500)
 * @returns A Response object with JSON error
 */
export function createErrorResponse(message: string, status: number = 500): Response {
  return new Response(
    JSON.stringify({ message }),
    {
      status,
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
}

/**
 * Gets the current user ID from the JWT token by calling the backend verify endpoint
 * @param request - The incoming request
 * @returns The user ID
 * @throws Error with message when token is invalid or user ID cannot be obtained
 */
export async function getCurrentUserId(request: Request): Promise<string> {
  const backendUrl = validateBackendUrl();
  const token = validateAuthToken(request);

  // Call backend verify endpoint to get user ID from token
  const response = await fetch(`${backendUrl}/auth/verify`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to verify token");
  }

  const data = await response.json();
  
  if (!data.valid || !data.userId) {
    throw new Error("Invalid token or user ID not found");
  }

  return data.userId;
}

/**
 * Handles API route errors and returns appropriate responses
 * @param error - The caught error
 * @param context - Optional context for logging
 * @returns A Response object
 */
export function handleApiError(error: unknown, context?: string): Response {
  console.error(`${context ? context + " " : ""}API error:`, error);

  if (error instanceof Error) {
    // Handle our custom validation errors
    if (error.message === "Backend URL not configured") {
      return createErrorResponse(error.message, 500);
    }
    if (error.message === "Not authenticated") {
      return createErrorResponse(error.message, 401);
    }
  }

  // Generic error response
  return createErrorResponse("An error occurred. Please try again.", 500);
}
