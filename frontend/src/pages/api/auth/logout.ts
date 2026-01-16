import type { APIRoute } from "astro";
import { validateBackendUrl, handleApiError } from "@/lib/api-utils";

// Endpoint to logout user - clears the auth_token cookie
export const POST: APIRoute = async ({ request }) => {
  try {
    const backendUrl = validateBackendUrl();

    // Forward cookies from the request to the backend
    const cookieHeader = request.headers.get("cookie");

    const response = await fetch(`${backendUrl}/auth/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cookieHeader && { Cookie: cookieHeader }),
      },
      credentials: "include",
    });

    if (!response.ok) {
      return handleApiError(new Error("Failed to logout"), "Logout failed");
    }

    const responseData = await response.json();

    // Get the Set-Cookie header from backend response to forward it to the client
    // This is crucial - the backend sets a cookie with max_age=0 to delete it
    const setCookieHeader = response.headers.get("set-cookie");

    const headers = new Headers({
      "Content-Type": "application/json",
    });

    if (setCookieHeader) {
      headers.set("Set-Cookie", setCookieHeader);
    }

    return new Response(JSON.stringify(responseData), {
      status: 200,
      headers,
    });
  } catch (error) {
    return handleApiError(error, "Logout failed");
  }
};
