import type { APIRoute } from "astro";
import {
  validateBackendUrl,
  validateAuthToken,
  handleApiError,
  createErrorResponse,
} from "@/lib/api-utils";

// Endpoint to fetch current user details
export const GET: APIRoute = async ({ request }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);

    const response = await fetch(`${backendUrl}/auth/verify`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      return createErrorResponse(
        "Failed to fetch user details",
        response.status,
      );
    }

    const data = await response.json();
    console.debug("Fetched user details:", data);
    const user = {
      id: data.userId,
      username: data.username,
      role: data.role,
    };

    return new Response(JSON.stringify(user), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    return handleApiError(error);
  }
};
