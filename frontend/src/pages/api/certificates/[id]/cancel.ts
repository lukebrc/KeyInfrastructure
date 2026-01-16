import type { APIRoute } from "astro";
import {
  validateBackendUrl,
  validateAuthToken,
  handleApiError,
  createErrorResponse,
  getCurrentUserId,
} from "@/lib/api-utils";

export const PUT: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);

    let userId: string;
    try {
      userId = await getCurrentUserId(request);
    } catch (error) {
      console.error("Failed to get user ID:", error);
      return new Response(
        JSON.stringify({
          message:
            error instanceof Error ? error.message : "Failed to get user ID",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    }

    const certificateId = params.id;

    if (!certificateId) {
      return new Response(
        JSON.stringify({
          message: "Certificate ID is required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    }

    // Forward the request to the backend
    const response = await fetch(
      `${backendUrl}/users/${userId}/certificates/${certificateId}/cancel`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      },
    );

    if (!response.ok) {
      let errorMessage = "Failed to cancel certificate";
      try {
        const errorData = await response.json();
        errorMessage = errorData.message || errorMessage;
      } catch {
        errorMessage = response.statusText || errorMessage;
      }

      return new Response(
        JSON.stringify({
          message: errorMessage,
        }),
        {
          status: response.status,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    }

    const data = await response.json().catch(async () => {
      return {};
    });

    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Cancel certificate API error:", error);
    return new Response(
      JSON.stringify({
        message: "An error occurred. Please try again.",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
        },
      },
    );
  }
};