import type { APIRoute } from "astro";
import {
  validateBackendUrl,
  validateAuthToken,
  getCurrentUserId,
} from "@/lib/api-utils";

export const DELETE: APIRoute = async ({ request, params }) => {
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

    const requestId = params.id;

    if (!requestId) {
      return new Response(
        JSON.stringify({
          message: "Certificate request ID is required",
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
      `${backendUrl}/users/${userId}/certificates/request/${requestId}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      },
    );

    if (!response.ok) {
      let errorMessage = "Failed to cancel certificate request";
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
    console.error("Cancel certificate request API error:", error);
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
