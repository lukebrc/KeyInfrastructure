import type { APIRoute } from "astro";
import {
  validateBackendUrl,
  validateAuthToken,
  handleApiError,
  createErrorResponse,
  getCurrentUserId,
} from "@/lib/api-utils";

export const POST: APIRoute = async ({ request, params }) => {
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

    // Get request body
    const body = await request.json();

    // Use certificate owner's user_id if provided (for admin downloads), otherwise use current user's ID
    const certificateOwnerId = body.user_id || userId;

    // Forward the request to the backend PKCS12 endpoint
    const response = await fetch(
      `${backendUrl}/users/${certificateOwnerId}/certificates/${certificateId}/pkcs12`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({ password: body.password }),
      },
    );

    if (!response.ok) {
      let errorMessage = "Failed to download certificate";
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

    // Handle binary responses (downloads)
    const blob = await response.blob();
    const contentType =
      response.headers.get("content-type") || "application/octet-stream";
    const contentDisposition =
      response.headers.get("content-disposition") || "attachment";

    return new Response(blob, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": contentDisposition,
      },
    });
  } catch (error) {
    console.error("Download certificate API error:", error);
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
