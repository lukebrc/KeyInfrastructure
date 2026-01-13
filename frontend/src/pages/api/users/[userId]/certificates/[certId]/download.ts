import type { APIRoute } from "astro";
import { validateBackendUrl, validateAuthToken } from "@/lib/api-utils";

export const GET: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);
    
    const userId = params.userId;
    const certificateId = params.certId;

    if (!userId) {
      return new Response(
        JSON.stringify({
          message: "User ID is required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

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
        }
      );
    }

    // Forward the GET request to the backend for public certificate download
    const response = await fetch(`${backendUrl}/users/${userId}/certificates/${certificateId}/download`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      credentials: "include",
    });

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
        }
      );
    }

    // Handle binary responses (downloads)
    const blob = await response.blob();
    const contentType = response.headers.get("content-type") || "application/x-x509-ca-cert";
    const contentDisposition = response.headers.get("content-disposition") || "attachment";

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
      }
    );
  }
};
