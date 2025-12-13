import type { APIRoute } from "astro";
import { validateBackendUrl, validateAuthToken, handleApiError, getCurrentUserId, fetchPendingCertificatesFromBackend } from "@/lib/api-utils";

export const GET: APIRoute = async ({ request }) => {
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
          message: error instanceof Error ? error.message : "Failed to get user ID",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    console.info("Getting pending certificates");

    const pendingResult = await fetchPendingCertificatesFromBackend(backendUrl, token, userId);
    if (pendingResult.error) {
      return new Response(JSON.stringify({ message: pendingResult.error.message }), {
        status: pendingResult.error.status,
        headers: { "Content-Type": "application/json" },
      });
    }

    // The helper already returns transformed pending certificate objects with user_id filled
    const transformedCertificates = pendingResult.data;

    return new Response(JSON.stringify(transformedCertificates), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Get pending certificates API error:", error);
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
