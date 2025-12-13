import type { APIRoute } from "astro";
import { validateBackendUrl, validateAuthToken, handleApiError, getCurrentUserId } from "@/lib/api-utils";

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

    // Forward the request to the backend
    const response = await fetch(`${backendUrl}/users/${userId}/certificates/pending`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    if (!response.ok) {
      let errorMessage = "Failed to get pending certificates";
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

    const data = await response.json();

    // Transform the backend response to match frontend Certificate format
    // Backend returns: { certificates: [{ id, valid_days, dn }] }
    // Frontend expects: [{ id, serial_number, user_id, dn, status, expiration_date, created_at }]
    const transformedCertificates = data.certificates.map((cert: any) => ({
      id: cert.id,
      serial_number: "PENDING", // Placeholder for pending certificates
      user_id: "", // Will be filled by current user context
      dn: cert.dn,
      status: "PENDING",
      expiration_date: new Date(Date.now() + cert.valid_days * 24 * 60 * 60 * 1000).toISOString(), // Calculate expiration
      created_at: new Date().toISOString(), // Placeholder
    }));

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
