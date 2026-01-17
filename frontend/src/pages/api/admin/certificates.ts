import type { APIRoute } from "astro";
import { validateBackendUrl, validateAuthToken } from "@/lib/api-utils";

interface BackendCertificate {
  id?: string | number;
  serialNumber?: string;
  serial_number?: string;
  userId?: string;
  user_id?: string;
  dn?: string;
  status?: string;
  expirationDate?: string;
  expiration_date?: string;
  createdAt?: string;
  created_at?: string;
  renewedCount?: number;
  renewed_count?: number;
}

/**
 * Admin-only endpoint to list all certificates across all users.
 * Supports filtering by status (e.g., REVOKED, ACTIVE, EXPIRED).
 */
export const GET: APIRoute = async ({ request }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);

    // Get query params from request URL
    const url = new URL(request.url);
    const queryString = url.search;

    console.info(
      `Admin: Getting all certificates: ${backendUrl}/certificates/list${queryString}`,
    );

    // Forward the request to the backend admin endpoint
    const response = await fetch(
      `${backendUrl}/certificates/list${queryString}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        credentials: "include",
      },
    );

    if (!response.ok) {
      let errorMessage = "Failed to get certificates";
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

    const backendData = await response.json();
    const limit = parseInt(url.searchParams.get("limit") || "10", 10);

    // Transform certificates to match frontend Certificate type
    const transformedCertificates = (
      (backendData.certificates || []) as BackendCertificate[]
    ).map((cert) => ({
      id: cert.id || String(cert.id),
      serial_number: cert.serialNumber || cert.serial_number || "",
      user_id: cert.userId || cert.user_id || "",
      dn: cert.dn || "",
      status: cert.status || "ACTIVE",
      expiration_date:
        cert.expirationDate || cert.expiration_date || new Date().toISOString(),
      created_at:
        cert.createdAt ||
        cert.created_at ||
        cert.expirationDate ||
        cert.expiration_date ||
        new Date().toISOString(),
      renewed_count: cert.renewedCount || cert.renewed_count || 0,
    }));

    const totalPages = Math.ceil((backendData.total || 0) / limit);

    const transformedData = {
      data: transformedCertificates,
      total: backendData.total || 0,
      page: backendData.page || 1,
      limit: limit,
      total_pages: totalPages,
    };

    return new Response(JSON.stringify(transformedData), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Admin get certificates API error:", error);

    if (error instanceof Error && error.message === "Not authenticated") {
      return new Response(
        JSON.stringify({
          message: "Not authenticated",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    }

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
