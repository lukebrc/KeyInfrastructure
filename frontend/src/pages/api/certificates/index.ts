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

    // Get query params from request URL
    const url = new URL(request.url);
    const queryString = url.search;

    const statusFilter = url.searchParams.get("status");
    const limit = parseInt(url.searchParams.get("limit") || "10", 10);
    // Helper that fetches pending certificates (shared impl) 
    const fetchPendingCertificates = async () => fetchPendingCertificatesFromBackend(backendUrl, token, userId);

    // If status is PENDING, do not call the backend /list endpoint; fetch pending directly
    if (statusFilter === "PENDING") {
      console.info(`Getting pending certificates for user ${userId}`);
      const pendingResult = await fetchPendingCertificates();
      if (pendingResult.error) {
        return new Response(JSON.stringify({ message: pendingResult.error.message }), {
          status: pendingResult.error.status,
          headers: { "Content-Type": "application/json" },
        });
      }
      const transformedCertificates = pendingResult.data;
      const backendData = { total: transformedCertificates.length, page: 1 };
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
        headers: { "Content-Type": "application/json" },
      });
    }

    console.info(`Getting certificates: ${backendUrl}/users/${userId}/certificates/list${queryString}`);

    // Forward the request to the backend
    const response = await fetch(`${backendUrl}/users/${userId}/certificates/list${queryString}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

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
        }
      );
    }

    // fetchPendingCertificates will be delegated to shared helper via wrapper above

    let backendData: any;
    let transformedCertificates: any[] = [];

    // Fetch active certificates (status != PENDING)
    backendData = await response.json();

      // Transform certificates to match frontend Certificate type
      // Backend uses camelCase serialization (from serde rename_all = "camelCase")
      transformedCertificates = (backendData.certificates || []).map((cert: any) => ({
        id: cert.id || String(cert.id),
        serial_number: cert.serialNumber || cert.serial_number || "",
        // Preserve backend's userId if present, otherwise use userId from path
        user_id: cert.userId || cert.user_id || userId,
        dn: cert.dn || "",
        status: cert.status || "ACTIVE",
        expiration_date: cert.expirationDate || cert.expiration_date || new Date().toISOString(),
        created_at: cert.createdAt || cert.created_at || cert.expirationDate || cert.expiration_date || new Date().toISOString(),
        renewed_count: cert.renewedCount || cert.renewed_count || 0,
      }));

      // If status is 'ALL' or not specified, also include pending certificates
      if (!statusFilter || statusFilter === "ALL") {
        const pendingResult = await fetchPendingCertificates();
        const pendingCertificates = pendingResult.data || [];
        transformedCertificates = [...transformedCertificates, ...pendingCertificates];
        if (!pendingResult.error) {
          backendData.total = (backendData.total || 0) + pendingCertificates.length;
        }
      }
    

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
    console.error("Get certificates API error:", error);
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
