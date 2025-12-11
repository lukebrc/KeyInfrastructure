import type { APIRoute } from "astro";
import { validateBackendUrl, validateAuthToken, handleApiError, createErrorResponse } from "@/lib/api-utils";

export const GET: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);

    // Get userId from params
    const { userId } = params;

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

    // Get query params from request URL
    const url = new URL(request.url);
    const status = url.searchParams.get('status') || 'ALL';
    console.info(`Getting certificates for user ${userId}: with status ${status}`);

    //todo: add page and total parameters
    const fetchPendingCertificates = async (): Promise<any[]> => {
      console.debug(`Getting pending certificates for user ${userId}: ${backendUrl}/users/${userId}/certificates/pending`);

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

        throw new Error(errorMessage);
      }

      const pendingData = await response.json();
      console.info(`${pendingData.certificates.length} pending certificates for user ${userId}`);

      // Transform pending certificates to match list format
      return pendingData.certificates.map((cert: any) => ({
        id: cert.id,
        serial_number: null,
        dn: null,
        status: 'PENDING',
        expiration_date: null,
        renewed_count: 0,
        valid_days: cert.valid_days
      }));
    };

    let data;

    if (status === 'PENDING') {
      data = {
        certificates: [],
        total: 0,
        page: 1
      };
    } else {
      // Prepare query string - for 'ALL', remove status to get all statuses
      const fetchUrl = new URL(url);
      if (status === 'ALL') {
        fetchUrl.searchParams.delete('status');
      }
      const queryString = fetchUrl.search;

      console.info(`Getting certificates for user ${userId}: ${backendUrl}/users/${userId}/certificates/list${queryString}`);

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

      data = await response.json();
    }

    // Add pending certificates if status requires it
    if (status === 'PENDING' || status === 'ALL') {
      const pendingCertificates = await fetchPendingCertificates();
      console.debug(`Got ${data.certificates.length} normal and ${pendingCertificates.length} pending certificates`);
      data.certificates = [...data.certificates, ...pendingCertificates];
      data.total += pendingCertificates.length;
    }

    data.data = data.certificates;
    delete data.certificates;

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Get user certificates API error:", error);
    return new Response(
      JSON.stringify({
        message: error instanceof Error ? error.message : "An error occurred. Please try again.",
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

export const POST: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = validateBackendUrl();
    const token = validateAuthToken(request);

    // Get request body
    const body = await request.json();
    console.debug('Request body:', body);
    const { user_id: userId, validity_period_days, distinguished_name } = body;

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

    if (!validity_period_days || !distinguished_name?.cn) {
      return new Response(
        JSON.stringify({
          message: "Validity period and distinguished name with CN are required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Transform the request to match backend expectations
    // Backend expects: { dn: "CN=.../O=.../C=...", days_valid: number }
    const dnParts: string[] = [];
    if (distinguished_name.c) dnParts.push(`C=${distinguished_name.c}`);
    if (distinguished_name.st) dnParts.push(`ST=${distinguished_name.st}`);
    if (distinguished_name.l) dnParts.push(`L=${distinguished_name.l}`);
    if (distinguished_name.o) dnParts.push(`O=${distinguished_name.o}`);
    if (distinguished_name.ou) dnParts.push(`OU=${distinguished_name.ou}`);
    if (distinguished_name.cn) dnParts.push(`CN=${distinguished_name.cn}`);

    const dn = dnParts.join('/');
    const backendRequest = {
      dn,
      days_valid: validity_period_days,
    };

    console.debug('Transformed request for backend:', backendRequest);

    // Forward the request to the backend
    const response = await fetch(`${backendUrl}/users/${userId}/certificates/request`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(backendRequest),
    });

    if (!response.ok) {
      let errorMessage = "Failed to create certificate";
      try {
        const errorData = await response.json();
        errorMessage = errorData.message || errorMessage;
      } catch {
        errorMessage = response.statusText || errorMessage;
      }
      console.error("Error sending certificates request", errorMessage);

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

    return new Response(JSON.stringify(data), {
      status: 201,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Create certificate API error:", error);
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
