import type { APIRoute } from "astro";

export const GET: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = import.meta.env.BACKEND_URL;

    if (!backendUrl) {
      return new Response(
        JSON.stringify({
          message: "Backend URL not configured",
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Get auth token from cookie
    const cookieHeader = request.headers.get("cookie");
    const token = cookieHeader?.split("; ").find((c) => c.startsWith("auth_token="))?.split("=")[1];

    if (!token) {
      return new Response(
        JSON.stringify({
          message: "Not authenticated",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

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
    const queryString = url.search;

    console.info(`Getting certificates for user ${userId}: ${backendUrl}/users/${userId}/certificates/list${queryString}`);

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

    const data = await response.json();

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

export const POST: APIRoute = async ({ request, params }) => {
  try {
    const backendUrl = import.meta.env.BACKEND_URL;

    if (!backendUrl) {
      return new Response(
        JSON.stringify({
          message: "Backend URL not configured",
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Get auth token from cookie
    const cookieHeader = request.headers.get("cookie");
    const token = cookieHeader?.split("; ").find((c) => c.startsWith("auth_token="))?.split("=")[1];

    if (!token) {
      return new Response(
        JSON.stringify({
          message: "Not authenticated",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

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
