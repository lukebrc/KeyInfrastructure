import type { APIRoute } from "astro";

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
    const { user_id: userId, ...certificateData } = body;

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

    // Forward the request to the backend
    const response = await fetch(`${backendUrl}/users/${userId}/certificates/request`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(certificateData),
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
