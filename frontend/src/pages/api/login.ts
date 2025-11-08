import type { APIRoute } from "astro";

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return new Response(
        JSON.stringify({
          message: "Username and password are required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

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

    // Forward the request to the backend
    // Note: Backend currently uses /login, but plan specifies /auth/login
    // This will be updated when backend implements JWT tokens
    const response = await fetch(`${backendUrl}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      let errorMessage = "Login failed";
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

    // Parse response (expecting LoginResponse with token and user)
    const data = await response.json();

    // Extract cookies from response and forward them
    const setCookieHeaders = response.headers.get("set-cookie");
    const headers = new Headers({
      "Content-Type": "application/json",
    });

    if (setCookieHeaders) {
      headers.set("set-cookie", setCookieHeaders);
    }

    return new Response(
      JSON.stringify({
        token: data.token,
        user: data.user,
        role: data.role || data.user?.role || "USER",
      }),
      {
        status: 200,
        headers,
      }
    );
  } catch (error) {
    console.error("Login API error:", error);
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
