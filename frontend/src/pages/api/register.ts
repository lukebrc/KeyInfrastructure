import type { APIRoute } from "astro";

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { username, password, pin } = body;

    if (!username || !password || !pin) {
      return new Response(
        JSON.stringify({
          message: "Username, password, and PIN are required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Validate PIN length (minimum 8 characters according to plan)
    if (pin.length < 8) {
      return new Response(
        JSON.stringify({
          message: "PIN must be at least 8 characters long",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Validate password length (minimum 8 characters)
    if (password.length < 8) {
      return new Response(
        JSON.stringify({
          message: "Password must be at least 8 characters long",
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
    // Note: Backend currently uses /register, but plan specifies /users
    // This will be updated when backend implements the full API
    const response = await fetch(`${backendUrl}/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, pin }),
    });

    if (!response.ok) {
      let errorMessage = "Registration failed";
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

    // Parse response (expecting User object)
    const data = await response.json();

    return new Response(JSON.stringify(data), {
      status: 201,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Register API error:", error);
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

