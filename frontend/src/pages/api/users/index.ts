import type { APIRoute } from "astro";

export const GET: APIRoute = async ({ request, cookies }) => {
  // 1. Get the backend URL from environment variables
  const backendApiUrl = import.meta.env.BACKEND_API_URL;
  if (!backendApiUrl) {
    console.error("BACKEND_API_URL is not set in environment variables.");
    return new Response(JSON.stringify({ message: "Server configuration error." }), { status: 500 });
  }

  // 2. Get the authentication token from the httpOnly cookie
  const authToken = cookies.get("auth_token")?.value;

  // If there's no token, the user is not authenticated.
  // The backend will ultimately be responsible for enforcing this,
  // but we can short-circuit here if desired.
  if (!authToken) {
    return new Response(JSON.stringify({ message: "Unauthorized" }), { status: 401 });
  }

  try {
    // 3. Forward the request to the backend service
    const backendResponse = await fetch(`${backendApiUrl}/users`, {
      method: "GET",
      headers: {
        // Forward the authorization token to the backend
        "Authorization": `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
    });

    // 4. Return the response from the backend to the client
    // This streams the body and forwards status and headers.
    return new Response(backendResponse.body, {
      status: backendResponse.status,
      statusText: backendResponse.statusText,
      headers: backendResponse.headers,
    });
  } catch (error) {
    console.error("Error proxying /api/users request:", error);
    return new Response(JSON.stringify({ message: "An internal server error occurred." }), { status: 500 });
  }
};