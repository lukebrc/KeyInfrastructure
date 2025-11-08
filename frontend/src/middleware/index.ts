import type { MiddlewareHandler } from "astro";

// Public routes that don't require authentication
const PUBLIC_ROUTES = ["/", "/login", "/register"];

// Helper function to get auth token from cookie
function getAuthToken(request: Request): string | null {
  const cookieHeader = request.headers.get("cookie");
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split("; ").reduce((acc, cookie) => {
    const [key, value] = cookie.split("=");
    acc[key] = value;
    return acc;
  }, {} as Record<string, string>);

  return cookies["auth_token"] || null;
}

// Helper function to verify token with backend
async function verifyToken(token: string): Promise<{ valid: boolean; role?: string; userId?: string }> {
  try {
    const backendUrl = import.meta.env.BACKEND_URL;
    if (!backendUrl) {
      return { valid: false };
    }

    const response = await fetch(`${backendUrl}/auth/verify`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      return { valid: false };
    }

    const data = await response.json();
    return {
      valid: true,
      role: data.role || data.user?.role || "USER",
      userId: data.userId || data.user?.id,
    };
  } catch {
    return { valid: false };
  }
}

export const onRequest: MiddlewareHandler = async (context, next) => {
  const { url, request } = context;
  const pathname = new URL(url).pathname;

  // Allow public routes and API routes
  if (PUBLIC_ROUTES.some((route) => pathname === route) || pathname.startsWith("/api/")) {
    return next();
  }

  // Check if route requires authentication
  const token = getAuthToken(request);

  if (!token) {
    // No token, redirect to login
    if (pathname.startsWith("/admin") || pathname.startsWith("/dashboard")) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: `/login?redirect=${encodeURIComponent(pathname)}&message=${encodeURIComponent("Session expired. Please log in again.")}`,
        },
      });
    }
    return next();
  }

  // Verify token with backend
  const verification = await verifyToken(token);

  if (!verification.valid) {
    // Invalid token, redirect to login
    if (pathname.startsWith("/admin") || pathname.startsWith("/dashboard")) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: `/login?redirect=${encodeURIComponent(pathname)}&message=${encodeURIComponent("Session expired. Please log in again.")}`,
        },
      });
    }
    return next();
  }

  // Check admin routes
  if (pathname.startsWith("/admin")) {
    if (verification.role !== "ADMIN") {
      // User is not admin, redirect to dashboard
      return new Response(null, {
        status: 302,
        headers: {
          Location: `/dashboard?message=${encodeURIComponent("Access denied. Administrator privileges required.")}`,
        },
      });
    }
  }

  // Store user info in context for use in pages
  context.locals.user = {
    id: verification.userId || "",
    role: verification.role || "USER",
    token,
  };

  return next();
};

