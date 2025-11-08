import React, { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import type { LoginRequest, ApiError } from "@/types";

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);
  const hasCheckedAuth = useRef(false);

  // Check if user is already logged in and redirect
  // Also check for query params (redirect, message)
  // Only check once when component mounts
  useEffect(() => {
    // Prevent multiple checks - this ensures the check only runs once
    if (hasCheckedAuth.current) {
      return;
    }
    hasCheckedAuth.current = true;

    // Check query params first (synchronous, no API call)
    const params = new URLSearchParams(window.location.search);
    const redirect = params.get("redirect");
    const message = params.get("message");
    
    if (redirect) {
      setRedirectUrl(redirect);
    }
    
    if (message) {
      setError(decodeURIComponent(message));
    }

    // Check authentication status (only once)
    const checkAuth = async () => {
      try {
        const user = await api.getCurrentUser();
        // User is logged in, redirect based on role
        if (user.role === "ADMIN") {
          window.location.href = "/admin/dashboard";
        } else {
          window.location.href = "/dashboard";
        }
      } catch (error) {
        // User is not logged in - this is expected on login page
        // Don't do anything, just let the user see the login form
      }
    };
    
    checkAuth();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty dependency array ensures this runs only once on mount

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    // Client-side validation
    if (!username || !password) {
      setError("Username and password are required");
      setLoading(false);
      return;
    }

    try {
      const request: LoginRequest = { username, password };
      const response = await api.login(request);

      // Token should be set in httpOnly cookie by backend
      // Redirect based on role or redirect URL
      if (redirectUrl) {
        window.location.href = redirectUrl;
      } else if (response.role === "ADMIN") {
        window.location.href = "/admin/dashboard";
      } else {
        window.location.href = "/dashboard";
      }
    } catch (err) {
      const apiError = err as ApiError;
      // Handle 401 - invalid credentials
      if (apiError.message.includes("401") || apiError.message.includes("Unauthorized")) {
        setError("Invalid username or password");
      } else {
        setError(apiError.message || "An error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">Login</CardTitle>
          <CardDescription>Enter your credentials to access your account</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <label htmlFor="username" className="text-sm font-medium">
                Username
              </label>
              <Input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                disabled={loading}
                aria-invalid={error ? "true" : "false"}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium">
                Password
              </label>
              <Input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                disabled={loading}
                aria-invalid={error ? "true" : "false"}
              />
            </div>
            <Button type="submit" disabled={loading} className="w-full">
              {loading ? "Logging in..." : "Login"}
            </Button>
          </form>
        </CardContent>
        <CardFooter>
          <p className="text-center text-sm text-muted-foreground w-full">
            Don't have an account?{" "}
            <a href="/register" className="text-primary hover:underline">
              Register here
            </a>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
};

export default LoginForm;