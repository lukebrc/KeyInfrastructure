import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import type { LoginRequest, ApiError } from "@/types";

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState<string>("/dashboard");

  // Check for query params (redirect, message) on component mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const redirect = params.get("redirect");
    const message = params.get("message");

    if (redirect) {
      setRedirectUrl(redirect);
    }

    if (message) {
      setError(decodeURIComponent(message));
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    console.info("LoginForm.handleLogin", e);
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

      console.info(
        "Login response",
        response.user.username,
        response.user.role,
      );
      // Token should be set in httpOnly cookie by backend
      // Redirect based on role or redirect URL
      if (redirectUrl) {
        window.location.href = redirectUrl;
      } else if (response.user.role === "ADMIN") {
        window.location.href = redirectUrl.startsWith("/admin")
          ? redirectUrl
          : "/admin/dashboard";
      } else {
        window.location.href = "/dashboard";
      }
    } catch (err) {
      console.error("Login failed", err);

      const apiError = err as ApiError;
      // Handle 401 - invalid credentials
      if (
        apiError.message.includes("401") ||
        apiError.message.includes("Unauthorized")
      ) {
        setError("Invalid username or password");
      } else {
        setError(apiError.message || "An error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4 bg-gradient-to-br from-sky-50 via-blue-50 to-indigo-100">
      <Card className="w-full max-w-md border-sky-100 shadow-lg">
        <CardHeader>
          <CardTitle className="text-2xl">Login</CardTitle>
          <CardDescription>
            Enter your credentials to access your account
          </CardDescription>
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
            Don&apos;t have an account?{" "}
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
