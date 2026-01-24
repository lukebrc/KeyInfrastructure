import React, { useState } from "react";
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
import type { RegisterRequest, ApiError, UserRole } from "@/types";

const RegisterForm: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [registeringAs, setRegisteringAs] = useState<UserRole | null>(null);

  const validateForm = (): boolean => {
    if (!username || !password) {
      setError("Username and password are required");
      return false;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters long");
      return false;
    }

    return true;
  };

  const handleRegister = async (
    e: React.FormEvent,
    role: UserRole = "USER",
  ) => {
    e.preventDefault();
    setLoading(true);
    setRegisteringAs(role);
    setError(null);
    setSuccess(false);

    // Client-side validation
    if (!validateForm()) {
      setLoading(false);
      setRegisteringAs(null);
      return;
    }

    try {
      const request: RegisterRequest = { username, password, role };
      await api.register(request);

      // After successful registration, automatically log in
      setSuccess(true);
      try {
        await api.login({ username, password });
        // Token should be set in httpOnly cookie by backend
        // Redirect to dashboard
        window.location.href = "/dashboard";
      } catch {
        // If auto-login fails, redirect to login page
        setError(
          "Registration successful, but automatic login failed. Please log in manually.",
        );
        setTimeout(() => {
          window.location.href = "/login";
        }, 2000);
      }
    } catch (err) {
      const apiError = err as ApiError;
      // Handle specific error codes
      if (
        apiError.message.includes("409") ||
        apiError.message.includes("Conflict") ||
        apiError.message.includes("already exists")
      ) {
        setError(
          "Username already exists. Please choose a different username.",
        );
      } else if (
        apiError.message.includes("400") ||
        apiError.message.includes("Bad Request")
      ) {
        setError(apiError.message || "Invalid data. Please check your input.");
      } else {
        setError(apiError.message || "An error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
      setRegisteringAs(null);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4 bg-gradient-to-br from-sky-50 via-blue-50 to-indigo-100">
      <Card className="w-full max-w-md border-sky-100 shadow-lg">
        <CardHeader>
          <CardTitle className="text-2xl">Register</CardTitle>
          <CardDescription>Create a new account to get started</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {success && (
              <Alert>
                <AlertDescription>
                  Registration successful! Logging you in...
                </AlertDescription>
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
                aria-describedby="username-hint"
              />
              <p id="username-hint" className="text-xs text-muted-foreground">
                Username must be unique
              </p>
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
                aria-describedby="password-hint"
                minLength={8}
              />
              <p id="password-hint" className="text-xs text-muted-foreground">
                Password must be at least 8 characters long
              </p>
            </div>

            <div className="flex gap-2">
              <Button
                type="button"
                disabled={loading}
                className="flex-1"
                onClick={(e) => handleRegister(e, "USER")}
              >
                {loading && registeringAs === "USER"
                  ? "Registering..."
                  : "Register"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={loading}
                className="flex-1"
                onClick={(e) => handleRegister(e, "ADMIN")}
              >
                {loading && registeringAs === "ADMIN"
                  ? "Registering..."
                  : "Register as Admin"}
              </Button>
            </div>
          </form>
        </CardContent>
        <CardFooter>
          <p className="text-center text-sm text-muted-foreground w-full">
            Already have an account?{" "}
            <a href="/login" className="text-primary hover:underline">
              Login here
            </a>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
};

export default RegisterForm;
