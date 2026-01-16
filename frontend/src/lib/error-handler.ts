import type { ApiError } from "@/types";
import { toast } from "sonner";

/**
 * Central error handler for API errors
 */
export class ErrorHandler {
  /**
   * Handle API error and show appropriate message to user
   */
  static handleError(
    error: unknown,
    defaultMessage = "An error occurred",
  ): void {
    const apiError = error as ApiError;

    // Extract error message
    let message = defaultMessage;
    if (apiError?.message) {
      message = apiError.message;
    } else if (error instanceof Error) {
      message = error.message;
    }

    // Handle specific error codes
    if (typeof message === "string") {
      console.info("handleError message:", message);
      if (message.includes("401") || message.includes("Unauthorized")) {
        // Redirect to login is handled by API client
        toast.error("Session expired. Please log in again.");
        return;
      }

      if (message.includes("403") || message.includes("Forbidden")) {
        toast.error(
          "Access denied. You don't have permission to perform this action.",
        );
        return;
      }

      if (message.includes("404") || message.includes("Not Found")) {
        toast.error("Resource not found.");
        return;
      }

      if (message.includes("409") || message.includes("Conflict")) {
        toast.error(message);
        return;
      }

      if (message.includes("400") || message.includes("Bad Request")) {
        toast.error(message);
        return;
      }

      if (
        message.includes("500") ||
        message.includes("Internal Server Error")
      ) {
        toast.error("Server error. Please try again later.");
        return;
      }

      if (message.includes("Network") || message.includes("Failed to fetch")) {
        toast.error("Network error. Please check your connection.");
        return;
      }
    }

    // Default error message
    toast.error(message);
  }

  /**
   * Show success message
   */
  static showSuccess(message: string): void {
    toast.success(message);
  }

  /**
   * Show info message
   */
  static showInfo(message: string): void {
    toast.info(message);
  }

  /**
   * Show warning message
   */
  static showWarning(message: string): void {
    toast.warning(message);
  }
}
