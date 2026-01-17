import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AlertCircle } from "lucide-react";

interface NetworkErrorFallbackProps {
  onRetry?: () => void;
  message?: string;
}

export const NetworkErrorFallback: React.FC<NetworkErrorFallbackProps> = ({
  onRetry,
  message = "Network error. Please check your connection and try again.",
}) => {
  return (
    <div className="flex min-h-[400px] items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertCircle className="size-5 text-destructive" />
            <CardTitle>Connection Error</CardTitle>
          </div>
          <CardDescription>{message}</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            We couldn&apos;t connect to the server. Please check your internet
            connection and try again.
          </p>
        </CardContent>
        {onRetry && (
          <CardFooter>
            <Button onClick={onRetry} className="w-full">
              Try Again
            </Button>
          </CardFooter>
        )}
      </Card>
    </div>
  );
};
