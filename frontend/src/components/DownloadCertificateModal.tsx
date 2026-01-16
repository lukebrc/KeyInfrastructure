import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { Certificate } from "@/types";
import { Download, Loader2 } from "lucide-react";

interface DownloadCertificateModalProps {
  certificate: Certificate | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const DownloadCertificateModal: React.FC<
  DownloadCertificateModalProps
> = ({ certificate, open, onOpenChange }) => {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async () => {
    if (!certificate) return;
    console.info("DownloadCertificateModal.handleDownload", certificate);

    setLoading(true);
    setError(null);

    // Validate password
    if (password.length < 8) {
      setError("Password must be at least 8 characters long");
      setLoading(false);
      return;
    }

    try {
      const blob = await api.downloadCertificate(certificate.id, {
        password,
        user_id: certificate.user_id,
      });

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `certificate-${certificate.serial_number}.p12`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      ErrorHandler.showSuccess("Certificate downloaded successfully");
      onOpenChange(false);
      setPassword("");
    } catch (err) {
      const apiError = err as { message?: string };
      if (
        apiError.message?.includes("password") ||
        apiError.message?.includes("400")
      ) {
        setError("Invalid password. Please try again.");
      } else {
        ErrorHandler.handleError(err, "Failed to download certificate");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setPassword("");
    setError(null);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Download Certificate</DialogTitle>
          <DialogDescription>
            Enter your password to download the certificate file (PKCS#12
            format). The password must be at least 8 characters long.
          </DialogDescription>
        </DialogHeader>
        {certificate && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium">Serial Number:</p>
              <p className="text-sm text-muted-foreground">
                {certificate.serial_number}
              </p>
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
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
                disabled={loading}
                minLength={8}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !loading && password.length >= 8) {
                    handleDownload();
                  }
                }}
              />
              <p className="text-xs text-muted-foreground">
                Password must be at least 8 characters long
              </p>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            onClick={handleDownload}
            disabled={loading || password.length < 8}
          >
            {loading ? (
              <>
                <Loader2 className="size-4 mr-2 animate-spin" />
                Downloading...
              </>
            ) : (
              <>
                <Download className="size-4 mr-2" />
                Download
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
