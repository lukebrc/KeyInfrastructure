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

export const DownloadCertificateModal: React.FC<DownloadCertificateModalProps> = ({
  certificate,
  open,
  onOpenChange,
}) => {
  const [pin, setPin] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async () => {
    if (!certificate) return;

    setLoading(true);
    setError(null);

    // Validate PIN
    if (pin.length < 8) {
      setError("PIN must be at least 8 characters long");
      setLoading(false);
      return;
    }

    try {
      const blob = await api.downloadCertificate(certificate.id, { pin });

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
      setPin("");
    } catch (err) {
      const apiError = err as { message?: string };
      if (apiError.message?.includes("PIN") || apiError.message?.includes("400")) {
        setError("Invalid PIN. Please try again.");
      } else {
        ErrorHandler.handleError(err, "Failed to download certificate");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setPin("");
    setError(null);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Download Certificate</DialogTitle>
          <DialogDescription>
            Enter your PIN to download the certificate file (PKCS#12 format). The PIN must be at least 8 characters long.
          </DialogDescription>
        </DialogHeader>
        {certificate && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium">Serial Number:</p>
              <p className="text-sm text-muted-foreground">{certificate.serial_number}</p>
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <label htmlFor="pin" className="text-sm font-medium">
                PIN
              </label>
              <Input
                type="password"
                id="pin"
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="Enter your PIN"
                disabled={loading}
                minLength={8}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !loading && pin.length >= 8) {
                    handleDownload();
                  }
                }}
              />
              <p className="text-xs text-muted-foreground">PIN must be at least 8 characters long</p>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleDownload} disabled={loading || pin.length < 8}>
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

