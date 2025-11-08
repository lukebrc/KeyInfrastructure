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
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import type { Certificate } from "@/types";
import { Loader2, AlertTriangle } from "lucide-react";

interface RevokeModalProps {
  certificate: Certificate | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRevoked: () => void;
}

export const RevokeModal: React.FC<RevokeModalProps> = ({
  certificate,
  open,
  onOpenChange,
  onRevoked,
}) => {
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleRevoke = async () => {
    if (!certificate) return;

    setLoading(true);
    setError(null);

    try {
      const { api } = await import("@/lib/api");
      const { ErrorHandler } = await import("@/lib/error-handler");

      await api.revokeCertificate(certificate.id, { reason: reason.trim() || undefined });
      ErrorHandler.showSuccess("Certificate revoked successfully");
      onRevoked();
      onOpenChange(false);
      setReason("");
    } catch (err) {
      const apiError = err as { message?: string };
      setError(apiError.message || "Failed to revoke certificate");
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setReason("");
    setError(null);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="size-5 text-destructive" />
            Revoke Certificate
          </DialogTitle>
          <DialogDescription>
            Are you sure you want to revoke this certificate? This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        {certificate && (
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium">Serial Number:</p>
              <p className="text-sm text-muted-foreground font-mono">{certificate.serial_number}</p>
            </div>
            <div>
              <p className="text-sm font-medium">User:</p>
              <p className="text-sm text-muted-foreground">{certificate.username || "N/A"}</p>
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <div className="space-y-2">
              <Label htmlFor="reason">Reason (optional)</Label>
              <Textarea
                id="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Enter reason for revocation..."
                disabled={loading}
                rows={3}
              />
              <p className="text-xs text-muted-foreground">
                Provide a reason for revoking this certificate (optional)
              </p>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleRevoke} disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="size-4 mr-2 animate-spin" />
                Revoking...
              </>
            ) : (
              "Revoke Certificate"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

