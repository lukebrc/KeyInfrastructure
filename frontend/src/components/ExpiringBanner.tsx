import { useState, useEffect, useCallback } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { Certificate } from "@/types";
import { AlertTriangle, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/utils";

export const ExpiringBanner: React.FC = () => {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [minimized, setMinimized] = useState(false);
  const [renewing, setRenewing] = useState<Record<string, boolean>>({});

  const fetchExpiringCertificates = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getExpiringCertificates(30);
      setCertificates(data);
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to load expiring certificates");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchExpiringCertificates();

    // Poll for updates every 5 minutes
    const interval = setInterval(fetchExpiringCertificates, 5 * 60 * 1000);

    return () => clearInterval(interval);
  }, [fetchExpiringCertificates]);

  const handleRenew = async (certificateId: string) => {
    try {
      setRenewing((prev) => ({ ...prev, [certificateId]: true }));
      await api.renewCertificate(certificateId);
      ErrorHandler.showSuccess("Certificate renewed successfully");
      await fetchExpiringCertificates();
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to renew certificate");
    } finally {
      setRenewing((prev) => ({ ...prev, [certificateId]: false }));
    }
  };

  if (loading) {
    return null;
  }

  if (certificates.length === 0) {
    return null;
  }

  const getDaysUntilExpiry = (expirationDate: string): number => {
    const expiry = new Date(expirationDate);
    const now = new Date();
    const diffTime = expiry.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  const getExpiryColor = (days: number): string => {
    if (days <= 7)
      return "bg-red-500/20 border-red-500/50 text-red-900 dark:text-red-100";
    if (days <= 14)
      return "bg-orange-500/20 border-orange-500/50 text-orange-900 dark:text-orange-100";
    return "bg-yellow-500/20 border-yellow-500/50 text-yellow-900 dark:text-yellow-100";
  };

  return (
    <Alert
      className={cn(
        "sticky top-0 z-50 mb-4 border-2 shadow-lg transition-all",
        getExpiryColor(
          getDaysUntilExpiry(certificates[0]?.expiration_date || ""),
        ),
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 flex-1">
          <AlertTriangle className="size-5 mt-0.5 flex-shrink-0" />
          <div className="flex-1">
            <AlertTitle className="flex items-center gap-2 mb-2">
              Certificates Expiring Soon
              <Badge variant="destructive">{certificates.length}</Badge>
            </AlertTitle>
            {!minimized && (
              <AlertDescription className="space-y-2">
                {certificates.map((cert) => {
                  const days = getDaysUntilExpiry(cert.expiration_date);
                  return (
                    <div
                      key={cert.id}
                      className="flex items-center justify-between gap-4 py-2 border-b last:border-b-0"
                    >
                      <div className="flex-1">
                        <p className="font-medium">{cert.serial_number}</p>
                        <p className="text-sm opacity-90">
                          Expires in {days} {days === 1 ? "day" : "days"} (
                          {new Date(cert.expiration_date).toLocaleDateString()})
                        </p>
                        <p className="text-xs opacity-75 truncate max-w-md">
                          {cert.dn}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => handleRenew(cert.id)}
                        disabled={renewing[cert.id] || cert.status !== "ACTIVE"}
                      >
                        {renewing[cert.id] ? (
                          <>
                            <RefreshCw className="size-4 mr-2 animate-spin" />
                            Renewing...
                          </>
                        ) : (
                          <>
                            <RefreshCw className="size-4 mr-2" />
                            Renew Now
                          </>
                        )}
                      </Button>
                    </div>
                  );
                })}
              </AlertDescription>
            )}
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setMinimized(!minimized)}
          className="flex-shrink-0"
          aria-label={minimized ? "Expand banner" : "Minimize banner"}
        >
          {minimized ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronUp className="size-4" />
          )}
        </Button>
      </div>
    </Alert>
  );
};
