import { useState, useEffect, useMemo } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import { DownloadCertificateModal } from "./DownloadCertificateModal";
import { RevokeModal } from "./RevokeModal";
import type { Certificate, CertificateStatus } from "@/types";
import { Download, RefreshCw, ArrowUpDown, ArrowUp, ArrowDown, XCircle, Play } from "lucide-react";
import { cn } from "@/lib/utils";

interface CertificateTableProps {
  certificates?: Certificate[];
  showUserColumn?: boolean;
  onRevoke?: (certificate: Certificate) => void;
  onRefresh?: () => void;
}

export const CertificateTable: React.FC<CertificateTableProps> = ({
  certificates: externalCertificates,
  showUserColumn = false,
  onRevoke,
  onRefresh,
}) => {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(!externalCertificates);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<CertificateStatus | "ALL">("ALL");
  const [sortBy, setSortBy] = useState<"expiration_date" | "serial_number">("expiration_date");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null);
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [renewing, setRenewing] = useState<Record<string, boolean>>({});
  const [generating, setGenerating] = useState<Record<string, boolean>>({});
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [certificateToRevoke, setCertificateToRevoke] = useState<Certificate | null>(null);

  const fetchCertificates = async () => {
    try {
      setLoading(true);
      const response = await api.getCertificates({
        page,
        limit,
        status: statusFilter !== "ALL" ? statusFilter : undefined,
        sort_by: sortBy,
        order: sortOrder,
      });
      setCertificates(response.data);
      setTotal(response.total);
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to load certificates");
    } finally {
      setLoading(false);
    }
  };

  // Use external certificates if provided, otherwise fetch our own
  const displayedCertificates = externalCertificates || certificates;
  const displayedLoading = externalCertificates ? false : loading;
  const displayedTotal = externalCertificates ? externalCertificates.length : total;

  useEffect(() => {
    if (!externalCertificates) {
      fetchCertificates();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, statusFilter, sortBy, sortOrder, externalCertificates]);

  // Update internal state when external certificates change
  useEffect(() => {
    if (externalCertificates) {
      setCertificates(externalCertificates);
      setLoading(false);
    }
  }, [externalCertificates]);

  const handleSort = (field: "expiration_date" | "serial_number") => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("asc");
    }
  };

  const handleRenew = async (certificateId: string) => {
    try {
      setRenewing((prev) => ({ ...prev, [certificateId]: true }));
      await api.renewCertificate(certificateId);
      ErrorHandler.showSuccess("Certificate renewed successfully");
      if (onRefresh) {
        await onRefresh();
      } else {
        await fetchCertificates();
      }
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to renew certificate");
    } finally {
      setRenewing((prev) => ({ ...prev, [certificateId]: false }));
    }
  };

  const handleGenerate = async (certificateId: string) => {
    try {
      setGenerating((prev) => ({ ...prev, [certificateId]: true }));
      await api.generateCertificate(certificateId);
      ErrorHandler.showSuccess("Certificate generated successfully");
      if (onRefresh) {
        await onRefresh();
      } else {
        await fetchCertificates();
      }
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to generate certificate");
    } finally {
      setGenerating((prev) => ({ ...prev, [certificateId]: false }));
    }
  };

  const handleDownload = (certificate: Certificate) => {
    setSelectedCertificate(certificate);
    setDownloadModalOpen(true);
  };

  const handleRevokeClick = (certificate: Certificate) => {
    if (onRevoke) {
      onRevoke(certificate);
    } else {
      // Fallback: use internal revoke modal
      setCertificateToRevoke(certificate);
      setRevokeModalOpen(true);
    }
  };

  const handleRevoked = async () => {
    setRevokeModalOpen(false);
    setCertificateToRevoke(null);
    if (onRefresh) {
      await onRefresh();
    } else {
      await fetchCertificates();
    }
  };

  const getDaysUntilExpiry = (expirationDate: string): number => {
    const expiry = new Date(expirationDate);
    const now = new Date();
    const diffTime = expiry.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  const isExpiringSoon = (expirationDate: string): boolean => {
    return getDaysUntilExpiry(expirationDate) <= 30;
  };

  const totalPages = Math.ceil(total / limit);

  const SortIcon = ({ field }: { field: "expiration_date" | "serial_number" }) => {
    if (sortBy !== field) {
      return <ArrowUpDown className="size-4 ml-1 opacity-50" />;
    }
    return sortOrder === "asc" ? (
      <ArrowUp className="size-4 ml-1" />
    ) : (
      <ArrowDown className="size-4 ml-1" />
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Select value={statusFilter} onValueChange={(value) => {
            setPage(1);
            setStatusFilter(value as CertificateStatus | "ALL")}
          }>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Statuses</SelectItem>
              <SelectItem value="ACTIVE">Active</SelectItem>
              <SelectItem value="REVOKED">Revoked</SelectItem>
              <SelectItem value="PENDING">Pending</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button variant="outline" onClick={onRefresh || fetchCertificates} disabled={displayedLoading}>
          <RefreshCw className={cn("size-4 mr-2", displayedLoading && "animate-spin")} />
          Refresh
        </Button>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 -ml-3"
                  onClick={() => handleSort("serial_number")}
                >
                  Serial Number
                  <SortIcon field="serial_number" />
                </Button>
              </TableHead>
              {showUserColumn && <TableHead>User</TableHead>}
              <TableHead>DN</TableHead>
              <TableHead>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 -ml-3"
                  onClick={() => handleSort("expiration_date")}
                >
                  Expiration Date
                  <SortIcon field="expiration_date" />
                </Button>
              </TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {displayedLoading ? (
              Array.from({ length: limit }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <Skeleton className="h-4 w-32" />
                  </TableCell>
                  {showUserColumn && (
                    <TableCell>
                      <Skeleton className="h-4 w-24" />
                    </TableCell>
                  )}
                  <TableCell>
                    <Skeleton className="h-4 w-48" />
                  </TableCell>
                  <TableCell>
                    <Skeleton className="h-4 w-24" />
                  </TableCell>
                  <TableCell>
                    <Skeleton className="h-4 w-16" />
                  </TableCell>
                  <TableCell className="text-right">
                    <Skeleton className="h-8 w-20 ml-auto" />
                  </TableCell>
                </TableRow>
              ))
            ) : displayedCertificates.length === 0 ? (
              <TableRow>
                <TableCell colSpan={showUserColumn ? 6 : 5} className="text-center py-8 text-muted-foreground">
                  No certificates found
                </TableCell>
              </TableRow>
            ) : (
              displayedCertificates.map((cert) => {
                const days = cert.status !== "PENDING" ? getDaysUntilExpiry(cert.expiration_date) : 0;
                const expiringSoon = cert.status !== "PENDING" ? isExpiringSoon(cert.expiration_date) : false;
                return (
                  <TableRow key={cert.id}>
                    <TableCell className="font-mono text-sm">{cert.serial_number}</TableCell>
                    {showUserColumn && <TableCell>{cert.username || "N/A"}</TableCell>}
                    <TableCell className="max-w-md truncate" title={cert.dn}>
                      {cert.dn}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        {cert.status === "PENDING" ? (
                          <span className="text-muted-foreground"></span>
                        ) : (
                          <>
                            <span className={cn(expiringSoon && "font-semibold text-orange-600 dark:text-orange-400")}>
                              {new Date(cert.expiration_date).toLocaleDateString()}
                            </span>
                            {expiringSoon && (
                              <span className="text-xs text-muted-foreground">
                                {days} {days === 1 ? "day" : "days"} left
                              </span>
                            )}
                          </>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={
                        cert.status === "ACTIVE" ? "default" :
                        cert.status === "PENDING" ? "secondary" :
                        "destructive"
                      }>
                        {cert.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        {cert.status === "ACTIVE" && (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleDownload(cert)}
                            >
                              <Download className="size-4 mr-1" />
                              Download
                            </Button>
                            {expiringSoon && (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleRenew(cert.id)}
                                disabled={renewing[cert.id]}
                              >
                                {renewing[cert.id] ? (
                                  <>
                                    <RefreshCw className="size-4 mr-1 animate-spin" />
                                    Renewing...
                                  </>
                                ) : (
                                  <>
                                    <RefreshCw className="size-4 mr-1" />
                                    Renew
                                  </>
                                )}
                              </Button>
                            )}
                            {(onRevoke || showUserColumn) && (
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => handleRevokeClick(cert)}
                              >
                                <XCircle className="size-4 mr-1" />
                                Revoke
                              </Button>
                            )}
                          </>
                        )}
                        {cert.status === "PENDING" && (
                          <Button
                            size="sm"
                            variant="default"
                            onClick={() => handleGenerate(cert.id)}
                            disabled={generating[cert.id]}
                          >
                            {generating[cert.id] ? (
                              <>
                                <RefreshCw className="size-4 mr-1 animate-spin" />
                                Generating...
                              </>
                            ) : (
                              <>
                                <Play className="size-4 mr-1" />
                                Generate
                              </>
                            )}
                          </Button>
                        )}
                        {cert.status === "REVOKED" && (onRevoke || showUserColumn) && (
                          <span className="text-sm text-muted-foreground">Revoked</span>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {((page - 1) * limit) + 1} to {Math.min(page * limit, total)} of {total} certificates
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
            >
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages || loading}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      <DownloadCertificateModal
        certificate={selectedCertificate}
        open={downloadModalOpen}
        onOpenChange={setDownloadModalOpen}
      />

      {!onRevoke && (
        <RevokeModal
          certificate={certificateToRevoke}
          open={revokeModalOpen}
          onOpenChange={setRevokeModalOpen}
          onRevoked={handleRevoked}
        />
      )}
    </div>
  );
};
