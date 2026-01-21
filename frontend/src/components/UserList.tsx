import { useState, useEffect } from "react";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { User, Certificate } from "@/types";
import { Users, Settings, RefreshCw, UserPlus } from "lucide-react";
import { cn } from "@/lib/utils";
import { CertificateTable } from "./CertificateTable";
import { CreateCertificateForm } from "./CreateCertificateForm";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAuth } from "@/components/AuthContext";

// Certificate counts by status for each user
interface CertificateCounts {
  valid: number; // Active and not expiring soon
  pending: number; // Pending status
  expiring: number; // Active but expiring within 30 days
  revoked: number; // Revoked status
}

// Helper to check if a certificate is expiring within given days
const isExpiringSoon = (expirationDate: string, days = 30): boolean => {
  const expDate = new Date(expirationDate);
  const now = new Date();
  const daysUntilExpiration = Math.ceil(
    (expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
  );
  return daysUntilExpiration > 0 && daysUntilExpiration <= days;
};

// Calculate certificate counts from a list of certificates
const calculateCertificateCounts = (
  certificates: Certificate[],
): CertificateCounts => {
  return certificates.reduce(
    (counts, cert) => {
      if (cert.status === "PENDING") {
        counts.pending++;
      } else if (cert.status === "REVOKED") {
        counts.revoked++;
      } else if (cert.status === "ACTIVE") {
        if (isExpiringSoon(cert.expiration_date)) {
          counts.expiring++;
        } else {
          counts.valid++;
        }
      }
      return counts;
    },
    { valid: 0, pending: 0, expiring: 0, revoked: 0 },
  );
};

// Component to display certificate counts with colors
const CertificateCountsDisplay: React.FC<{
  counts: CertificateCounts | null;
  loading?: boolean;
}> = ({ counts, loading }) => {
  if (loading) {
    return <Skeleton className="h-4 w-24" />;
  }

  if (!counts) {
    return <span className="text-sm text-muted-foreground">-</span>;
  }

  const hasAnyCertificates =
    counts.valid + counts.pending + counts.expiring + counts.revoked > 0;

  if (!hasAnyCertificates) {
    return <span className="text-sm text-muted-foreground">0</span>;
  }

  return (
    <div className="flex items-center gap-1.5 text-sm font-medium">
      {counts.valid > 0 && (
        <span
          className="text-green-600 dark:text-green-400"
          title="Valid certificates"
        >
          {counts.valid}
        </span>
      )}
      {counts.pending > 0 && (
        <>
          {counts.valid > 0 && <span className="text-muted-foreground">/</span>}
          <span
            className="text-gray-500 dark:text-gray-400"
            title="Pending certificates"
          >
            {counts.pending}
          </span>
        </>
      )}
      {counts.expiring > 0 && (
        <>
          {(counts.valid > 0 || counts.pending > 0) && (
            <span className="text-muted-foreground">/</span>
          )}
          <span
            className="text-orange-500 dark:text-orange-400"
            title="Expiring certificates"
          >
            {counts.expiring}
          </span>
        </>
      )}
      {counts.revoked > 0 && (
        <>
          {(counts.valid > 0 || counts.pending > 0 || counts.expiring > 0) && (
            <span className="text-muted-foreground">/</span>
          )}
          <span
            className="text-red-600 dark:text-red-400"
            title="Revoked certificates"
          >
            {counts.revoked}
          </span>
        </>
      )}
    </div>
  );
};

// Colorful column header with legend
const CertificatesColumnHeader: React.FC = () => (
  <div className="flex flex-col gap-0.5">
    <span>Certificates</span>
    <div className="flex items-center gap-1 text-xs font-normal">
      <span className="text-green-600 dark:text-green-400">Valid</span>
      <span className="text-muted-foreground">/</span>
      <span className="text-gray-500 dark:text-gray-400">Pending</span>
      <span className="text-muted-foreground">/</span>
      <span className="text-orange-500 dark:text-orange-400">Expiring</span>
      <span className="text-muted-foreground">/</span>
      <span className="text-red-600 dark:text-red-400">Revoked</span>
    </div>
  </div>
);

export const UserList: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [total, setTotal] = useState(0);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [manageModalOpen, setManageModalOpen] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [userCertificates, setUserCertificates] = useState<Certificate[]>([]);
  const [certificatesLoading, setCertificatesLoading] = useState(false);
  const [certificateStatusFilter, setCertificateStatusFilter] = useState<
    "ALL" | Certificate["status"]
  >("ALL");
  const { user: currentUser, loading: authLoading } = useAuth();

  // Certificate counts per user
  const [userCertificateCounts, setUserCertificateCounts] = useState<
    Record<string, CertificateCounts>
  >({});
  const [countsLoading, setCountsLoading] = useState(false);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await api.getUsers();
      setUsers(response);
      setTotal(response.length);
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to load users");
    } finally {
      setLoading(false);
    }
  };

  // Fetch certificate counts for all users
  const fetchAllUserCertificateCounts = async (userList: User[]) => {
    if (userList.length === 0) return;

    setCountsLoading(true);
    const counts: Record<string, CertificateCounts> = {};

    try {
      // Fetch certificates for all users in parallel
      const promises = userList.map(async (user) => {
        try {
          const response = await api.getUserCertificates(user.id, {
            page: 1,
            limit: 1000, // Get all certificates for counting
          });
          counts[user.id] = calculateCertificateCounts(response.data || []);
        } catch {
          // If we can't fetch for a user, set empty counts
          counts[user.id] = { valid: 0, pending: 0, expiring: 0, revoked: 0 };
        }
      });

      await Promise.all(promises);
      setUserCertificateCounts(counts);
    } catch (error) {
      console.error("Failed to fetch certificate counts:", error);
    } finally {
      setCountsLoading(false);
    }
  };

  const fetchUserCertificates = async (userId: string) => {
    try {
      setCertificatesLoading(true);
      const response = await api.getUserCertificates(userId, {
        page: 1,
        limit: 100, // Get all certificates for the user
      });
      setUserCertificates(response.data || []);
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to load user certificates");
      setUserCertificates([]); // Ensure it's always an array
    } finally {
      setCertificatesLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  // Fetch certificate counts when users are loaded
  useEffect(() => {
    if (users.length > 0 && !loading) {
      fetchAllUserCertificateCounts(users);
    }
  }, [users, loading]);

  const handleManageCertificates = (user: User) => {
    window.location.href = `/admin/certificates?userId=${user.id}`;
  };

  const handleCreateCertificate = (user: User) => {
    setSelectedUser(user);
    setCreateModalOpen(true);
  };

  const handleCertificateCreated = async () => {
    setCreateModalOpen(false);
    if (selectedUser) {
      await fetchUserCertificates(selectedUser.id);
      setManageModalOpen(true);
    }
    ErrorHandler.showSuccess("Certificate created successfully");
  };

  const handleCertificateRevoked = async () => {
    if (selectedUser) {
      await fetchUserCertificates(selectedUser.id);
    }
  };

  const handleCancelCertificate = async (certificate: Certificate) => {
    try {
      await api.cancelCertificateRequest(certificate.id);
      ErrorHandler.showSuccess("Certificate request cancelled successfully");
      if (selectedUser) {
        await fetchUserCertificates(selectedUser.id);
      }
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to cancel certificate request");
    }
  };

  const handleDownloadCertificate = async (cert: Certificate) => {
    if (!selectedUser) {
      console.error("No user selected");
      return;
    }

    try {
      // Direct download of the public certificate (CRT)
      const response = await fetch(
        `/api/users/${selectedUser.id}/certificates/${cert.id}/download`,
      );

      if (!response.ok) {
        throw new Error("Failed to download certificate");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${cert.serial_number}.crt`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to download certificate");
    }
  };

  const totalPages = Math.ceil(total / limit);

  // Client-side pagination: slice users for current page
  const paginatedUsers = users.slice((page - 1) * limit, page * limit);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users className="size-5" />
          <h3 className="text-lg font-semibold">User Management</h3>
        </div>
        <Button
          variant="outline"
          onClick={fetchUsers}
          disabled={loading || countsLoading}
        >
          <RefreshCw
            className={cn(
              "size-4 mr-2",
              (loading || countsLoading) && "animate-spin",
            )}
          />
          Refresh
        </Button>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Created At</TableHead>
              <TableHead>
                <CertificatesColumnHeader />
              </TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: limit }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <Skeleton className="h-4 w-24" />
                  </TableCell>
                  <TableCell>
                    <Skeleton className="h-4 w-16" />
                  </TableCell>
                  <TableCell>
                    <Skeleton className="h-4 w-32" />
                  </TableCell>
                  <TableCell>
                    <Skeleton className="h-4 w-12" />
                  </TableCell>
                  <TableCell className="text-right">
                    <Skeleton className="h-8 w-32 ml-auto" />
                  </TableCell>
                </TableRow>
              ))
            ) : paginatedUsers.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="text-center py-8 text-muted-foreground"
                >
                  No users found
                </TableCell>
              </TableRow>
            ) : (
              paginatedUsers.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.username}</TableCell>
                  <TableCell>
                    <Badge
                      variant={user.role === "ADMIN" ? "default" : "secondary"}
                    >
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {new Date(user.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <CertificateCountsDisplay
                      counts={userCertificateCounts[user.id] || null}
                      loading={countsLoading}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleManageCertificates(user)}
                        disabled={authLoading}
                      >
                        <Settings className="size-4 mr-1" />
                        Manage Certificates
                      </Button>
                      <Button
                        size="sm"
                        onClick={() => handleCreateCertificate(user)}
                      >
                        <UserPlus className="size-4 mr-1" />
                        New certificate request
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)}{" "}
            of {total} users
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

      {/* Manage Certificates Modal */}
      <Dialog open={manageModalOpen} onOpenChange={setManageModalOpen}>
        <DialogContent className="max-w-[95vw] lg:max-w-6xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              Manage Certificates for {selectedUser?.username}
            </DialogTitle>
            <DialogDescription>
              View and manage certificates for this user. You can renew or
              revoke active certificates.
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4">
            {certificatesLoading ? (
              <div className="space-y-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Select
                      value={certificateStatusFilter}
                      onValueChange={(val) =>
                        setCertificateStatusFilter(
                          val as "ALL" | Certificate["status"],
                        )
                      }
                    >
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
                  {/* Refresh button removed: use table's refresh / parent controls instead */}
                </div>

                <CertificateTable
                  certificates={userCertificates.filter((c) =>
                    certificateStatusFilter === "ALL"
                      ? true
                      : c.status === certificateStatusFilter,
                  )}
                  showUserColumn={false}
                  showStatusFilter={false}
                  allowGenerate={
                    currentUser !== null &&
                    selectedUser !== null &&
                    currentUser.id === selectedUser.id
                  }
                  onRevoke={handleCertificateRevoked}
                  onCancel={handleCancelCertificate}
                  onDownload={handleDownloadCertificate}
                  onRefresh={() =>
                    selectedUser && fetchUserCertificates(selectedUser.id)
                  }
                />
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Create Certificate Request Modal */}
      <Dialog open={createModalOpen} onOpenChange={setCreateModalOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Certificate Request</DialogTitle>
            <DialogDescription>
              Create a new certificate. Select the user and fill in the required
              information below.
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4">
            <CreateCertificateForm
              onSuccess={handleCertificateCreated}
              preselectedUserId={selectedUser?.id}
            />
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};
