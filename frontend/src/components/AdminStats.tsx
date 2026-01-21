import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import { Users, Shield, AlertTriangle, XCircle } from "lucide-react";
import type { Certificate } from "@/types";

interface Stats {
  totalUsers: number;
  totalCertificates: number;
  revokedCertificates: number;
  expiringCertificates: number;
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

// Count expiring certificates from a list
const countExpiringCertificates = (
  certificates: Certificate[],
  days = 30,
): number => {
  return certificates.filter(
    (cert) =>
      cert.status === "ACTIVE" && isExpiringSoon(cert.expiration_date, days),
  ).length;
};

export const AdminStats: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        // Fetch users
        const users = await api.getUsers();

        // Fetch all certificates to get total count (admin endpoint for all users)
        const certificatesResponse = await api.getAdminCertificates({
          limit: 1000,
        });

        // Fetch revoked certificates separately to get accurate count (admin endpoint for all users)
        const revokedResponse = await api.getAdminCertificates({
          limit: 1000,
          status: "REVOKED",
        });

        // Calculate expiring certificates from all active certificates
        // We need to count ACTIVE certificates that are expiring within 30 days
        const expiringCount = countExpiringCertificates(
          certificatesResponse.data || [],
          30,
        );

        setStats({
          totalUsers: users.length,
          totalCertificates: certificatesResponse.total,
          revokedCertificates: revokedResponse.total,
          expiringCertificates: expiringCount,
        });
      } catch (error) {
        ErrorHandler.handleError(error, "Failed to load statistics");
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardHeader>
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-8 w-16 mt-2" />
            </CardHeader>
          </Card>
        ))}
      </div>
    );
  }

  if (!stats) {
    return null;
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Users</CardTitle>
          <Users className="size-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.totalUsers}</div>
          <CardDescription>Registered users in the system</CardDescription>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">
            Total Certificates
          </CardTitle>
          <Shield className="size-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.totalCertificates}</div>
          <CardDescription>All certificates in the system</CardDescription>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Expiring Soon</CardTitle>
          <AlertTriangle className="size-4 text-yellow-600" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-yellow-600">
            {stats.expiringCertificates}
          </div>
          <CardDescription>Certificates expiring in 30 days</CardDescription>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Revoked</CardTitle>
          <XCircle className="size-4 text-destructive" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-destructive">
            {stats.revokedCertificates}
          </div>
          <CardDescription>Revoked certificates</CardDescription>
        </CardContent>
      </Card>
    </div>
  );
};
