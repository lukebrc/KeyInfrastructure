import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import type { User } from "@/types";
import { Skeleton } from "@/components/ui/skeleton";

interface CertificatesPageHeaderProps {
  userId?: string | null;
}

export const CertificatesPageHeader: React.FC<CertificatesPageHeaderProps> = ({
  userId,
}) => {
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(!!userId);

  useEffect(() => {
    if (!userId) {
      setLoading(false);
      return;
    }

    const fetchUsername = async () => {
      try {
        const users = await api.getUsers();
        const user = users.find((u: User) => u.id === userId);
        setUsername(user?.username ?? null);
      } catch {
        // If we can't fetch users, fall back to showing userId
        setUsername(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUsername();
  }, [userId]);

  const getSubtitle = () => {
    if (!userId) {
      return "View and manage all certificates in the system";
    }

    if (loading) {
      return <Skeleton className="h-5 w-64" />;
    }

    return `Certificates for user ${username ?? userId}`;
  };

  return (
    <div>
      <h1 className="text-3xl font-bold mb-2">Manage Certificates</h1>
      <p className="text-muted-foreground">{getSubtitle()}</p>
    </div>
  );
};
