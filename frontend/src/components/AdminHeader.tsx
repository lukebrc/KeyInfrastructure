import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { User } from "@/types";
import { LogOut, Shield } from "lucide-react";

export const AdminHeader: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const userData = await api.getCurrentUser();
        setUser(userData);
      } catch (error) {
        ErrorHandler.handleError(error, "Failed to load user information");
      } finally {
        setLoading(false);
      }
    };
    fetchUser();
  }, []);

  const handleLogout = async () => {
    try {
      await api.logout();
      window.location.href = "/login";
    } catch (error) {
      ErrorHandler.handleError(error, "Failed to logout");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-between p-4 border-b border-sky-100 bg-white shadow-sm">
        <div className="flex items-center gap-2">
          <Shield className="size-5 text-sky-600" />
          <span className="text-sm text-muted-foreground">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between p-4 border-b border-sky-100 bg-white shadow-sm">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Shield className="size-5 text-sky-600" />
          <div>
            <p className="text-sm font-medium text-slate-800">
              {user?.username}
            </p>
            <p className="text-xs text-sky-600">Administrator</p>
          </div>
        </div>
        <nav className="flex items-center gap-2 ml-4">
          <a
            href="/admin/dashboard"
            className="text-sm text-slate-600 hover:text-sky-600 transition-colors"
          >
            Dashboard
          </a>
          <span className="text-sky-300">•</span>
          <a
            href="/admin/certificates/create"
            className="text-sm text-slate-600 hover:text-sky-600 transition-colors"
          >
            New certificate request
          </a>
          {user && (
            <>
              <span className="text-sky-300">•</span>
              <a
                href={`/admin/certificates?userId=${user.id}`}
                className="text-sm text-slate-600 hover:text-sky-600 transition-colors"
              >
                Manage Certificates
              </a>
            </>
          )}
        </nav>
      </div>
      <Button variant="outline" size="sm" onClick={handleLogout}>
        <LogOut className="size-4 mr-2" />
        Logout
      </Button>
    </div>
  );
};
