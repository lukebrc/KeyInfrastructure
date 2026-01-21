import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { User } from "@/types";
import { LogOut, User as UserIcon } from "lucide-react";

export const UserHeader: React.FC = () => {
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
          <UserIcon className="size-5 text-sky-600" />
          <span className="text-sm text-muted-foreground">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between p-4 border-b border-sky-100 bg-white shadow-sm">
      <div className="flex items-center gap-2">
        <UserIcon className="size-5 text-sky-600" />
        <div>
          <p className="text-sm font-medium text-slate-800">USER {user?.username}</p>
        </div>
      </div>
      <Button variant="outline" size="sm" onClick={handleLogout}>
        <LogOut className="size-4 mr-2" />
        Logout
      </Button>
    </div>
  );
};
