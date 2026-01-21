import { AdminHeader } from "./AdminHeader";
import { AdminStats } from "./AdminStats";
import { UserList } from "./UserList";
import { Toaster } from "./ui/sonner";
import { AuthProvider } from "./AuthContext";

export const AdminDashboard: React.FC = () => {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-gradient-to-br from-sky-50 via-blue-50 to-indigo-50">
        <AdminHeader />
        <main className="container mx-auto p-4 md:p-6 lg:p-8">
          <div className="space-y-6">
            <div>
              <h1 className="text-3xl font-bold mb-2">
                Administrator Dashboard
              </h1>
              <p className="text-muted-foreground">
                Manage certificates and users
              </p>
            </div>

            <AdminStats />

            <UserList />
          </div>
        </main>
        <Toaster />
      </div>
    </AuthProvider>
  );
};
