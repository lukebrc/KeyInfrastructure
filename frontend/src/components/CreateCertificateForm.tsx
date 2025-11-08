import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import { ErrorHandler } from "@/lib/error-handler";
import type { User, CreateCertificateRequest, DistinguishedName, ApiError } from "@/types";
import { Loader2, CheckCircle2 } from "lucide-react";

export const CreateCertificateForm: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<string>("");
  const [validityPeriodDays, setValidityPeriodDays] = useState<string>("365");
  const [hashAlgorithm, setHashAlgorithm] = useState<"SHA-256" | "SHA-384" | "SHA-512">("SHA-256");
  const [dn, setDn] = useState<DistinguishedName>({
    cn: "",
    ou: "",
    o: "",
    l: "",
    st: "",
    c: "",
  });
  const [loading, setLoading] = useState(false);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [createdCertificateSerial, setCreatedCertificateSerial] = useState<string | null>(null);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        setLoadingUsers(true);
        const usersData = await api.getUsers();
        setUsers(usersData);
      } catch (error) {
        ErrorHandler.handleError(error, "Failed to load users");
      } finally {
        setLoadingUsers(false);
      }
    };
    fetchUsers();
  }, []);

  const formatDN = (dn: DistinguishedName): string => {
    const parts: string[] = [];
    if (dn.c) parts.push(`C=${dn.c}`);
    if (dn.st) parts.push(`ST=${dn.st}`);
    if (dn.l) parts.push(`L=${dn.l}`);
    if (dn.o) parts.push(`O=${dn.o}`);
    if (dn.ou) parts.push(`OU=${dn.ou}`);
    if (dn.cn) parts.push(`CN=${dn.cn}`);
    return parts.join(", ");
  };

  const validateForm = (): boolean => {
    if (!selectedUserId) {
      setError("Please select a user");
      return false;
    }

    if (!dn.cn || dn.cn.trim() === "") {
      setError("Common Name (CN) is required");
      return false;
    }

    const validityDays = parseInt(validityPeriodDays, 10);
    if (isNaN(validityDays) || validityDays < 1 || validityDays > 3650) {
      setError("Validity period must be between 1 and 3650 days");
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);

    if (!validateForm()) {
      setLoading(false);
      return;
    }

    try {
      const request: CreateCertificateRequest = {
        user_id: selectedUserId,
        validity_period_days: parseInt(validityPeriodDays, 10),
        hash_algorithm: hashAlgorithm,
        distinguished_name: {
          cn: dn.cn.trim(),
          ou: dn.ou?.trim() || undefined,
          o: dn.o?.trim() || undefined,
          l: dn.l?.trim() || undefined,
          st: dn.st?.trim() || undefined,
          c: dn.c?.trim() || undefined,
        },
      };

      const certificate = await api.createCertificate(selectedUserId, request);
      setCreatedCertificateSerial(certificate.serial_number);
      setSuccess(true);
      ErrorHandler.showSuccess(`Certificate created successfully! Serial: ${certificate.serial_number}`);

      // Reset form
      setTimeout(() => {
        setSelectedUserId("");
        setValidityPeriodDays("365");
        setHashAlgorithm("SHA-256");
        setDn({
          cn: "",
          ou: "",
          o: "",
          l: "",
          st: "",
          c: "",
        });
        setSuccess(false);
        setCreatedCertificateSerial(null);
      }, 5000);
    } catch (err) {
      const apiError = err as ApiError;
      if (apiError.message?.includes("400") || apiError.message?.includes("Bad Request")) {
        setError(apiError.message || "Invalid data. Please check your input.");
      } else if (apiError.message?.includes("403") || apiError.message?.includes("Forbidden")) {
        setError("You don't have permission to create certificates");
      } else {
        setError(apiError.message || "Failed to create certificate. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Create Certificate</CardTitle>
          <CardDescription>Create a new certificate for a user</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {success && (
              <Alert>
                <CheckCircle2 className="size-4" />
                <AlertDescription>
                  Certificate created successfully! Serial number: {createdCertificateSerial}
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <label htmlFor="user" className="text-sm font-medium">
                User <span className="text-destructive">*</span>
              </label>
              <Select
                value={selectedUserId}
                onValueChange={setSelectedUserId}
                disabled={loading || loadingUsers}
              >
                <SelectTrigger>
                  <SelectValue placeholder={loadingUsers ? "Loading users..." : "Select a user"} />
                </SelectTrigger>
                <SelectContent>
                  {users.map((user) => (
                    <SelectItem key={user.id} value={user.id}>
                      {user.username} ({user.role})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label htmlFor="validityPeriodDays" className="text-sm font-medium">
                Validity Period (days) <span className="text-destructive">*</span>
              </label>
              <Input
                type="number"
                id="validityPeriodDays"
                value={validityPeriodDays}
                onChange={(e) => setValidityPeriodDays(e.target.value)}
                min={1}
                max={3650}
                required
                disabled={loading}
                placeholder="365"
              />
              <p className="text-xs text-muted-foreground">Must be between 1 and 3650 days</p>
            </div>

            <div className="space-y-2">
              <label htmlFor="hashAlgorithm" className="text-sm font-medium">
                Hash Algorithm <span className="text-destructive">*</span>
              </label>
              <Select
                value={hashAlgorithm}
                onValueChange={(value) => setHashAlgorithm(value as "SHA-256" | "SHA-384" | "SHA-512")}
                disabled={loading}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="SHA-256">SHA-256</SelectItem>
                  <SelectItem value="SHA-384">SHA-384</SelectItem>
                  <SelectItem value="SHA-512">SHA-512</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Distinguished Name (DN)</h3>

              <div className="space-y-2">
                <label htmlFor="cn" className="text-sm font-medium">
                  Common Name (CN) <span className="text-destructive">*</span>
                </label>
                <Input
                  type="text"
                  id="cn"
                  value={dn.cn}
                  onChange={(e) => setDn({ ...dn, cn: e.target.value })}
                  required
                  disabled={loading}
                  placeholder="e.g., username"
                />
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <label htmlFor="ou" className="text-sm font-medium">
                    Organizational Unit (OU)
                  </label>
                  <Input
                    type="text"
                    id="ou"
                    value={dn.ou}
                    onChange={(e) => setDn({ ...dn, ou: e.target.value })}
                    disabled={loading}
                    placeholder="e.g., IT Department"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="o" className="text-sm font-medium">
                    Organization (O)
                  </label>
                  <Input
                    type="text"
                    id="o"
                    value={dn.o}
                    onChange={(e) => setDn({ ...dn, o: e.target.value })}
                    disabled={loading}
                    placeholder="e.g., Company Inc."
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="l" className="text-sm font-medium">
                    Locality (L)
                  </label>
                  <Input
                    type="text"
                    id="l"
                    value={dn.l}
                    onChange={(e) => setDn({ ...dn, l: e.target.value })}
                    disabled={loading}
                    placeholder="e.g., Warsaw"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="st" className="text-sm font-medium">
                    State/Province (ST)
                  </label>
                  <Input
                    type="text"
                    id="st"
                    value={dn.st}
                    onChange={(e) => setDn({ ...dn, st: e.target.value })}
                    disabled={loading}
                    placeholder="e.g., Mazovian"
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="c" className="text-sm font-medium">
                    Country (C)
                  </label>
                  <Input
                    type="text"
                    id="c"
                    value={dn.c}
                    onChange={(e) => setDn({ ...dn, c: e.target.value })}
                    disabled={loading}
                    placeholder="e.g., PL"
                    maxLength={2}
                  />
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">DN Preview</label>
              <div className="p-3 bg-muted rounded-md font-mono text-sm">
                {dn.cn ? formatDN(dn) : <span className="text-muted-foreground">Enter DN fields to see preview</span>}
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <Loader2 className="size-4 mr-2 animate-spin" />
                    Creating...
                  </>
                ) : (
                  "Create Certificate"
                )}
              </Button>
              <a href="/admin/dashboard">
                <Button type="button" variant="outline" disabled={loading}>
                  Cancel
                </Button>
              </a>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

