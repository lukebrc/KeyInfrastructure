import { Button } from "@/components/ui/button";
import { PlusCircle } from "lucide-react";
import React from "react";

interface CreateCertificateButtonProps {
  userId?: string | null;
}

export const CreateCertificateButton: React.FC<
  CreateCertificateButtonProps
> = ({ userId }) => {
  const href = userId
    ? `/admin/certificates/create?userId=${userId}`
    : "/admin/certificates/create";

  return (
    <Button asChild>
      <a href={href}>
        <PlusCircle className="size-4 mr-2" />
        New certificate request
      </a>
    </Button>
  );
};
