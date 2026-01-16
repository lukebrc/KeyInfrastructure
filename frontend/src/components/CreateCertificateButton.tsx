import { Button } from "@/components/ui/button";
import { PlusCircle } from "lucide-react";
import React from "react";

export const CreateCertificateButton: React.FC = () => {
  return (
    <Button asChild>
      <a href="/admin/certificates/create">
        <PlusCircle className="size-4 mr-2" />
        Create Certificate
      </a>
    </Button>
  );
};
