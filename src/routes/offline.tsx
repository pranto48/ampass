import { createFileRoute } from "@tanstack/react-router";
import { Card, CardContent } from "@/components/ui/card";
import { WifiOff, Lock } from "lucide-react";

export const Route = createFileRoute("/offline")({ component: OfflinePage });

function OfflinePage() {
  return (
    <div className="min-h-screen grid place-items-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardContent className="py-10 text-center space-y-4">
          <div className="mx-auto size-12 rounded-2xl gradient-brand grid place-items-center text-white">
            <WifiOff className="size-5" />
          </div>
          <h1 className="text-xl font-semibold">You're offline</h1>
          <p className="text-sm text-muted-foreground">
            AMPass requires a connection to sync your encrypted vault. Your vault remains locked while offline for safety.
          </p>
          <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
            <Lock className="size-3" /> Vault stays encrypted on-device
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
