import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { useAuth } from "@/lib/auth-context";
import { FullscreenLoader } from "@/components/RequireUnlocked";

export const Route = createFileRoute("/")({
  component: Index,
});

function Index() {
  const { session, loading, isLocked } = useAuth();
  const router = useRouter();
  React.useEffect(() => {
    if (loading) return;
    if (!session) router.navigate({ to: "/auth", replace: true });
    else if (isLocked) router.navigate({ to: "/unlock", replace: true });
    else router.navigate({ to: "/dashboard", replace: true });
  }, [session, loading, isLocked, router]);
  return <FullscreenLoader label="Opening AMPass…" />;
}
