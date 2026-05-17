import * as React from "react";
import { useRouter, useRouterState } from "@tanstack/react-router";
import { useAuth } from "@/lib/auth-context";

/** Wrapper for any authenticated route. Redirects to /auth if signed out, /unlock if locked. */
export function RequireUnlocked({ children }: { children: React.ReactNode }) {
  const { session, loading, isLocked, needsSetup } = useAuth();
  const router = useRouter();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  React.useEffect(() => {
    if (loading) return;
    if (!session && pathname !== "/auth") {
      router.navigate({ to: "/auth", replace: true });
    } else if (session && isLocked && pathname !== "/unlock") {
      router.navigate({ to: "/unlock", replace: true });
    }
  }, [session, loading, isLocked, needsSetup, pathname, router]);

  if (loading) return <FullscreenLoader label="Loading…" />;
  if (!session || isLocked) return <FullscreenLoader label="Redirecting…" />;
  return <>{children}</>;
}

export function FullscreenLoader({ label }: { label?: string }) {
  return (
    <div className="min-h-screen grid place-items-center text-muted-foreground text-sm">
      <div className="flex items-center gap-3">
        <div className="size-3 rounded-full bg-primary animate-pulse" />
        {label ?? "Loading"}
      </div>
    </div>
  );
}
