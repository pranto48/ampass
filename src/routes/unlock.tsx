import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { PasswordStrength } from "@/components/PasswordStrength";
import { logAudit } from "@/lib/audit";
import { toast } from "sonner";
import { Lock, LogOut, ShieldAlert, KeyRound } from "lucide-react";

export const Route = createFileRoute("/unlock")({ component: UnlockPage });

function UnlockPage() {
  const { session, loading, needsSetup, unlock, setupMaster, signOut, vaultKey, userId } = useAuth();
  const router = useRouter();
  const [pw, setPw] = React.useState("");
  const [pw2, setPw2] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!loading && !session) router.navigate({ to: "/auth", replace: true });
    if (vaultKey) router.navigate({ to: "/dashboard", replace: true });
  }, [loading, session, vaultKey, router]);

  const handle = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (pw.length < 10) { setError("Master password must be at least 10 characters."); return; }
    if (needsSetup && pw !== pw2) { setError("Passwords do not match."); return; }
    setBusy(true);
    try {
      if (needsSetup) {
        await setupMaster(pw);
        if (userId) await logAudit(userId, "master.setup");
        toast.success("Vault initialized");
      } else {
        await unlock(pw);
        if (userId) await logAudit(userId, "master.unlock");
      }
      router.navigate({ to: "/dashboard", replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed";
      setError(msg);
      if (userId) await logAudit(userId, "master.failed", null, { reason: msg });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-background grid place-items-center p-4">
      <Card className="w-full max-w-md shadow-elevated">
        <CardHeader className="text-center">
          <div className="mx-auto size-12 rounded-2xl gradient-brand grid place-items-center text-white shadow-soft mb-3">
            {needsSetup ? <KeyRound className="size-5" /> : <Lock className="size-5" />}
          </div>
          <CardTitle>{needsSetup ? "Create your master password" : "Unlock your vault"}</CardTitle>
          <CardDescription>
            {needsSetup
              ? "This is the key to your encrypted vault. We can never recover it — choose carefully."
              : "Enter your master password to decrypt your vault locally."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {needsSetup && (
            <Alert className="mb-4">
              <ShieldAlert className="size-4" />
              <AlertDescription>
                Your master password never leaves this device. If you forget it, your vault cannot be recovered.
              </AlertDescription>
            </Alert>
          )}
          <form onSubmit={handle} className="space-y-4">
            <div className="space-y-1.5">
              <Label>Master password</Label>
              <Input type="password" autoFocus autoComplete={needsSetup ? "new-password" : "current-password"}
                value={pw} onChange={(e) => setPw(e.target.value)} />
              {needsSetup && <PasswordStrength value={pw} />}
            </div>
            {needsSetup && (
              <div className="space-y-1.5">
                <Label>Confirm master password</Label>
                <Input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
              </div>
            )}
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full gradient-brand text-white border-0" disabled={busy}>
              {busy ? "Working…" : needsSetup ? "Create vault" : "Unlock"}
            </Button>
          </form>
          <div className="mt-4 text-center">
            <Button variant="ghost" size="sm" onClick={signOut}><LogOut className="size-4 mr-2" /> Sign out</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
