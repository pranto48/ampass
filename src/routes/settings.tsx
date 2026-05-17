import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { useTheme } from "@/lib/theme";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";

export const Route = createFileRoute("/settings")({
  component: () => (<RequireUnlocked><AppLayout><SettingsPage /></AppLayout></RequireUnlocked>),
});

function SettingsPage() {
  const { session, userId, lock, signOut } = useAuth();
  const { theme, toggle } = useTheme();
  const [profile, setProfile] = React.useState<{ full_name: string; username: string }>({ full_name: "", username: "" });

  React.useEffect(() => {
    if (!userId) return;
    supabase.from("profiles").select("full_name,username").eq("id", userId).maybeSingle()
      .then(({ data }) => { if (data) setProfile({ full_name: data.full_name ?? "", username: data.username ?? "" }); });
  }, [userId]);

  const save = async () => {
    if (!userId) return;
    const { error } = await supabase.from("profiles").update(profile).eq("id", userId);
    if (error) toast.error(error.message); else toast.success("Saved");
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground text-sm mt-1">Account, profile, security & appearance.</p>
      </header>

      <Card>
        <CardHeader><CardTitle className="text-base">Profile</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5"><Label>Email</Label><Input value={session?.user.email ?? ""} disabled /></div>
          <div className="space-y-1.5"><Label>Full name</Label><Input value={profile.full_name} onChange={(e) => setProfile((p) => ({ ...p, full_name: e.target.value }))} /></div>
          <div className="space-y-1.5"><Label>Username</Label><Input value={profile.username} onChange={(e) => setProfile((p) => ({ ...p, username: e.target.value }))} /></div>
          <div className="flex justify-end"><Button onClick={save} className="gradient-brand text-white border-0">Save</Button></div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Appearance</CardTitle></CardHeader>
        <CardContent>
          <label className="flex items-center justify-between border rounded-md px-3 py-2">
            <span className="text-sm">Dark mode</span>
            <Switch checked={theme === "dark"} onCheckedChange={toggle} />
          </label>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Security</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <Alert>
            <AlertDescription className="text-xs">
              Your vault is encrypted in your browser with AES-256-GCM and a key derived from your master password using PBKDF2 (250,000 iterations).
              We never receive your master password. Vault auto-locks after 15 minutes of inactivity.
            </AlertDescription>
          </Alert>
          <div className="flex gap-2">
            <Button variant="outline" onClick={lock}>Lock vault</Button>
            <Button variant="outline" onClick={signOut}>Sign out</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
