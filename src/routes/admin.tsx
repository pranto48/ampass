import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { Shield, Lock } from "lucide-react";
import { logAudit } from "@/lib/audit";

export const Route = createFileRoute("/admin")({
  component: () => (<RequireUnlocked><AppLayout><AdminPage /></AppLayout></RequireUnlocked>),
});

function AdminPage() {
  const { isAdmin, userId } = useAuth();
  const [siteName, setSiteName] = React.useState("AMPass");
  const [regEnabled, setRegEnabled] = React.useState(true);
  const [users, setUsers] = React.useState<{ id: string; email: string; username: string | null; full_name: string | null; roles: string[] }[]>([]);
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    const [s1, s2, prof, roles] = await Promise.all([
      supabase.from("app_settings").select("value").eq("key", "site_name").maybeSingle(),
      supabase.from("app_settings").select("value").eq("key", "registration_enabled").maybeSingle(),
      supabase.from("profiles").select("id,email,username,full_name"),
      supabase.from("user_roles").select("user_id,role"),
    ]);
    if (s1.data) setSiteName(typeof s1.data.value === "string" ? s1.data.value : "AMPass");
    if (s2.data) setRegEnabled(Boolean(s2.data.value));
    const roleMap = new Map<string, string[]>();
    for (const r of roles.data ?? []) {
      const list = roleMap.get(r.user_id) ?? [];
      list.push(r.role); roleMap.set(r.user_id, list);
    }
    setUsers((prof.data ?? []).map((p) => ({ ...p, roles: roleMap.get(p.id) ?? [] })));
  }, []);

  React.useEffect(() => { if (isAdmin) void load(); }, [isAdmin, load]);

  if (!isAdmin) {
    return (
      <Card>
        <CardContent className="py-16 text-center space-y-3">
          <Lock className="size-10 mx-auto text-muted-foreground" />
          <p className="font-medium">Admin only</p>
          <p className="text-sm text-muted-foreground">You don't have permission to access this page.</p>
        </CardContent>
      </Card>
    );
  }

  const saveSettings = async () => {
    setBusy(true);
    const { error: e1 } = await supabase.from("app_settings").update({ value: siteName }).eq("key", "site_name");
    const { error: e2 } = await supabase.from("app_settings").update({ value: regEnabled }).eq("key", "registration_enabled");
    if (e1 || e2) toast.error((e1 || e2)?.message ?? "Failed"); else { toast.success("Settings saved"); if (userId) await logAudit(userId, "settings.update"); }
    setBusy(false);
  };

  const toggleAdmin = async (uid: string, currentlyAdmin: boolean) => {
    if (currentlyAdmin) {
      const { error } = await supabase.from("user_roles").delete().eq("user_id", uid).eq("role", "admin");
      if (error) toast.error(error.message);
    } else {
      const { error } = await supabase.from("user_roles").insert({ user_id: uid, role: "admin" });
      if (error) toast.error(error.message);
    }
    void load();
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight flex items-center gap-2"><Shield className="size-6 text-primary" /> Admin panel</h1>
        <p className="text-muted-foreground text-sm mt-1">Manage site-wide settings and users.</p>
      </header>

      <Card>
        <CardHeader><CardTitle className="text-base">Site settings</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5"><Label>Site name</Label><Input value={siteName} onChange={(e) => setSiteName(e.target.value)} /></div>
          <label className="flex items-center justify-between border rounded-md px-3 py-2">
            <span className="text-sm">Allow new account registration</span>
            <Switch checked={regEnabled} onCheckedChange={setRegEnabled} />
          </label>
          <div className="flex justify-end"><Button onClick={saveSettings} disabled={busy} className="gradient-brand text-white border-0">Save</Button></div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Users ({users.length})</CardTitle></CardHeader>
        <CardContent className="divide-y">
          {users.map((u) => {
            const admin = u.roles.includes("admin");
            return (
              <div key={u.id} className="py-3 flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="font-medium truncate">{u.full_name || u.username || u.email}</div>
                  <div className="text-xs text-muted-foreground truncate">{u.email}</div>
                </div>
                {admin && <Badge variant="default">Admin</Badge>}
                <Button size="sm" variant="outline" onClick={() => toggleAdmin(u.id, admin)}>
                  {admin ? "Remove admin" : "Make admin"}
                </Button>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Alert>
        <AlertDescription className="text-xs">
          Backups exported from the Backup page are end-to-end encrypted. Only the user holding the matching master password can decrypt them.
        </AlertDescription>
      </Alert>
    </div>
  );
}
