import { createFileRoute, Link } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { decryptVaultItem, type VaultItemRow } from "@/lib/vault";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { Share2, Users, Info } from "lucide-react";
import { logAudit } from "@/lib/audit";

export const Route = createFileRoute("/shared")({
  component: () => (<RequireUnlocked><AppLayout><SharedPage /></AppLayout></RequireUnlocked>),
});

interface ShareRow {
  id: string; item_id: string; owner_id: string; shared_with_id: string;
  permission: string; revoked: boolean; created_at: string;
}

function SharedPage() {
  const { userId, vaultKey } = useAuth();
  const [shared, setShared] = React.useState<{ row: ShareRow; title: string }[]>([]);
  const [outgoing, setOutgoing] = React.useState<ShareRow[]>([]);

  const load = React.useCallback(async () => {
    if (!userId || !vaultKey) return;
    const [inRes, outRes] = await Promise.all([
      supabase.from("shared_items").select("*, vault_items!inner(*)").eq("shared_with_id", userId).eq("revoked", false),
      supabase.from("shared_items").select("*").eq("owner_id", userId),
    ]);
    const inList: { row: ShareRow; title: string }[] = [];
    for (const r of (inRes.data ?? []) as (ShareRow & { vault_items: VaultItemRow })[]) {
      try {
        const dec = await decryptVaultItem(vaultKey, r.vault_items);
        inList.push({ row: r, title: dec.data.title });
      } catch { inList.push({ row: r, title: "(unable to decrypt)" }); }
    }
    setShared(inList);
    setOutgoing((outRes.data ?? []) as ShareRow[]);
  }, [userId, vaultKey]);

  React.useEffect(() => { void load(); }, [load]);

  const revoke = async (id: string) => {
    const { error } = await supabase.from("shared_items").update({ revoked: true }).eq("id", id);
    if (error) { toast.error(error.message); return; }
    if (userId) await logAudit(userId, "share.revoke", id);
    toast.success("Revoked"); void load();
  };

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Shared</h1>
        <p className="text-muted-foreground text-sm mt-1">Credentials shared with you and by you.</p>
      </header>

      <Alert>
        <Info className="size-4" />
        <AlertDescription>
          End-to-end encrypted sharing using recipient public keys is enabled in the database schema. The UI currently
          supports listing and revoking shares; the encrypted key-exchange flow is wired into the audit log and will be
          completed in the next iteration. For now, recipients with the same vault key context can decrypt items shared
          with them.
        </AlertDescription>
      </Alert>

      <Tabs defaultValue="in">
        <TabsList>
          <TabsTrigger value="in"><Users className="size-4 mr-2" /> Shared with me ({shared.length})</TabsTrigger>
          <TabsTrigger value="out"><Share2 className="size-4 mr-2" /> Shared by me ({outgoing.filter((s) => !s.revoked).length})</TabsTrigger>
        </TabsList>
        <TabsContent value="in" className="space-y-2 mt-4">
          {shared.length === 0 && <Empty msg="Nothing has been shared with you yet." />}
          {shared.map((s) => (
            <Card key={s.row.id}>
              <CardContent className="p-3 flex items-center gap-3">
                <div className="size-8 rounded-md bg-primary/10 text-primary grid place-items-center"><Share2 className="size-4" /></div>
                <div className="flex-1 min-w-0">
                  <div className="font-medium truncate">{s.title}</div>
                  <div className="text-xs text-muted-foreground">{s.row.permission} • {new Date(s.row.created_at).toLocaleDateString()}</div>
                </div>
                <Link to="/vault/$id" params={{ id: s.row.item_id }}><Button size="sm" variant="outline">Open</Button></Link>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
        <TabsContent value="out" className="space-y-2 mt-4">
          {outgoing.length === 0 && <Empty msg="You haven't shared anything." />}
          {outgoing.map((s) => (
            <Card key={s.id}>
              <CardContent className="p-3 flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="text-sm">Item: <span className="font-mono text-xs">{s.item_id.slice(0,8)}…</span></div>
                  <div className="text-xs text-muted-foreground">{s.permission} • {s.revoked ? "Revoked" : "Active"}</div>
                </div>
                {!s.revoked && <Button size="sm" variant="outline" onClick={() => revoke(s.id)}>Revoke</Button>}
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Empty({ msg }: { msg: string }) {
  return <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">{msg}</CardContent></Card>;
}
