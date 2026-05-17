import { createFileRoute, Link } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { decryptVaultItem, type VaultItemRow, type DecryptedVaultItem } from "@/lib/vault";
import { scorePassword } from "@/lib/vault";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { KeyRound, Plus, Wand2, Star, AlertTriangle, Repeat2, Clock, ShieldCheck } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

export const Route = createFileRoute("/dashboard")({
  component: () => (<RequireUnlocked><AppLayout><DashboardPage /></AppLayout></RequireUnlocked>),
});

function DashboardPage() {
  const { vaultKey, userId } = useAuth();
  const [items, setItems] = React.useState<DecryptedVaultItem[] | null>(null);

  React.useEffect(() => {
    if (!vaultKey || !userId) return;
    (async () => {
      const { data, error } = await supabase
        .from("vault_items")
        .select("*")
        .eq("user_id", userId)
        .order("updated_at", { ascending: false });
      if (error) { console.error(error); setItems([]); return; }
      const decrypted = await Promise.all((data as VaultItemRow[]).map((r) => decryptVaultItem(vaultKey, r)));
      setItems(decrypted);
    })();
  }, [vaultKey, userId]);

  const stats = React.useMemo(() => {
    if (!items) return null;
    const passwords = items.filter((i) => i.data.password);
    const weak = passwords.filter((i) => scorePassword(i.data.password!).score < 2).length;
    const seen = new Map<string, number>();
    passwords.forEach((i) => { const p = i.data.password!; seen.set(p, (seen.get(p) ?? 0) + 1); });
    const reused = passwords.filter((i) => (seen.get(i.data.password!) ?? 0) > 1).length;
    const favorites = items.filter((i) => i.favorite).length;
    const recent = [...items].sort((a, b) =>
      (b.last_used_at ?? b.updated_at).localeCompare(a.last_used_at ?? a.updated_at)).slice(0, 5);

    const total = passwords.length || 1;
    const score = Math.max(0, Math.round(100 - (weak / total) * 50 - (reused / total) * 50));
    return { total: items.length, weak, reused, favorites, recent, score };
  }, [items]);

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">Your encrypted vault at a glance.</p>
        </div>
        <div className="flex gap-2">
          <Link to="/generator"><Button variant="outline"><Wand2 className="size-4 mr-2" /> Generator</Button></Link>
          <Link to="/vault/new"><Button className="gradient-brand text-white border-0"><Plus className="size-4 mr-2" /> New item</Button></Link>
        </div>
      </header>

      {!stats ? (
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Stat label="Vault items" value={stats.total} icon={KeyRound} />
            <Stat label="Weak passwords" value={stats.weak} icon={AlertTriangle} tone={stats.weak ? "warn" : undefined} />
            <Stat label="Reused" value={stats.reused} icon={Repeat2} tone={stats.reused ? "warn" : undefined} />
            <Stat label="Favorites" value={stats.favorites} icon={Star} />
          </div>

          <Card>
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-base">Security score</CardTitle>
                <p className="text-sm text-muted-foreground">Based on password strength & reuse.</p>
              </div>
              <div className="flex items-center gap-2 text-2xl font-bold">
                <ShieldCheck className="size-6 text-primary" /> {stats.score}
              </div>
            </CardHeader>
            <CardContent><Progress value={stats.score} /></CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-base flex items-center gap-2"><Clock className="size-4" /> Recently updated</CardTitle></CardHeader>
            <CardContent className="divide-y">
              {stats.recent.length === 0 && <p className="text-sm text-muted-foreground py-4">Your vault is empty. Add your first credential.</p>}
              {stats.recent.map((item) => (
                <Link key={item.id} to="/vault/$id" params={{ id: item.id }}
                  className="flex items-center justify-between py-3 hover:bg-accent/40 -mx-2 px-2 rounded">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="size-8 rounded-md bg-muted grid place-items-center"><KeyRound className="size-4 text-muted-foreground" /></div>
                    <div className="min-w-0">
                      <div className="font-medium truncate">{item.data.title}</div>
                      <div className="text-xs text-muted-foreground truncate">{item.data.username || item.data.url || item.item_type}</div>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground hidden sm:block">{new Date(item.updated_at).toLocaleDateString()}</div>
                </Link>
              ))}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, icon: Icon, tone }: { label: string; value: number; icon: React.ComponentType<{className?: string}>; tone?: "warn" }) {
  return (
    <Card>
      <CardContent className="p-5 flex items-center gap-4">
        <div className={`size-10 rounded-lg grid place-items-center ${tone === "warn" ? "bg-warning/15 text-warning" : "bg-primary/10 text-primary"}`}>
          <Icon className="size-5" />
        </div>
        <div>
          <div className="text-2xl font-bold leading-none">{value}</div>
          <div className="text-xs text-muted-foreground mt-1">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}
