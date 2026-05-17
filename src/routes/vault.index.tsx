import { createFileRoute, Link } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { decryptVaultItem, type VaultItemRow, type DecryptedVaultItem } from "@/lib/vault";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { Plus, Search, Star, Copy, ExternalLink, KeyRound } from "lucide-react";
import { logAudit } from "@/lib/audit";

export const Route = createFileRoute("/vault/")({
  component: () => (<RequireUnlocked><AppLayout><VaultList /></AppLayout></RequireUnlocked>),
});

interface Folder { id: string; name: string; color: string }

function VaultList() {
  const { vaultKey, userId } = useAuth();
  const [items, setItems] = React.useState<DecryptedVaultItem[] | null>(null);
  const [folders, setFolders] = React.useState<Folder[]>([]);
  const [q, setQ] = React.useState("");
  const [folder, setFolder] = React.useState("all");
  const [favOnly, setFavOnly] = React.useState(false);

  React.useEffect(() => {
    if (!vaultKey || !userId) return;
    (async () => {
      const [v, fRes] = await Promise.all([
        supabase.from("vault_items").select("*").eq("user_id", userId).order("updated_at", { ascending: false }),
        supabase.from("folders").select("*").eq("user_id", userId).order("name"),
      ]);
      if (v.error) { toast.error(v.error.message); setItems([]); return; }
      setFolders((fRes.data ?? []) as Folder[]);
      const dec = await Promise.all((v.data as VaultItemRow[]).map((r) => decryptVaultItem(vaultKey, r)));
      setItems(dec);
    })();
  }, [vaultKey, userId]);

  const filtered = React.useMemo(() => {
    if (!items) return null;
    const term = q.trim().toLowerCase();
    return items.filter((i) => {
      if (favOnly && !i.favorite) return false;
      if (folder !== "all" && i.folder_id !== folder) return false;
      if (!term) return true;
      const hay = `${i.data.title} ${i.data.url ?? ""} ${i.data.username ?? ""} ${i.tags.join(" ")}`.toLowerCase();
      return hay.includes(term);
    });
  }, [items, q, folder, favOnly]);

  const copy = async (text: string, label: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} copied — clears in 30s`);
      if (label === "Password" && userId) await logAudit(userId, "vault.copy_password", id);
      setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30_000);
    } catch { toast.error("Couldn't access clipboard"); }
  };

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Vault</h1>
          <p className="text-muted-foreground text-sm mt-1">All your encrypted credentials in one place.</p>
        </div>
        <Link to="/vault/new"><Button className="gradient-brand text-white border-0"><Plus className="size-4 mr-2" /> New item</Button></Link>
      </header>

      <div className="flex gap-2 flex-wrap items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
          <Input placeholder="Search title, URL, username…" value={q} onChange={(e) => setQ(e.target.value)} className="pl-9" />
        </div>
        <Select value={folder} onValueChange={setFolder}>
          <SelectTrigger className="w-44"><SelectValue placeholder="All folders" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All folders</SelectItem>
            {folders.map((f) => <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant={favOnly ? "default" : "outline"} onClick={() => setFavOnly((v) => !v)}>
          <Star className="size-4 mr-2" /> Favorites
        </Button>
      </div>

      {!filtered ? (
        <div className="grid gap-2">{Array.from({length:6}).map((_,i) => <Skeleton key={i} className="h-16" />)}</div>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="py-16 text-center text-muted-foreground">
          <KeyRound className="size-10 mx-auto opacity-40 mb-3" />
          <p>No items match your search.</p>
        </CardContent></Card>
      ) : (
        <div className="grid gap-2">
          {filtered.map((i) => (
            <Card key={i.id} className="hover:shadow-soft transition-shadow">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="size-10 rounded-lg bg-primary/10 text-primary grid place-items-center shrink-0">
                  <KeyRound className="size-5" />
                </div>
                <Link to="/vault/$id" params={{ id: i.id }} className="min-w-0 flex-1">
                  <div className="font-medium truncate flex items-center gap-2">
                    {i.data.title}
                    {i.favorite && <Star className="size-3.5 fill-warning text-warning" />}
                  </div>
                  <div className="text-xs text-muted-foreground truncate">{i.data.username || i.data.url || i.item_type}</div>
                  {i.tags.length > 0 && (
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {i.tags.slice(0,4).map((t) => <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>)}
                    </div>
                  )}
                </Link>
                <div className="flex items-center gap-1">
                  {i.data.username && (
                    <Button size="icon" variant="ghost" title="Copy username" onClick={() => copy(i.data.username!, "Username", i.id)}>
                      <Copy className="size-4" />
                    </Button>
                  )}
                  {i.data.password && (
                    <Button size="icon" variant="ghost" title="Copy password" onClick={() => copy(i.data.password!, "Password", i.id)}>
                      <KeyRound className="size-4" />
                    </Button>
                  )}
                  {i.data.url && (
                    <Button size="icon" variant="ghost" title="Open site" asChild>
                      <a href={normalizeUrl(i.data.url)} target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="size-4" />
                      </a>
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <p className="text-xs text-muted-foreground text-center pt-4">
        Browser-wide autofill requires a browser extension or mobile autofill integration. Use Copy and Launch buttons for now.
      </p>
    </div>
  );
}

function normalizeUrl(u: string) { return u.startsWith("http") ? u : `https://${u}`; }
