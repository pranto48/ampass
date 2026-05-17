import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { decryptVaultItem, encryptVaultItem, type VaultItemRow, type VaultItemData } from "@/lib/vault";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { logAudit } from "@/lib/audit";
import { ArrowLeft, Eye, EyeOff, Trash2, Save, Share2, ExternalLink, Copy } from "lucide-react";
import { PasswordStrength } from "@/components/PasswordStrength";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";

export const Route = createFileRoute("/vault/$id")({
  component: () => (<RequireUnlocked><AppLayout><EditItem /></AppLayout></RequireUnlocked>),
});

function EditItem() {
  const { id } = Route.useParams();
  const { vaultKey, userId } = useAuth();
  const router = useRouter();
  const [row, setRow] = React.useState<VaultItemRow | null>(null);
  const [data, setData] = React.useState<VaultItemData>({ title: "" });
  const [favorite, setFavorite] = React.useState(false);
  const [tags, setTags] = React.useState("");
  const [show, setShow] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [readOnly, setReadOnly] = React.useState(false);

  React.useEffect(() => {
    if (!vaultKey || !userId) return;
    (async () => {
      const { data: r, error } = await supabase.from("vault_items").select("*").eq("id", id).maybeSingle();
      if (error || !r) { toast.error("Item not found"); router.navigate({ to: "/vault" }); return; }
      const item = r as VaultItemRow;
      setRow(item);
      setReadOnly(item.user_id !== userId);
      const dec = await decryptVaultItem(vaultKey, item);
      setData(dec.data);
      setFavorite(dec.favorite);
      setTags(dec.tags.join(", "));
      if (userId === item.user_id) {
        supabase.from("vault_items").update({ last_used_at: new Date().toISOString() }).eq("id", id).then(() => {});
      }
      await logAudit(userId, "vault.view", id);
    })();
  }, [id, vaultKey, userId, router]);

  const upd = (k: keyof VaultItemData, v: string) => setData((d) => ({ ...d, [k]: v }));

  const save = async () => {
    if (!vaultKey || !row || !userId) return;
    if (!data.title.trim()) { toast.error("Title required"); return; }
    setBusy(true);
    try {
      const { ciphertext, iv } = await encryptVaultItem(vaultKey, data);
      const { error } = await supabase.from("vault_items").update({
        ciphertext, iv, favorite, tags: tags.split(",").map((s) => s.trim()).filter(Boolean),
      }).eq("id", row.id);
      if (error) throw error;
      await logAudit(userId, "vault.update", row.id);
      toast.success("Saved");
      router.navigate({ to: "/vault" });
    } catch (e) { toast.error(e instanceof Error ? e.message : "Failed"); }
    finally { setBusy(false); }
  };

  const del = async () => {
    if (!row || !userId) return;
    const { error } = await supabase.from("vault_items").delete().eq("id", row.id);
    if (error) { toast.error(error.message); return; }
    await logAudit(userId, "vault.delete", row.id);
    toast.success("Deleted");
    router.navigate({ to: "/vault" });
  };

  const copy = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied — clears in 30s`);
    if (label === "Password" && userId && row) await logAudit(userId, "vault.copy_password", row.id);
    setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30_000);
  };

  if (!row) return <div className="text-sm text-muted-foreground">Loading…</div>;

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.history.back()}><ArrowLeft className="size-4 mr-2" /> Back</Button>
        {!readOnly && (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="sm" className="text-destructive"><Trash2 className="size-4 mr-2" /> Delete</Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete this item?</AlertDialogTitle>
                <AlertDialogDescription>This permanently removes the encrypted record. This cannot be undone.</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={del} className="bg-destructive text-destructive-foreground">Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      </div>

      {readOnly && (
        <Alert><AlertDescription>This item is shared with you (read-only).</AlertDescription></Alert>
      )}

      <Card>
        <CardHeader><CardTitle>Edit item</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <Row label="Title"><Input value={data.title} onChange={(e) => upd("title", e.target.value)} disabled={readOnly} /></Row>
          <Row label="Website / URL">
            <div className="flex gap-2">
              <Input value={data.url ?? ""} onChange={(e) => upd("url", e.target.value)} disabled={readOnly} />
              {data.url && (
                <Button asChild variant="outline" size="icon"><a href={normalize(data.url)} target="_blank" rel="noopener noreferrer"><ExternalLink className="size-4" /></a></Button>
              )}
            </div>
          </Row>
          <Row label="Username / email">
            <div className="flex gap-2">
              <Input value={data.username ?? ""} onChange={(e) => upd("username", e.target.value)} disabled={readOnly} />
              {data.username && <Button variant="outline" size="icon" onClick={() => copy(data.username!, "Username")}><Copy className="size-4" /></Button>}
            </div>
          </Row>
          <Row label="Password">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input type={show ? "text" : "password"} value={data.password ?? ""} onChange={(e) => upd("password", e.target.value)} disabled={readOnly} className="pr-10" />
                <button type="button" onClick={() => setShow((s) => !s)} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground">
                  {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
              {data.password && <Button variant="outline" size="icon" onClick={() => copy(data.password!, "Password")}><Copy className="size-4" /></Button>}
            </div>
            <PasswordStrength value={data.password ?? ""} className="mt-2" />
          </Row>
          <Row label="Notes"><Textarea rows={4} value={data.notes ?? ""} onChange={(e) => upd("notes", e.target.value)} disabled={readOnly} /></Row>
          <Row label="Tags"><Input value={tags} onChange={(e) => setTags(e.target.value)} disabled={readOnly} /></Row>
          {!readOnly && (
            <div className="flex items-center gap-3">
              <Switch checked={favorite} onCheckedChange={setFavorite} id="fav" />
              <Label htmlFor="fav">Favorite</Label>
            </div>
          )}

          {!readOnly && (
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => router.navigate({ to: "/shared" })}><Share2 className="size-4 mr-2" /> Manage sharing</Button>
              <Button onClick={save} disabled={busy} className="gradient-brand text-white border-0"><Save className="size-4 mr-2" /> {busy ? "Saving…" : "Save"}</Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="space-y-1.5"><Label>{label}</Label>{children}</div>;
}
function normalize(u: string) { return u.startsWith("http") ? u : `https://${u}`; }
