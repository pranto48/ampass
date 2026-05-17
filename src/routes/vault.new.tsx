import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { encryptVaultItem, type VaultItemType, type VaultItemData } from "@/lib/vault";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { PasswordStrength } from "@/components/PasswordStrength";
import { logAudit } from "@/lib/audit";
import { generatePassword } from "@/lib/vault";
import { ArrowLeft, Eye, EyeOff, Wand2, Save } from "lucide-react";

export const Route = createFileRoute("/vault/new")({
  component: () => (<RequireUnlocked><AppLayout><NewItem /></AppLayout></RequireUnlocked>),
});

const TYPES: { value: VaultItemType; label: string }[] = [
  { value: "login", label: "Login credential" },
  { value: "note", label: "Secure note" },
  { value: "identity", label: "Identity" },
  { value: "card", label: "Payment card" },
  { value: "wifi", label: "Wi-Fi password" },
  { value: "ssh", label: "Server / SSH" },
  { value: "license", label: "Software license" },
  { value: "bank", label: "Bank account" },
  { value: "custom", label: "Custom item" },
];

function NewItem() {
  const { vaultKey, userId } = useAuth();
  const router = useRouter();
  const [type, setType] = React.useState<VaultItemType>("login");
  const [folderId, setFolderId] = React.useState<string>("none");
  const [folders, setFolders] = React.useState<{ id: string; name: string }[]>([]);
  const [favorite, setFavorite] = React.useState(false);
  const [tags, setTags] = React.useState("");
  const [data, setData] = React.useState<VaultItemData>({ title: "" });
  const [show, setShow] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (!userId) return;
    supabase.from("folders").select("id,name").eq("user_id", userId).order("name")
      .then(({ data }) => setFolders((data ?? []) as { id: string; name: string }[]));
  }, [userId]);

  const save = async () => {
    if (!vaultKey || !userId) return;
    if (!data.title.trim()) { toast.error("Title is required"); return; }
    setBusy(true);
    try {
      const { ciphertext, iv } = await encryptVaultItem(vaultKey, data);
      const { data: row, error } = await supabase
        .from("vault_items")
        .insert({
          user_id: userId,
          folder_id: folderId === "none" ? null : folderId,
          item_type: type,
          favorite,
          tags: tags.split(",").map((s) => s.trim()).filter(Boolean),
          ciphertext, iv,
        })
        .select("id")
        .single();
      if (error) throw error;
      await logAudit(userId, "vault.create", row.id, { item_type: type });
      toast.success("Saved");
      router.navigate({ to: "/vault" });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save");
    } finally { setBusy(false); }
  };

  const upd = (k: keyof VaultItemData, v: string) => setData((d) => ({ ...d, [k]: v }));
  const genPw = () => {
    const pw = generatePassword({ length: 20, upper: true, lower: true, numbers: true, symbols: true, avoidAmbiguous: true });
    upd("password", pw); setShow(true);
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <Button variant="ghost" size="sm" onClick={() => router.history.back()}><ArrowLeft className="size-4 mr-2" /> Back</Button>
      <Card>
        <CardHeader><CardTitle>New vault item</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <FieldRow label="Type">
              <Select value={type} onValueChange={(v) => setType(v as VaultItemType)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>{TYPES.map((t) => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}</SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="Folder">
              <Select value={folderId} onValueChange={setFolderId}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No folder</SelectItem>
                  {folders.map((f) => <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </FieldRow>
          </div>

          <FieldRow label="Title *"><Input value={data.title} onChange={(e) => upd("title", e.target.value)} placeholder="e.g. GitHub" /></FieldRow>

          {(type === "login" || type === "ssh" || type === "wifi" || type === "custom") && (
            <>
              <FieldRow label="Website / URL"><Input value={data.url ?? ""} onChange={(e) => upd("url", e.target.value)} placeholder="https://" /></FieldRow>
              <FieldRow label="Username / email"><Input value={data.username ?? ""} onChange={(e) => upd("username", e.target.value)} autoComplete="off" /></FieldRow>
              <FieldRow label="Password">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Input type={show ? "text" : "password"} value={data.password ?? ""} onChange={(e) => upd("password", e.target.value)} autoComplete="off" className="pr-10" />
                    <button type="button" onClick={() => setShow((s) => !s)} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground">
                      {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </button>
                  </div>
                  <Button type="button" variant="outline" onClick={genPw} title="Generate"><Wand2 className="size-4" /></Button>
                </div>
                <PasswordStrength value={data.password ?? ""} className="mt-2" />
              </FieldRow>
            </>
          )}

          <FieldRow label="Notes"><Textarea rows={4} value={data.notes ?? ""} onChange={(e) => upd("notes", e.target.value)} /></FieldRow>
          <FieldRow label="Tags (comma-separated)"><Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="work, personal" /></FieldRow>

          <div className="flex items-center gap-3">
            <Switch checked={favorite} onCheckedChange={setFavorite} id="fav" />
            <Label htmlFor="fav">Mark as favorite</Label>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => router.history.back()}>Cancel</Button>
            <Button onClick={save} disabled={busy} className="gradient-brand text-white border-0">
              <Save className="size-4 mr-2" /> {busy ? "Saving…" : "Save"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="space-y-1.5"><Label>{label}</Label>{children}</div>;
}
