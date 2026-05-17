import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { Download, Upload, ShieldCheck } from "lucide-react";
import {
  deriveKeyFromPassword, encryptString, decryptString, randomBytes, b64,
} from "@/lib/crypto";
import { decryptVaultItem, encryptVaultItem, type VaultItemRow } from "@/lib/vault";
import { logAudit } from "@/lib/audit";

export const Route = createFileRoute("/backup")({
  component: () => (<RequireUnlocked><AppLayout><BackupPage /></AppLayout></RequireUnlocked>),
});

function BackupPage() {
  const { userId, vaultKey } = useAuth();
  const [exportPw, setExportPw] = React.useState("");
  const [importPw, setImportPw] = React.useState("");
  const [importFile, setImportFile] = React.useState<File | null>(null);
  const [busy, setBusy] = React.useState(false);

  const doExport = async () => {
    if (!userId || !vaultKey) { toast.error("Vault locked"); return; }
    if (exportPw.length < 10) { toast.error("Use a password at least 10 chars"); return; }
    setBusy(true);
    try {
      const { data, error } = await supabase.from("vault_items").select("*").eq("user_id", userId);
      if (error) throw error;
      const rows = (data ?? []) as VaultItemRow[];
      const decrypted = await Promise.all(rows.map((r) => decryptVaultItem(vaultKey, r)));
      const payload = JSON.stringify({ exported_at: new Date().toISOString(), items: decrypted });
      const salt = b64.encode(randomBytes(16));
      const key = await deriveKeyFromPassword(exportPw, salt);
      const enc = await encryptString(key, payload);
      const file = { format: "ampass-encrypted-backup", version: 1, salt, iterations: 250000, iv: enc.iv, ciphertext: enc.ciphertext };
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `ampass-backup-${new Date().toISOString().slice(0,10)}.json`;
      a.click(); URL.revokeObjectURL(a.href);
      await logAudit(userId, "backup.export", null, { count: rows.length });
      toast.success(`Exported ${rows.length} item(s)`);
    } catch (e) { toast.error(e instanceof Error ? e.message : "Failed"); }
    finally { setBusy(false); }
  };

  const doImport = async () => {
    if (!userId || !vaultKey || !importFile) { toast.error("Select a file"); return; }
    setBusy(true);
    try {
      const text = await importFile.text();
      const file = JSON.parse(text);
      if (file.format !== "ampass-encrypted-backup") throw new Error("Not an AMPass backup");
      const key = await deriveKeyFromPassword(importPw, file.salt, file.iterations ?? 250000);
      const decryptedJson = await decryptString(key, file.ciphertext, file.iv);
      const payload = JSON.parse(decryptedJson) as { items: { item_type: string; favorite: boolean; tags: string[]; data: Record<string, unknown> }[] };
      let n = 0;
      for (const it of payload.items) {
        const enc = await encryptVaultItem(vaultKey, it.data as unknown as Parameters<typeof encryptVaultItem>[1]);
        const { error } = await supabase.from("vault_items").insert({
          user_id: userId, item_type: it.item_type as never,
          favorite: !!it.favorite, tags: it.tags ?? [],
          ciphertext: enc.ciphertext, iv: enc.iv,
        });
        if (!error) n++;
      }
      await logAudit(userId, "backup.import", null, { imported: n });
      toast.success(`Imported ${n} item(s)`);
    } catch (e) { toast.error(e instanceof Error ? e.message : "Failed — wrong password or invalid file"); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Encrypted backup</h1>
        <p className="text-muted-foreground text-sm mt-1">Download or restore your entire vault.</p>
      </header>

      <Alert>
        <ShieldCheck className="size-4" />
        <AlertDescription>
          Backups are encrypted with a password you choose, using AES-256-GCM and PBKDF2. Anyone with the file
          and the password can restore your vault — store the file safely.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader><CardTitle className="text-base">Export</CardTitle><CardDescription>Encrypts your vault with the password you choose.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5"><Label>Backup password</Label><Input type="password" value={exportPw} onChange={(e) => setExportPw(e.target.value)} /></div>
          <div className="flex justify-end"><Button onClick={doExport} disabled={busy} className="gradient-brand text-white border-0"><Download className="size-4 mr-2" /> Download backup</Button></div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Import</CardTitle><CardDescription>Restore items from a previously exported file.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5"><Label>Backup file</Label>
            <Input type="file" accept="application/json" onChange={(e) => setImportFile(e.target.files?.[0] ?? null)} />
          </div>
          <div className="space-y-1.5"><Label>Backup password</Label><Input type="password" value={importPw} onChange={(e) => setImportPw(e.target.value)} /></div>
          <div className="flex justify-end"><Button onClick={doImport} disabled={busy} variant="outline"><Upload className="size-4 mr-2" /> Import</Button></div>
        </CardContent>
      </Card>
    </div>
  );
}
