import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { encryptVaultItem } from "@/lib/vault";
import { generatePassword, generatePassphrase, scorePassword, type GenOpts } from "@/lib/vault";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PasswordStrength } from "@/components/PasswordStrength";
import { toast } from "sonner";
import { Copy, RefreshCw, Save } from "lucide-react";

export const Route = createFileRoute("/generator")({
  component: () => (<RequireUnlocked><AppLayout><GeneratorPage /></AppLayout></RequireUnlocked>),
});

function GeneratorPage() {
  const [opts, setOpts] = React.useState<GenOpts>({
    length: 20, upper: true, lower: true, numbers: true, symbols: true, avoidAmbiguous: true,
  });
  const [password, setPassword] = React.useState(() =>
    generatePassword({ length: 20, upper: true, lower: true, numbers: true, symbols: true, avoidAmbiguous: true }));
  const [words, setWords] = React.useState(5);
  const [phrase, setPhrase] = React.useState(() => generatePassphrase(5));

  const regen = () => setPassword(generatePassword(opts));
  React.useEffect(() => { setPassword(generatePassword(opts)); }, [opts]);

  return (
    <div className="space-y-5 max-w-2xl">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Password generator</h1>
        <p className="text-muted-foreground text-sm mt-1">Create strong passwords and passphrases.</p>
      </header>

      <Tabs defaultValue="password">
        <TabsList>
          <TabsTrigger value="password">Password</TabsTrigger>
          <TabsTrigger value="phrase">Passphrase</TabsTrigger>
        </TabsList>

        <TabsContent value="password">
          <Card>
            <CardHeader><CardTitle className="text-base">Generated password</CardTitle></CardHeader>
            <CardContent className="space-y-5">
              <PasswordOutput value={password} onRegen={regen} />

              <div className="space-y-2">
                <div className="flex justify-between"><Label>Length</Label><span className="text-sm text-muted-foreground">{opts.length}</span></div>
                <Slider min={8} max={64} step={1} value={[opts.length]} onValueChange={([v]) => setOpts((o) => ({ ...o, length: v }))} />
              </div>

              <div className="grid sm:grid-cols-2 gap-3">
                <Toggle label="Uppercase A-Z" value={opts.upper} onChange={(v) => setOpts((o) => ({ ...o, upper: v }))} />
                <Toggle label="Lowercase a-z" value={opts.lower} onChange={(v) => setOpts((o) => ({ ...o, lower: v }))} />
                <Toggle label="Numbers 0-9" value={opts.numbers} onChange={(v) => setOpts((o) => ({ ...o, numbers: v }))} />
                <Toggle label="Symbols !@#$" value={opts.symbols} onChange={(v) => setOpts((o) => ({ ...o, symbols: v }))} />
                <Toggle label="Avoid ambiguous (0/O, 1/l)" value={opts.avoidAmbiguous} onChange={(v) => setOpts((o) => ({ ...o, avoidAmbiguous: v }))} />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="phrase">
          <Card>
            <CardHeader><CardTitle className="text-base">Generated passphrase</CardTitle></CardHeader>
            <CardContent className="space-y-5">
              <PasswordOutput value={phrase} onRegen={() => setPhrase(generatePassphrase(words))} />
              <div className="space-y-2">
                <div className="flex justify-between"><Label>Words</Label><span className="text-sm text-muted-foreground">{words}</span></div>
                <Slider min={3} max={10} step={1} value={[words]} onValueChange={([v]) => { setWords(v); setPhrase(generatePassphrase(v)); }} />
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function PasswordOutput({ value, onRegen }: { value: string; onRegen: () => void }) {
  const { vaultKey, userId } = useAuth();
  const router = useRouter();
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    toast.success("Copied — clears in 30s");
    setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30_000);
  };
  const saveAsItem = async () => {
    if (!vaultKey || !userId) { toast.error("Vault locked"); return; }
    const title = prompt("Title for this password?");
    if (!title) return;
    const { ciphertext, iv } = await encryptVaultItem(vaultKey, { title, password: value });
    const { error } = await supabase.from("vault_items").insert({
      user_id: userId, item_type: "login", ciphertext, iv, tags: [],
    });
    if (error) { toast.error(error.message); return; }
    toast.success("Saved to vault");
    router.navigate({ to: "/vault" });
  };
  return (
    <div>
      <div className="flex gap-2">
        <div className="flex-1 rounded-md border bg-muted/40 px-3 py-3 font-mono text-sm break-all">{value || <span className="text-muted-foreground">—</span>}</div>
        <div className="flex flex-col gap-1">
          <Button size="icon" variant="outline" onClick={onRegen} title="Regenerate"><RefreshCw className="size-4" /></Button>
          <Button size="icon" variant="outline" onClick={copy} title="Copy"><Copy className="size-4" /></Button>
        </div>
      </div>
      <PasswordStrength value={value} className="mt-3" />
      <div className="mt-3 flex justify-end">
        <Button onClick={saveAsItem} className="gradient-brand text-white border-0"><Save className="size-4 mr-2" /> Save to vault</Button>
      </div>
    </div>
  );
}
function Toggle({ label, value, onChange }: { label: string; value: boolean; onChange: (v: boolean) => void }) {
  return <label className="flex items-center justify-between border rounded-md px-3 py-2 cursor-pointer hover:bg-accent/40">
    <span className="text-sm">{label}</span><Switch checked={value} onCheckedChange={onChange} />
  </label>;
}
