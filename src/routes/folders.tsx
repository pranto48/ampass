import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { toast } from "sonner";
import { Plus, FolderOpen, Trash2 } from "lucide-react";

export const Route = createFileRoute("/folders")({
  component: () => (<RequireUnlocked><AppLayout><FoldersPage /></AppLayout></RequireUnlocked>),
});

interface Folder { id: string; name: string; color: string }

function FoldersPage() {
  const { userId } = useAuth();
  const [folders, setFolders] = React.useState<Folder[]>([]);
  const [name, setName] = React.useState("");
  const [color, setColor] = React.useState("#6366f1");

  const load = React.useCallback(async () => {
    if (!userId) return;
    const { data } = await supabase.from("folders").select("*").eq("user_id", userId).order("name");
    setFolders((data ?? []) as Folder[]);
  }, [userId]);
  React.useEffect(() => { void load(); }, [load]);

  const add = async () => {
    if (!userId || !name.trim()) return;
    const { error } = await supabase.from("folders").insert({ user_id: userId, name: name.trim(), color });
    if (error) { toast.error(error.message); return; }
    setName(""); void load();
  };

  const del = async (id: string) => {
    const { error } = await supabase.from("folders").delete().eq("id", id);
    if (error) { toast.error(error.message); return; }
    void load();
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Folders</h1>
        <p className="text-muted-foreground text-sm mt-1">Organize your vault items into categories.</p>
      </header>

      <Card>
        <CardContent className="p-4 flex flex-wrap gap-2 items-end">
          <div className="flex-1 min-w-[200px]">
            <Input placeholder="Folder name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <Input type="color" value={color} onChange={(e) => setColor(e.target.value)} className="w-16 p-1" />
          <Button onClick={add} className="gradient-brand text-white border-0"><Plus className="size-4 mr-2" /> Add</Button>
        </CardContent>
      </Card>

      <div className="grid gap-2">
        {folders.length === 0 && <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">No folders yet.</CardContent></Card>}
        {folders.map((f) => (
          <Card key={f.id}>
            <CardContent className="p-3 flex items-center gap-3">
              <div className="size-8 rounded-md grid place-items-center" style={{ backgroundColor: f.color + "22", color: f.color }}>
                <FolderOpen className="size-4" />
              </div>
              <div className="flex-1 font-medium truncate">{f.name}</div>
              <Button size="icon" variant="ghost" onClick={() => del(f.id)}><Trash2 className="size-4 text-destructive" /></Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
