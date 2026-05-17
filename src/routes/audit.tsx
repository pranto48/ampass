import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { RequireUnlocked } from "@/components/RequireUnlocked";
import { AppLayout } from "@/components/AppLayout";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export const Route = createFileRoute("/audit")({
  component: () => (<RequireUnlocked><AppLayout><AuditPage /></AppLayout></RequireUnlocked>),
});

interface Log { id: string; action: string; target_id: string | null; created_at: string; metadata: Record<string, unknown> }

function AuditPage() {
  const { userId, isAdmin } = useAuth();
  const [logs, setLogs] = React.useState<Log[]>([]);

  React.useEffect(() => {
    if (!userId) return;
    let q = supabase.from("audit_logs").select("*").order("created_at", { ascending: false }).limit(200);
    if (!isAdmin) q = q.eq("user_id", userId);
    q.then(({ data }) => setLogs((data ?? []) as Log[]));
  }, [userId, isAdmin]);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Audit log</h1>
        <p className="text-muted-foreground text-sm mt-1">{isAdmin ? "All security events across the system." : "Your recent security events."}</p>
      </header>
      <Card>
        <CardHeader><CardTitle className="text-base">Last 200 events</CardTitle></CardHeader>
        <CardContent className="divide-y">
          {logs.length === 0 && <p className="text-sm text-muted-foreground py-6 text-center">No events yet.</p>}
          {logs.map((l) => (
            <div key={l.id} className="py-2.5 flex items-center gap-3 text-sm">
              <Badge variant={l.action.includes("failed") ? "destructive" : "secondary"}>{l.action}</Badge>
              {l.target_id && <span className="font-mono text-xs text-muted-foreground">{l.target_id.slice(0,8)}…</span>}
              <div className="flex-1" />
              <span className="text-xs text-muted-foreground">{new Date(l.created_at).toLocaleString()}</span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
