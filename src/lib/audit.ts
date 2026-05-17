import { supabase } from "@/integrations/supabase/client";

export type AuditAction =
  | "vault.create"
  | "vault.update"
  | "vault.delete"
  | "vault.view"
  | "vault.copy_password"
  | "share.create"
  | "share.revoke"
  | "master.unlock"
  | "master.setup"
  | "master.failed"
  | "auth.signin"
  | "auth.signout"
  | "settings.update"
  | "backup.export"
  | "backup.import";

export async function logAudit(
  userId: string,
  action: AuditAction,
  targetId?: string | null,
  metadata: Record<string, unknown> = {},
) {
  // Fire-and-forget; never block UX on audit.
  try {
    await supabase.from("audit_logs").insert({
      user_id: userId,
      action,
      target_id: targetId ?? null,
      metadata: metadata as never,
    });
  } catch (e) {
    console.warn("[audit] failed", e);
  }
}
