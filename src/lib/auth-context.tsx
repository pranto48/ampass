import * as React from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";
import {
  createUserSecurity,
  unlockVault as cryptoUnlock,
} from "./crypto";

interface AuthCtx {
  session: Session | null;
  userId: string | null;
  loading: boolean;
  vaultKey: CryptoKey | null;
  isLocked: boolean;
  needsSetup: boolean;            // user has no user_security row yet
  isAdmin: boolean;
  unlock: (master: string) => Promise<void>;
  setupMaster: (master: string) => Promise<void>;
  lock: () => void;
  signOut: () => Promise<void>;
  refreshSecurity: () => Promise<void>;
}

const Ctx = React.createContext<AuthCtx | null>(null);

const AUTO_LOCK_MS = 15 * 60 * 1000; // 15 min

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = React.useState<Session | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [vaultKey, setVaultKey] = React.useState<CryptoKey | null>(null);
  const [needsSetup, setNeedsSetup] = React.useState(false);
  const [isAdmin, setIsAdmin] = React.useState(false);
  const lockTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const resetAutoLock = React.useCallback(() => {
    if (lockTimer.current) clearTimeout(lockTimer.current);
    lockTimer.current = setTimeout(() => setVaultKey(null), AUTO_LOCK_MS);
  }, []);

  React.useEffect(() => {
    // IMPORTANT: subscribe BEFORE getSession
    const { data: sub } = supabase.auth.onAuthStateChange((_event, s) => {
      setSession(s);
      if (!s) {
        setVaultKey(null);
        setNeedsSetup(false);
        setIsAdmin(false);
      }
    });
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setLoading(false);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  const refreshSecurity = React.useCallback(async () => {
    if (!session) return;
    const [{ data: sec }, { data: roles }] = await Promise.all([
      supabase.from("user_security").select("user_id").eq("user_id", session.user.id).maybeSingle(),
      supabase.from("user_roles").select("role").eq("user_id", session.user.id),
    ]);
    setNeedsSetup(!sec);
    setIsAdmin(!!roles?.some((r) => r.role === "admin"));
  }, [session]);

  React.useEffect(() => {
    if (session) void refreshSecurity();
  }, [session, refreshSecurity]);

  React.useEffect(() => {
    if (!vaultKey) return;
    resetAutoLock();
    const handler = () => resetAutoLock();
    window.addEventListener("mousemove", handler, { passive: true });
    window.addEventListener("keydown", handler);
    return () => {
      window.removeEventListener("mousemove", handler);
      window.removeEventListener("keydown", handler);
    };
  }, [vaultKey, resetAutoLock]);

  const unlock = React.useCallback(
    async (master: string) => {
      if (!session) throw new Error("Not signed in");
      const { data, error } = await supabase
        .from("user_security")
        .select("*")
        .eq("user_id", session.user.id)
        .maybeSingle();
      if (error) throw error;
      if (!data) {
        setNeedsSetup(true);
        throw new Error("No vault initialized. Set a master password first.");
      }
      const key = await cryptoUnlock(master, data);
      setVaultKey(key);
    },
    [session],
  );

  const setupMaster = React.useCallback(
    async (master: string) => {
      if (!session) throw new Error("Not signed in");
      const sec = await createUserSecurity(master);
      const { error } = await supabase.from("user_security").insert({
        user_id: session.user.id,
        kdf_salt: sec.saltB64,
        kdf_iterations: sec.iterations,
        verifier_ciphertext: sec.verifier_ciphertext,
        verifier_iv: sec.verifier_iv,
        wrapped_vault_key: sec.wrapped_vault_key,
        wrapped_vault_key_iv: sec.wrapped_vault_key_iv,
      });
      if (error) throw error;
      setVaultKey(sec.vaultKey);
      setNeedsSetup(false);
    },
    [session],
  );

  const lock = React.useCallback(() => setVaultKey(null), []);
  const signOut = React.useCallback(async () => {
    setVaultKey(null);
    await supabase.auth.signOut();
  }, []);

  const value: AuthCtx = {
    session,
    userId: session?.user.id ?? null,
    loading,
    vaultKey,
    isLocked: !vaultKey,
    needsSetup,
    isAdmin,
    unlock,
    setupMaster,
    lock,
    signOut,
    refreshSecurity,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = React.useContext(Ctx);
  if (!v) throw new Error("useAuth must be used inside AuthProvider");
  return v;
}
