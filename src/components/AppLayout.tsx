import * as React from "react";
import { Link, useRouter, useRouterState } from "@tanstack/react-router";
import { useAuth } from "@/lib/auth-context";
import { useTheme } from "@/lib/theme";
import { Button } from "@/components/ui/button";
import {
  LayoutDashboard, KeyRound, FolderOpen, Share2, Shield,
  Settings, Activity, Archive, Lock, LogOut, Sun, Moon, Plus, Wand2, Menu, X,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/vault", label: "Vault", icon: KeyRound },
  { to: "/folders", label: "Folders", icon: FolderOpen },
  { to: "/shared", label: "Shared", icon: Share2 },
  { to: "/generator", label: "Generator", icon: Wand2 },
  { to: "/audit", label: "Audit log", icon: Activity },
  { to: "/backup", label: "Backup", icon: Archive },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

const MOBILE_NAV = [
  { to: "/dashboard", label: "Home", icon: LayoutDashboard },
  { to: "/vault", label: "Vault", icon: KeyRound },
  { to: "/generator", label: "Generate", icon: Wand2 },
  { to: "/shared", label: "Shared", icon: Share2 },
  { to: "/settings", label: "More", icon: Settings },
] as const;

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { signOut, lock, isAdmin } = useAuth();
  const { theme, toggle } = useTheme();
  const router = useRouter();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [openMobile, setOpenMobile] = React.useState(false);

  const isActive = (to: string) => pathname === to || pathname.startsWith(to + "/");

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar (mobile) */}
      <header className="md:hidden sticky top-0 z-30 border-b bg-sidebar/95 backdrop-blur supports-[backdrop-filter]:bg-sidebar/80">
        <div className="flex items-center justify-between px-4 h-14">
          <Link to="/dashboard" className="flex items-center gap-2">
            <Logo />
            <span className="font-semibold tracking-tight">AMPass</span>
          </Link>
          <div className="flex items-center gap-1">
            <Button size="icon" variant="ghost" onClick={toggle} aria-label="Toggle theme">
              {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </Button>
            <Button size="icon" variant="ghost" onClick={lock} aria-label="Lock vault">
              <Lock className="size-4" />
            </Button>
            <Button size="icon" variant="ghost" onClick={() => setOpenMobile((o) => !o)} aria-label="Menu">
              {openMobile ? <X className="size-4" /> : <Menu className="size-4" />}
            </Button>
          </div>
        </div>
        {openMobile && (
          <nav className="border-t bg-sidebar px-2 py-2 grid grid-cols-2 gap-1">
            {NAV.map((n) => (
              <Link key={n.to} to={n.to} onClick={() => setOpenMobile(false)}
                className={cn("flex items-center gap-2 px-3 py-2 rounded-md text-sm",
                  isActive(n.to) ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent")}>
                <n.icon className="size-4" /> {n.label}
              </Link>
            ))}
            {isAdmin && (
              <Link to="/admin" onClick={() => setOpenMobile(false)}
                className={cn("flex items-center gap-2 px-3 py-2 rounded-md text-sm col-span-2",
                  isActive("/admin") ? "bg-sidebar-accent text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent")}>
                <Shield className="size-4" /> Admin panel
              </Link>
            )}
          </nav>
        )}
      </header>

      <div className="md:flex md:min-h-screen">
        {/* Sidebar (desktop) */}
        <aside className="hidden md:flex flex-col w-64 shrink-0 border-r bg-sidebar text-sidebar-foreground">
          <Link to="/dashboard" className="flex items-center gap-2 px-5 h-16 border-b">
            <Logo />
            <span className="font-semibold tracking-tight text-base">AMPass</span>
          </Link>
          <nav className="flex-1 px-3 py-4 space-y-1">
            {NAV.map((n) => (
              <Link key={n.to} to={n.to}
                className={cn("flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                  isActive(n.to) ? "bg-sidebar-accent text-sidebar-accent-foreground"
                                 : "text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground")}>
                <n.icon className="size-4" /> {n.label}
              </Link>
            ))}
            {isAdmin && (
              <Link to="/admin"
                className={cn("flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium",
                  isActive("/admin") ? "bg-sidebar-accent text-sidebar-accent-foreground"
                                     : "text-sidebar-foreground/80 hover:bg-sidebar-accent")}>
                <Shield className="size-4" /> Admin
              </Link>
            )}
          </nav>
          <div className="border-t p-3 space-y-2">
            <Button size="sm" className="w-full justify-start gap-2 gradient-brand text-white border-0"
              onClick={() => router.navigate({ to: "/vault/new" })}>
              <Plus className="size-4" /> New item
            </Button>
            <div className="flex items-center justify-between gap-1">
              <Button size="sm" variant="ghost" onClick={toggle} className="flex-1 justify-start">
                {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
                <span className="ml-2">{theme === "dark" ? "Light" : "Dark"}</span>
              </Button>
              <Button size="icon" variant="ghost" onClick={lock} title="Lock vault">
                <Lock className="size-4" />
              </Button>
              <Button size="icon" variant="ghost" onClick={signOut} title="Sign out">
                <LogOut className="size-4" />
              </Button>
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="flex-1 min-w-0 pb-20 md:pb-0">
          <div className="mx-auto max-w-6xl px-4 md:px-8 py-6 md:py-10">{children}</div>
        </main>
      </div>

      {/* Bottom nav (mobile) */}
      <nav className="md:hidden fixed bottom-0 inset-x-0 z-30 border-t bg-sidebar/95 backdrop-blur">
        <div className="grid grid-cols-5">
          {MOBILE_NAV.map((n) => (
            <Link key={n.to} to={n.to}
              className={cn("flex flex-col items-center gap-1 py-2 text-xs",
                isActive(n.to) ? "text-primary" : "text-sidebar-foreground/70")}>
              <n.icon className="size-5" />
              <span>{n.label}</span>
            </Link>
          ))}
        </div>
      </nav>
    </div>
  );
}

function Logo() {
  return (
    <div className="size-8 rounded-lg gradient-brand grid place-items-center text-white shadow-soft">
      <KeyRound className="size-4" />
    </div>
  );
}
