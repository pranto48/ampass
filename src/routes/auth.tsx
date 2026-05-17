import { createFileRoute, useRouter } from "@tanstack/react-router";
import * as React from "react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { ShieldCheck, KeyRound } from "lucide-react";

export const Route = createFileRoute("/auth")({ component: AuthPage });

const signinSchema = z.object({
  email: z.string().trim().email("Enter a valid email").max(255),
  password: z.string().min(8, "At least 8 characters").max(200),
});
const signupSchema = signinSchema.extend({
  full_name: z.string().trim().min(1, "Required").max(100),
  username: z.string().trim().min(3, "At least 3 chars").max(40)
    .regex(/^[a-zA-Z0-9_\-]+$/, "Letters, numbers, _ and - only"),
});

function AuthPage() {
  const { session, loading } = useAuth();
  const router = useRouter();
  const [registrationEnabled, setRegistrationEnabled] = React.useState(true);

  React.useEffect(() => {
    supabase.from("app_settings").select("value").eq("key", "registration_enabled").maybeSingle()
      .then(({ data }) => { if (data) setRegistrationEnabled(Boolean(data.value)); });
  }, []);

  React.useEffect(() => {
    if (!loading && session) router.navigate({ to: "/unlock", replace: true });
  }, [session, loading, router]);

  return (
    <div className="min-h-screen grid md:grid-cols-2">
      {/* Brand panel */}
      <div className="hidden md:flex flex-col justify-between p-12 gradient-brand text-white">
        <div className="flex items-center gap-3">
          <div className="size-10 rounded-xl bg-white/15 grid place-items-center backdrop-blur">
            <KeyRound className="size-5" />
          </div>
          <span className="text-xl font-semibold tracking-tight">AMPass</span>
        </div>
        <div className="space-y-4 max-w-md">
          <h1 className="text-4xl font-bold leading-tight tracking-tight">Your vault, encrypted before it leaves your device.</h1>
          <p className="text-white/85 leading-relaxed">
            AMPass uses zero-knowledge AES-256 encryption. Your master password never reaches our servers,
            and neither do your secrets — only ciphertext.
          </p>
        </div>
        <ul className="space-y-2 text-sm text-white/90">
          <li className="flex items-center gap-2"><ShieldCheck className="size-4" /> Client-side AES-GCM encryption</li>
          <li className="flex items-center gap-2"><ShieldCheck className="size-4" /> Auto-lock & breach-aware</li>
          <li className="flex items-center gap-2"><ShieldCheck className="size-4" /> Installable PWA, works offline-locked</li>
        </ul>
      </div>

      <div className="flex items-center justify-center p-6">
        <Card className="w-full max-w-md shadow-elevated">
          <CardHeader>
            <CardTitle>Welcome to AMPass</CardTitle>
            <CardDescription>Sign in to access your encrypted vault.</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="signin">
              <TabsList className="grid grid-cols-2 w-full">
                <TabsTrigger value="signin">Sign in</TabsTrigger>
                <TabsTrigger value="signup" disabled={!registrationEnabled}>
                  {registrationEnabled ? "Create account" : "Registration closed"}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="signin"><SignInForm /></TabsContent>
              <TabsContent value="signup">
                {registrationEnabled ? <SignUpForm /> : (
                  <Alert><AlertDescription>The administrator has disabled new registrations.</AlertDescription></Alert>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function SignInForm() {
  const router = useRouter();
  const f = useForm<z.infer<typeof signinSchema>>({ resolver: zodResolver(signinSchema), defaultValues: { email: "", password: "" } });
  const onSubmit = async (v: z.infer<typeof signinSchema>) => {
    const { error } = await supabase.auth.signInWithPassword(v);
    if (error) { toast.error(error.message); return; }
    toast.success("Signed in");
    router.navigate({ to: "/unlock", replace: true });
  };
  return (
    <form onSubmit={f.handleSubmit(onSubmit)} className="space-y-4 mt-4">
      <Field label="Email" error={f.formState.errors.email?.message}>
        <Input type="email" autoComplete="email" {...f.register("email")} />
      </Field>
      <Field label="Account password" error={f.formState.errors.password?.message}>
        <Input type="password" autoComplete="current-password" {...f.register("password")} />
      </Field>
      <Button type="submit" className="w-full gradient-brand text-white border-0" disabled={f.formState.isSubmitting}>
        Sign in
      </Button>
      <p className="text-xs text-muted-foreground text-center">
        Your account password is separate from your master password. You'll be asked for your master password next.
      </p>
    </form>
  );
}

function SignUpForm() {
  const router = useRouter();
  const f = useForm<z.infer<typeof signupSchema>>({
    resolver: zodResolver(signupSchema),
    defaultValues: { email: "", password: "", full_name: "", username: "" },
  });
  const onSubmit = async (v: z.infer<typeof signupSchema>) => {
    const redirectUrl = `${window.location.origin}/`;
    const { error } = await supabase.auth.signUp({
      email: v.email,
      password: v.password,
      options: {
        emailRedirectTo: redirectUrl,
        data: { full_name: v.full_name, username: v.username },
      },
    });
    if (error) { toast.error(error.message); return; }
    toast.success("Account created — check your email to confirm, then sign in.");
  };
  return (
    <form onSubmit={f.handleSubmit(onSubmit)} className="space-y-3 mt-4">
      <Field label="Full name" error={f.formState.errors.full_name?.message}>
        <Input {...f.register("full_name")} />
      </Field>
      <Field label="Username" error={f.formState.errors.username?.message}>
        <Input {...f.register("username")} />
      </Field>
      <Field label="Email" error={f.formState.errors.email?.message}>
        <Input type="email" {...f.register("email")} />
      </Field>
      <Field label="Account password" error={f.formState.errors.password?.message}>
        <Input type="password" autoComplete="new-password" {...f.register("password")} />
      </Field>
      <Button type="submit" className="w-full gradient-brand text-white border-0" disabled={f.formState.isSubmitting}>
        Create account
      </Button>
    </form>
  );
}

function Field({ label, error, children }: { label: string; error?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
