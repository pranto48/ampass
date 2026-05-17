import { scorePassword } from "@/lib/vault";
import { cn } from "@/lib/utils";

const BAR_COLORS = [
  "bg-destructive",
  "bg-destructive/80",
  "bg-warning",
  "bg-success/80",
  "bg-success",
];

export function PasswordStrength({ value, className }: { value: string; className?: string }) {
  const { score, label } = scorePassword(value);
  return (
    <div className={cn("space-y-1", className)}>
      <div className="flex gap-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className={cn("h-1.5 flex-1 rounded-full bg-muted",
            i <= score && BAR_COLORS[score])} />
        ))}
      </div>
      <p className="text-xs text-muted-foreground">{value ? label : "—"}</p>
    </div>
  );
}
