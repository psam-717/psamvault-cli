import { Loader2, Lock } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import {
  type AuthResult,
  ApiError,
  issueRecoveryCodes,
  loginAccount,
  recoverAccount,
  recoveryCodeCount,
  restoreAccount,
} from "./api";
import { Button, Card, Dialog, DialogContent, Input } from "./components/ui";

type Mode = "login" | "recover" | "restore";

const COPY: Record<Mode, { title: string; detail: string }> = {
  login: {
    title: "Sign in",
    detail: "The password stays on this computer. The vault key is not sent to the page.",
  },
  recover: {
    title: "Forgot password",
    detail: "One recovery code sets a new login password. That code is used up. Your entries stay encrypted with the same key.",
  },
  restore: {
    title: "Restore this machine",
    detail: "Use this on a new or wiped computer. A backup passphrase, or a recovery kit file, unlocks the same vault. Entries are not re-uploaded.",
  },
};

function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="block space-y-1.5 text-sm">
      <span className="text-sm font-medium">{label}</span>
      {children}
    </label>
  );
}

export function AuthScreen({
  onSignedIn,
  onAlreadySignedIn,
  compact = false,
}: {
  onSignedIn: (result: AuthResult) => void;
  onAlreadySignedIn?: () => void;
  compact?: boolean;
}) {
  const [mode, setMode] = useState<Mode>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [kitName, setKitName] = useState("");
  const [kit, setKit] = useState("");
  const [generateCodes, setGenerateCodes] = useState(true);
  const [replaceSession, setReplaceSession] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  function clearSecrets() {
    setPassword("");
    setPassphrase("");
    setConfirm("");
    setRecoveryCode("");
    setKit("");
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending) return;
    setPending(true);
    setError("");
    try {
      const result =
        mode === "login"
          ? await loginAccount(username, password)
          : mode === "recover"
            ? await recoverAccount({
                username,
                recovery_code: recoveryCode,
                new_password: password,
                confirm,
              })
            : await restoreAccount({
                username,
                passphrase,
                new_password: password,
                confirm,
                kit,
                generate_codes: generateCodes,
                replace_session: replaceSession,
              });
      clearSecrets();
      onSignedIn(result);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed");
    } finally {
      setPending(false);
    }
  }

  async function readKit(file: File | undefined) {
    if (!file) {
      setKit("");
      setKitName("");
      return;
    }
    if (file.size > 256_000) {
      setError("That kit file is too large.");
      return;
    }
    setKit(await file.text());
    setKitName(file.name);
    setError("");
  }

  const copy = COPY[mode];

  return (
    <Card className={compact ? "p-4" : "w-full max-w-md p-8"}>
      {!compact && (
        <div className="mb-6 flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Lock className="size-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">psamvault</h1>
            <p className="text-sm text-muted-foreground">{copy.title}</p>
          </div>
        </div>
      )}
      <div className="mb-4 flex gap-2">
        {(
          [
            ["login", "Sign in"],
            ["recover", "Forgot password"],
            ["restore", "Restore"],
          ] as const
        ).map(([id, label]) => (
          <Button
            key={id}
            type="button"
            size="sm"
            variant={mode === id ? "default" : "outline"}
            onClick={() => {
              setMode(id);
              setError("");
            }}
          >
            {label}
          </Button>
        ))}
      </div>
      <p className="mb-4 text-sm text-muted-foreground">{copy.detail}</p>
      <form className="space-y-3" onSubmit={(event) => void submit(event)}>
        {mode !== "restore" && (
          <Field label="Username">
            <Input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
            />
          </Field>
        )}
        {mode === "restore" && !kit && (
          <Field label="Username">
            <Input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
            />
          </Field>
        )}
        {mode === "recover" && (
          <Field label="Recovery code">
            <Input
              value={recoveryCode}
              onChange={(event) => setRecoveryCode(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="ABCD-EF01-2345"
              required
            />
          </Field>
        )}
        {mode === "restore" && (
          <>
            <Field label="Backup passphrase">
              <Input
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>
            <Field label="Recovery kit (optional)">
              <Input
                type="file"
                accept="application/json,.json"
                onChange={(event) => void readKit(event.target.files?.[0])}
              />
              {kitName && <p className="text-xs text-muted-foreground">{kitName}</p>}
            </Field>
          </>
        )}
        <Field label={mode === "login" ? "Login password" : "New login password"}>
          <Input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
          />
        </Field>
        {mode !== "login" && (
          <Field label="Confirm new login password">
            <Input
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              required
            />
          </Field>
        )}
        {mode === "restore" && (
          <>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={generateCodes}
                onChange={(event) => setGenerateCodes(event.target.checked)}
              />
              Generate 8 new recovery codes after restore
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={replaceSession}
                onChange={(event) => setReplaceSession(event.target.checked)}
              />
              Replace a session already on this machine
            </label>
          </>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Button className="w-full" type="submit" disabled={pending}>
          {pending && <Loader2 className="animate-spin" />}
          {mode === "login" ? "Sign in" : mode === "recover" ? "Reset password" : "Restore and sign in"}
        </Button>
      </form>
      {mode === "login" && onAlreadySignedIn && (
        <Button className="mt-3 w-full" type="button" variant="outline" onClick={onAlreadySignedIn}>
          I've already signed in with pv login
        </Button>
      )}
      <p className="mt-4 text-xs text-muted-foreground">
        A brand-new account still starts in the terminal with <span className="font-mono">pv configure</span> and{" "}
        <span className="font-mono">pv signup</span>. An account from before the master-password change uses{" "}
        <span className="font-mono">pv migrate</span>.
      </p>
    </Card>
  );
}

export function CodeList({ codes }: { codes: string[] }) {
  return (
    <ol className="space-y-1 rounded-md bg-muted p-3 font-mono text-sm">
      {codes.map((code, index) => (
        <li key={code}>
          {index + 1}. {code}
        </li>
      ))}
    </ol>
  );
}

export function RecoveryCodesDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [remaining, setRemaining] = useState<number | null>(null);
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) {
      setPassword("");
      setCodes(null);
      setError("");
      return;
    }
    void recoveryCodeCount()
      .then((body) => setRemaining(body.remaining))
      .catch((caught) => {
        if (caught instanceof ApiError && caught.recovery === "session") {
          setError(caught.message);
          return;
        }
        setError(caught instanceof Error ? caught.message : "Could not check recovery codes");
      });
  }, [open]);

  async function replaceCodes(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const body = await issueRecoveryCodes(password);
      setPassword("");
      setCodes(body.codes);
      setRemaining(body.codes.length);
      toast.success("New recovery codes stored. Write them down now.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not store recovery codes");
    } finally {
      setPending(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Recovery codes">
        <p className="mb-3 text-sm text-muted-foreground">
          {remaining === null
            ? "Checking how many codes are left."
            : `${remaining} of 8 recovery codes remaining. Replacing them invalidates the old set.`}
        </p>
        {codes ? (
          <>
            <CodeList codes={codes} />
            <p className="mt-3 text-sm text-muted-foreground">
              Each code works once. This list is not saved in the browser.
            </p>
          </>
        ) : (
          <form className="space-y-3" onSubmit={(event) => void replaceCodes(event)}>
            <Field label="Current login password">
              <Input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              Replace recovery codes
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
