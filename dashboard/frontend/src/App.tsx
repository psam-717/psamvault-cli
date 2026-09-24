import {
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  Moon,
  MoreHorizontal,
  Plus,
  Search,
  Shield,
  Sun,
  Vault,
} from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  addApiKey,
  addEntry,
  type ApiKeyRow,
  type Bootstrap,
  deleteApiKey,
  deleteEntry,
  type Entry,
  getApiKey,
  getEntry,
  loadBootstrap,
  logout,
  revealApiKey,
  revealEntry,
  updateApiKey,
  updateEntry,
  ApiError,
} from "./api";
import {
  Alert,
  AlertDialog,
  AlertDialogContent,
  Avatar,
  AvatarFallback,
  Badge,
  Button,
  Card,
  Dialog,
  DialogContent,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  Empty,
  Input,
  Label,
  ScrollArea,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsList,
  TabsTrigger,
  Textarea,
  Tooltip,
  TooltipProvider,
} from "./components/ui";

type Tab = "entries" | "keys";
type DialogState =
  | { kind: "add-entry" }
  | { kind: "add-key" }
  | { kind: "edit-entry"; site: string }
  | { kind: "edit-key"; name: string }
  | { kind: "view-entry"; entry: Entry }
  | { kind: "view-key"; row: ApiKeyRow }
  | null;
type ConfirmState = { kind: "entry" | "key" | "logout"; name: string } | null;

function initials(name: string) {
  return name.slice(0, 2).toUpperCase() || "PV";
}

export function App() {
  const [data, setData] = useState<Bootstrap | null>(null);
  const [loggedOut, setLoggedOut] = useState(false);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("entries");
  const [query, setQuery] = useState("");
  const [dialog, setDialog] = useState<DialogState>(null);
  const [confirm, setConfirm] = useState<ConfirmState>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [sessionHelp, setSessionHelp] = useState(false);
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));

  async function refresh(force = false) {
    try {
      const body = await loadBootstrap(force);
      setData(body);
      setLoggedOut(false);
      setSessionHelp(body.entries_recovery === "session" || body.api_keys_recovery === "session");
    } catch (error) {
      if (error instanceof ApiError && error.recovery === "session") {
        setSessionHelp(true);
        toast.error(error.message);
        return;
      }
      if (error instanceof ApiError && error.status === 401) {
        setLoggedOut(true);
        setData(null);
        return;
      }
      toast.error(error instanceof Error ? error.message : "Could not load the vault");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  function toggleTheme() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("psamvault-theme", next ? "dark" : "light");
  }

  const entries = data?.entries;
  const keys = data?.api_keys;
  const filteredEntries = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!entries) return [];
    if (!needle) return entries;
    return entries.filter(
      (entry) =>
        entry.site_name.toLowerCase().includes(needle) ||
        entry.username_hint.toLowerCase().includes(needle),
    );
  }, [entries, query]);
  const filteredKeys = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!keys) return [];
    if (!needle) return keys;
    return keys.filter(
      (row) => row.name.toLowerCase().includes(needle) || row.service_hint.toLowerCase().includes(needle),
    );
  }, [keys, query]);

  async function run(id: string, action: () => Promise<void>) {
    if (pending) return;
    setPending(id);
    try {
      await action();
    } catch (error) {
      if (error instanceof ApiError && error.recovery === "session") setSessionHelp(true);
      toast.error(error instanceof Error ? error.message : "Request failed");
    } finally {
      setPending(null);
    }
  }

  if (loading) {
    return (
      <Shell username="" dark={dark} onTheme={toggleTheme} onLogout={() => {}}>
        <div className="space-y-3">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-10 w-64" />
          <Skeleton className="h-64 w-full" />
        </div>
      </Shell>
    );
  }

  if (loggedOut || !data) {
    return (
      <main className="flex min-h-screen items-center justify-center p-6">
        <Card className="w-full max-w-md p-8">
          <div className="mb-6 flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Lock className="size-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold">psamvault</h1>
              <p className="text-sm text-muted-foreground">You are logged out</p>
            </div>
          </div>
          <p className="text-sm text-muted-foreground">
            Sign-in happens in the terminal. This page has no password field. Run this command, then come back
            and click the button.
          </p>
          <pre className="mt-4 rounded-md bg-muted px-3 py-2 font-mono text-sm">pv login</pre>
          <Button className="mt-6 w-full" type="button" onClick={() => void refresh(true)}>
            I've logged in
          </Button>
        </Card>
      </main>
    );
  }

  const searching = query.trim().length > 0;

  return (
    <Shell
      username={data.username}
      dark={dark}
      onTheme={toggleTheme}
      onLogout={() => setConfirm({ kind: "logout", name: "" })}
    >
      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        <Stat icon={<Vault className="size-4" />} label="Vault entries" value={entries ? String(entries.length) : "—"} />
        <Stat icon={<KeyRound className="size-4" />} label="API keys" value={keys ? String(keys.length) : "—"} />
        <Stat icon={<Shield className="size-4" />} label="Vault status" value="Encrypted" />
      </div>

      <Tabs
        value={tab}
        onValueChange={(value) => {
          setTab(value as Tab);
          setQuery("");
        }}
      >
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <TabsList>
            <TabsTrigger value="entries">
              Entries {entries && <Badge>{entries.length}</Badge>}
            </TabsTrigger>
            <TabsTrigger value="keys">
              API keys {keys && <Badge>{keys.length}</Badge>}
            </TabsTrigger>
          </TabsList>
          <div className="flex gap-2">
            <div className="relative min-w-0 flex-1 sm:w-64">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={tab === "entries" ? "Search entries" : "Search API keys"}
                className="pl-8"
                aria-label="Search"
              />
            </div>
            <Button
              type="button"
              onClick={() => setDialog(tab === "entries" ? { kind: "add-entry" } : { kind: "add-key" })}
            >
              <Plus /> Add
            </Button>
          </div>
        </div>

        {sessionHelp && <SessionGuide onRetry={() => void refresh(true)} />}

        {tab === "entries" && data.entries_error && data.entries_recovery !== "session" && (
          <Alert className="mb-4 border-destructive/40 text-destructive">
            <p>{data.entries_error}</p>
            <Button className="mt-3" variant="outline" type="button" onClick={() => void refresh(true)}>
              Retry
            </Button>
          </Alert>
        )}
        {tab === "keys" && data.api_keys_error && data.api_keys_recovery !== "session" && (
          <Alert className="mb-4 border-destructive/40 text-destructive">
            <p>{data.api_keys_error}</p>
            <Button className="mt-3" variant="outline" type="button" onClick={() => void refresh(true)}>
              Retry
            </Button>
          </Alert>
        )}

        <Card>
          <ScrollArea>
            {tab === "entries" && entries && filteredEntries.length === 0 && (
              <Empty
                icon={<Vault className="size-8" />}
                title={searching ? "No matching entries" : "No vault entries yet"}
                description={
                  searching
                    ? "Nothing in the loaded list matches that search."
                    : "Use psamvault add, or Add, to store a credential."
                }
              />
            )}
            {tab === "keys" && keys && filteredKeys.length === 0 && (
              <Empty
                icon={<KeyRound className="size-8" />}
                title={searching ? "No matching API keys" : "No API keys stored"}
                description={
                  searching
                    ? "Nothing in the loaded list matches that search."
                    : "Use psamvault ak-add, or Add, to store a key."
                }
              />
            )}
            {tab === "entries" && filteredEntries.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Site</TableHead>
                    <TableHead>Username</TableHead>
                    <TableHead className="hidden sm:table-cell">Updated</TableHead>
                    <TableHead className="w-12" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEntries.map((entry) => (
                    <TableRow key={entry.site_name}>
                      <TableCell className="font-medium">{entry.site_name}</TableCell>
                      <TableCell className="font-mono text-xs">{entry.username_hint}</TableCell>
                      <TableCell className="hidden text-muted-foreground sm:table-cell">{entry.updated_at}</TableCell>
                      <TableCell>
                        <RowMenu
                          onView={() => setDialog({ kind: "view-entry", entry })}
                          onEdit={() => setDialog({ kind: "edit-entry", site: entry.site_name })}
                          onDelete={() => setConfirm({ kind: "entry", name: entry.site_name })}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {tab === "keys" && filteredKeys.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead className="hidden sm:table-cell">Updated</TableHead>
                    <TableHead className="w-12" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredKeys.map((row) => (
                    <TableRow key={row.name}>
                      <TableCell className="font-medium">{row.name}</TableCell>
                      <TableCell>{row.service_hint}</TableCell>
                      <TableCell className="hidden text-muted-foreground sm:table-cell">{row.updated_at}</TableCell>
                      <TableCell>
                        <RowMenu
                          onView={() => setDialog({ kind: "view-key", row })}
                          onEdit={() => setDialog({ kind: "edit-key", name: row.name })}
                          onDelete={() => setConfirm({ kind: "key", name: row.name })}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </ScrollArea>
        </Card>
      </Tabs>

      {dialog?.kind === "add-entry" && (
        <EntryForm
          title="Add entry"
          pending={pending === "save"}
          onClose={() => setDialog(null)}
          onSubmit={(payload) =>
            run("save", async () => {
              const row = await addEntry(payload);
              setData((current) =>
                current && current.entries
                  ? { ...current, entries: [...current.entries.filter((item) => item.site_name !== row.site_name), row] }
                  : current,
              );
              toast.success(`Saved ${row.site_name}`);
              setDialog(null);
            })
          }
        />
      )}
      {dialog?.kind === "add-key" && (
        <KeyForm
          title="Add API key"
          pending={pending === "save"}
          onClose={() => setDialog(null)}
          onSubmit={(payload) =>
            run("save", async () => {
              const row = await addApiKey(payload);
              setData((current) =>
                current && current.api_keys
                  ? { ...current, api_keys: [...current.api_keys.filter((item) => item.name !== row.name), row] }
                  : current,
              );
              toast.success(`Saved ${row.name}`);
              setDialog(null);
            })
          }
        />
      )}
      {dialog?.kind === "edit-entry" && (
        <EntryEditor
          site={dialog.site}
          pending={pending === "save"}
          onClose={() => setDialog(null)}
          onSubmit={(payload) =>
            run("save", async () => {
              const row = await updateEntry(dialog.site, payload);
              setData((current) =>
                current && current.entries
                  ? { ...current, entries: current.entries.map((item) => (item.site_name === row.site_name ? row : item)) }
                  : current,
              );
              toast.success(`Updated ${row.site_name}`);
              setDialog(null);
            })
          }
        />
      )}
      {dialog?.kind === "edit-key" && (
        <KeyEditor
          name={dialog.name}
          pending={pending === "save"}
          onClose={() => setDialog(null)}
          onSubmit={(payload) =>
            run("save", async () => {
              const row = await updateApiKey(dialog.name, payload);
              setData((current) =>
                current && current.api_keys
                  ? { ...current, api_keys: current.api_keys.map((item) => (item.name === row.name ? row : item)) }
                  : current,
              );
              toast.success(`Updated ${row.name}`);
              setDialog(null);
            })
          }
        />
      )}
      {dialog?.kind === "view-entry" && (
        <EntryDetail entry={dialog.entry} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "view-key" && <KeyDetail row={dialog.row} onClose={() => setDialog(null)} />}

      <AlertDialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        {confirm && (
          <AlertDialogContent
            title={confirm.kind === "logout" ? "Sign out?" : `Delete ${confirm.name}?`}
            description={
              confirm.kind === "logout"
                ? "You will need pv login in the terminal before this page can open the vault again."
                : "This removes the item from the vault. It cannot be undone from the dashboard."
            }
            confirmLabel={confirm.kind === "logout" ? "Sign out" : "Delete"}
            destructive={confirm.kind !== "logout"}
            pending={pending === "confirm"}
            onConfirm={() =>
              run("confirm", async () => {
                if (confirm.kind === "logout") {
                  await logout();
                  setLoggedOut(true);
                  setData(null);
                } else if (confirm.kind === "entry") {
                  await deleteEntry(confirm.name);
                  setData((current) =>
                    current && current.entries
                      ? { ...current, entries: current.entries.filter((item) => item.site_name !== confirm.name) }
                      : current,
                  );
                  toast.success(`Deleted ${confirm.name}`);
                } else {
                  await deleteApiKey(confirm.name);
                  setData((current) =>
                    current && current.api_keys
                      ? { ...current, api_keys: current.api_keys.filter((item) => item.name !== confirm.name) }
                      : current,
                  );
                  toast.success(`Deleted ${confirm.name}`);
                }
                setConfirm(null);
              })
            }
          />
        )}
      </AlertDialog>
    </Shell>
  );
}

function Shell({
  username,
  dark,
  onTheme,
  onLogout,
  children,
}: {
  username: string;
  dark: boolean;
  onTheme: () => void;
  onLogout: () => void;
  children: ReactNode;
}) {
  return (
    <TooltipProvider>
      <main className="mx-auto min-h-screen w-full max-w-5xl px-4 py-6 sm:px-6">
        <header className="mb-6 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="flex size-8 items-center justify-center rounded-md bg-primary text-xs font-semibold text-primary-foreground">
              pv
            </div>
            <span className="font-semibold">psamvault</span>
          </div>
          <div className="flex items-center gap-2">
            {username && (
              <div className="flex items-center gap-2 text-sm">
                <Avatar>
                  <AvatarFallback>{initials(username)}</AvatarFallback>
                </Avatar>
                <span className="hidden sm:inline">{username}</span>
              </div>
            )}
            <Tooltip label={dark ? "Light theme" : "Dark theme"}>
              <Button type="button" variant="ghost" size="icon" onClick={onTheme} aria-label="Toggle theme">
                {dark ? <Sun /> : <Moon />}
              </Button>
            </Tooltip>
            {username && (
              <Button type="button" variant="outline" size="sm" onClick={onLogout}>
                <LogOut /> Sign out
              </Button>
            )}
          </div>
        </header>
        {children}
      </main>
    </TooltipProvider>
  );
}

function SessionGuide({ onRetry }: { onRetry: () => void }) {
  return (
    <Alert className="mb-4">
      <p className="font-medium">Your session has expired</p>
      <p className="mt-1 text-muted-foreground">
        Run this in the terminal to restore it, then click Retry.
      </p>
      <pre className="mt-3 rounded-md bg-muted px-3 py-2 font-mono text-sm text-foreground">pv list</pre>
      <p className="mt-3 text-muted-foreground">
        If that command says you are logged out, sign in with this instead, then click Retry.
      </p>
      <pre className="mt-3 rounded-md bg-muted px-3 py-2 font-mono text-sm text-foreground">pv login</pre>
      <Button className="mt-4" type="button" variant="outline" onClick={onRetry}>
        Retry
      </Button>
    </Alert>
  );
}

function Stat({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <Card className="flex items-center gap-3 p-4">
      <div className="flex size-9 items-center justify-center rounded-md bg-muted text-muted-foreground">{icon}</div>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-lg font-semibold">{value}</p>
      </div>
    </Card>
  );
}

function RowMenu({ onView, onEdit, onDelete }: { onView: () => void; onEdit: () => void; onDelete: () => void }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button type="button" variant="ghost" size="icon" aria-label="Row actions">
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuItem onSelect={onView}>View</DropdownMenuItem>
        <DropdownMenuItem onSelect={onEdit}>Edit</DropdownMenuItem>
        <DropdownMenuItem className="text-destructive" onSelect={onDelete}>
          Delete
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-3 space-y-1.5">
      <Label>{label}</Label>
      {children}
    </div>
  );
}

function EntryFields({
  pending,
  onClose,
  onSubmit,
  initial,
}: {
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
  initial?: { username: string; login_url: string; notes: string };
}) {
  return (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            onSubmit(Object.fromEntries(form.entries()) as Record<string, string>);
          }}
        >
          {!initial && (
            <Field label="Site name">
              <Input name="site_name" required placeholder="GitHub" />
            </Field>
          )}
          <Field label="Username">
            <Input name="username" defaultValue={initial?.username ?? ""} placeholder="Leave blank to keep" />
          </Field>
          <Field label="Password">
            <Input name="password" type="password" required={!initial} placeholder={initial ? "Leave blank to keep" : ""} />
            {!initial && <p className="text-xs text-muted-foreground">At least 8 characters, 1 uppercase, 1 digit.</p>}
          </Field>
          <Field label="Login URL">
            <Input name="login_url" defaultValue={initial?.login_url ?? ""} placeholder="https://" />
          </Field>
          <Field label="Notes">
            <Textarea name="notes" defaultValue={initial?.notes ?? ""} placeholder={initial ? "Clear this to remove notes" : ""} />
          </Field>
          <div className="mt-4 flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? <Loader2 className="animate-spin" /> : null}
              Save
            </Button>
          </div>
        </form>
  );
}

function EntryForm(props: {
  title: string;
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
}) {
  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent title={props.title}>
        <EntryFields {...props} />
      </DialogContent>
    </Dialog>
  );
}

function EntryEditor(props: {
  site: string;
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
}) {
  const [initial, setInitial] = useState<{ username: string; login_url: string; notes: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getEntry(props.site)
      .then(setInitial)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Entry not found"));
  }, [props.site]);
  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent title={`Edit ${props.site}`}>
        {error && <Alert className="mb-3 border-destructive/40">{error}</Alert>}
        {!initial && !error && <Skeleton className="h-40 w-full" />}
        {initial && (
          <EntryFields pending={props.pending} onClose={props.onClose} onSubmit={props.onSubmit} initial={initial} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function KeyFields({
  pending,
  onClose,
  onSubmit,
  initial,
}: {
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
  initial?: { service: string; notes: string };
}) {
  return (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            onSubmit(Object.fromEntries(form.entries()) as Record<string, string>);
          }}
        >
          {!initial && (
            <Field label="Name">
              <Input name="name" required placeholder="OpenAI production" />
            </Field>
          )}
          <Field label="Service">
            <Input name="service" defaultValue={initial?.service ?? ""} />
          </Field>
          <Field label="API key">
            <Input name="api_key" type="password" required={!initial} placeholder={initial ? "Leave blank to keep" : "sk-…"} />
          </Field>
          <Field label="Notes">
            <Textarea name="notes" defaultValue={initial?.notes ?? ""} />
          </Field>
          <div className="mt-4 flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? <Loader2 className="animate-spin" /> : null}
              Save
            </Button>
          </div>
        </form>
  );
}

function KeyForm(props: {
  title: string;
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
}) {
  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent title={props.title}>
        <KeyFields {...props} />
      </DialogContent>
    </Dialog>
  );
}

function KeyEditor(props: {
  name: string;
  pending: boolean;
  onClose: () => void;
  onSubmit: (payload: Record<string, string>) => void;
}) {
  const [initial, setInitial] = useState<{ service: string; notes: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getApiKey(props.name)
      .then(setInitial)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "API key not found"));
  }, [props.name]);
  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent title={`Edit ${props.name}`}>
        {error && <Alert className="mb-3 border-destructive/40">{error}</Alert>}
        {!initial && !error && <Skeleton className="h-40 w-full" />}
        {initial && (
          <KeyFields pending={props.pending} onClose={props.onClose} onSubmit={props.onSubmit} initial={initial} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function SecretRow({
  label,
  value,
  revealed,
  pending,
  onReveal,
  onCopy,
}: {
  label: string;
  value: string | null;
  revealed: boolean;
  pending: boolean;
  onReveal: () => void;
  onCopy: () => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b py-3 last:border-0">
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="font-mono text-sm break-all">{revealed && value !== null ? value : "••••••••••••"}</p>
      </div>
      <div className="flex shrink-0 gap-1">
        <Button type="button" variant="outline" size="sm" disabled={pending} onClick={onReveal}>
          {pending ? <Loader2 className="animate-spin" /> : revealed ? "Hide" : "Reveal"}
        </Button>
        <Button type="button" variant="outline" size="sm" disabled={pending} onClick={onCopy}>
          Copy
        </Button>
      </div>
    </div>
  );
}

function EntryDetail({ entry, onClose }: { entry: Entry; onClose: () => void }) {
  const [password, setPassword] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  async function ensure(field: "password" | "notes") {
    if (field === "password" && password !== null) return password;
    if (field === "notes" && notes !== null) return notes;
    setBusy(field);
    try {
      const body = await revealEntry(entry.site_name, field);
      const value = body[field] ?? "";
      if (field === "password") setPassword(value);
      else setNotes(value);
      return value;
    } finally {
      setBusy(null);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent title={entry.site_name}>
        <p className="text-sm text-muted-foreground">{entry.username_hint}</p>
        {entry.login_url && (
          <a className="text-sm underline" href={entry.login_url} target="_blank" rel="noreferrer">
            {entry.login_url}
          </a>
        )}
        <div className="mt-4">
          <SecretRow
            label="Password"
            value={password}
            revealed={showPassword}
            pending={busy === "password"}
            onReveal={() => {
              if (showPassword) {
                setShowPassword(false);
                return;
              }
              void ensure("password")
                .then(() => setShowPassword(true))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not reveal"));
            }}
            onCopy={() => {
              void ensure("password")
                .then((value) => navigator.clipboard.writeText(value))
                .then(() => toast.success("Copied"))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not copy"));
            }}
          />
          <SecretRow
            label="Notes"
            value={notes}
            revealed={showNotes}
            pending={busy === "notes"}
            onReveal={() => {
              if (showNotes) {
                setShowNotes(false);
                return;
              }
              void ensure("notes")
                .then(() => setShowNotes(true))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not reveal"));
            }}
            onCopy={() => {
              void ensure("notes")
                .then((value) => navigator.clipboard.writeText(value))
                .then(() => toast.success("Copied"))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not copy"));
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

function KeyDetail({ row, onClose }: { row: ApiKeyRow; onClose: () => void }) {
  const [secret, setSecret] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  async function ensure(field: "api_key" | "notes") {
    if (field === "api_key" && secret !== null) return secret;
    if (field === "notes" && notes !== null) return notes;
    setBusy(field);
    try {
      const body = await revealApiKey(row.name, field);
      const value = body[field] ?? "";
      if (field === "api_key") setSecret(value);
      else setNotes(value);
      return value;
    } finally {
      setBusy(null);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent title={row.name}>
        <p className="text-sm text-muted-foreground">{row.service_hint}</p>
        <div className="mt-4">
          <SecretRow
            label="API key"
            value={secret}
            revealed={showSecret}
            pending={busy === "api_key"}
            onReveal={() => {
              if (showSecret) {
                setShowSecret(false);
                return;
              }
              void ensure("api_key").then(() => setShowSecret(true)).catch((reason: unknown) =>
                toast.error(reason instanceof Error ? reason.message : "Could not reveal"),
              );
            }}
            onCopy={() => {
              void ensure("api_key")
                .then((value) => navigator.clipboard.writeText(value))
                .then(() => toast.success("Copied"))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not copy"));
            }}
          />
          <SecretRow
            label="Notes"
            value={notes}
            revealed={showNotes}
            pending={busy === "notes"}
            onReveal={() => {
              if (showNotes) {
                setShowNotes(false);
                return;
              }
              void ensure("notes").then(() => setShowNotes(true)).catch((reason: unknown) =>
                toast.error(reason instanceof Error ? reason.message : "Could not reveal"),
              );
            }}
            onCopy={() => {
              void ensure("notes")
                .then((value) => navigator.clipboard.writeText(value))
                .then(() => toast.success("Copied"))
                .catch((reason: unknown) => toast.error(reason instanceof Error ? reason.message : "Could not copy"));
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
