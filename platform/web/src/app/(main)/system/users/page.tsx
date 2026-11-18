"use client";

import * as React from "react";
import { toast } from "sonner";
import { KeyRoundIcon, PlusIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { UserAccount } from "@/lib/types";

const ROLE_LABEL: Record<string, string> = { admin: "管理员", operator: "操作员", viewer: "只读" };

export default function UsersPage() {
  const [users, setUsers] = React.useState<UserAccount[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [createOpen, setCreateOpen] = React.useState(false);
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [role, setRole] = React.useState<UserAccount["role"]>("operator");
  const [busy, setBusy] = React.useState(false);
  const [resetUser, setResetUser] = React.useState<UserAccount | null>(null);
  const [newPassword, setNewPassword] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setUsers(await api.users());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => { void load(); }, [load]);

  async function create() {
    if (!username.trim() || !password) { toast.error("请填写用户名和密码"); return; }
    setBusy(true);
    try {
      await api.createUser({ username: username.trim(), password, role });
      toast.success("用户已创建");
      setCreateOpen(false);
      setUsername(""); setPassword(""); setRole("operator");
      await load();
    } catch (e) { toast.error(`创建失败：${(e as Error).message}`); }
    finally { setBusy(false); }
  }

  async function patch(u: UserAccount, body: { role?: UserAccount["role"]; enabled?: boolean }) {
    try {
      await api.updateUser(u.id, body);
      await load();
    } catch (e) { toast.error(`更新失败：${(e as Error).message}`); }
  }

  async function remove(u: UserAccount) {
    if (!window.confirm(`删除用户「${u.username}」？此操作不可撤销。`)) return;
    try { await api.deleteUser(u.id); toast.success("已删除"); await load(); }
    catch (e) { toast.error(`删除失败：${(e as Error).message}`); }
  }

  async function resetPassword() {
    if (!resetUser || newPassword.length < 8) { toast.error("密码至少 8 位"); return; }
    setBusy(true);
    try {
      await api.updateUser(resetUser.id, { password: newPassword });
      toast.success(`已重置 ${resetUser.username} 的密码`);
      setResetUser(null); setNewPassword("");
    } catch (e) { toast.error(`重置失败：${(e as Error).message}`); }
    finally { setBusy(false); }
  }

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">用户与角色</h1>
          <p className="text-muted-foreground text-sm">管理员可管理用户；操作员可分析与配置；只读用户只能查看。</p>
        </div>
        <Button size="sm" onClick={() => setCreateOpen(true)}><PlusIcon /> 新建用户</Button>
      </div>

      {error && <Card className="border-destructive/40 p-4 text-sm text-destructive">{error}</Card>}

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>用户名</TableHead>
              <TableHead>角色</TableHead>
              <TableHead>启用</TableHead>
              <TableHead>更新时间</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && users.length === 0 ? (
              <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">加载中…</TableCell></TableRow>
            ) : users.length === 0 ? (
              <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">暂无用户</TableCell></TableRow>
            ) : users.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.username}</TableCell>
                <TableCell>
                  <Select value={u.role} onValueChange={(v) => void patch(u, { role: v as UserAccount["role"] })}>
                    <SelectTrigger size="sm" className="w-32"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">管理员</SelectItem>
                      <SelectItem value="operator">操作员</SelectItem>
                      <SelectItem value="viewer">只读</SelectItem>
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Switch checked={u.enabled} onCheckedChange={(v) => void patch(u, { enabled: v })} />
                    <Badge variant="outline">{u.enabled ? "启用" : "禁用"}</Badge>
                  </div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{new Date(u.updated_at).toLocaleString("zh-CN")}</TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1">
                    <Button size="sm" variant="ghost" title="重置密码" onClick={() => setResetUser(u)}><KeyRoundIcon /></Button>
                    <Button size="sm" variant="ghost" title="删除" onClick={() => void remove(u)}><Trash2Icon className="text-destructive" /></Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建用户</DialogTitle>
            <DialogDescription>新用户创建后立即生效。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5"><Label>用户名</Label><Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="operator1" /></div>
            <div className="grid gap-1.5"><Label>初始密码</Label><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="至少 8 位" /></div>
            <div className="grid gap-1.5">
              <Label>角色</Label>
              <Select value={role} onValueChange={(v) => setRole(v as UserAccount["role"])}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">管理员</SelectItem>
                  <SelectItem value="operator">操作员</SelectItem>
                  <SelectItem value="viewer">只读</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={busy}>取消</Button>
            <Button onClick={() => void create()} disabled={busy}>{busy ? "创建中…" : "创建"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!resetUser} onOpenChange={(o) => { if (!o) { setResetUser(null); setNewPassword(""); } }}>
   
        <DialogContent>
          <DialogHeader>
            <DialogTitle>重置密码：{resetUser?.username}</DialogTitle>
            <DialogDescription>输入新密码（至少 8 位）。</DialogDescription>
          </DialogHeader>
          <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="新密码" />
          <DialogFooter>
            <Button variant="outline" onClick={() => setResetUser(null)} disabled={busy}>取消</Button>
            <Button onClick={() => void resetPassword()} disabled={busy}>{busy ? "保存中…" : "保存"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
