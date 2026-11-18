#!/usr/bin/env python3
"""Smoke-test the SUSFS-to-BakaSU setprocattr bridge patcher."""
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
patcher = repo / "patches/apply_susfs_selinux_hide_bridge.py"

hooks_fixture = r"""
#ifdef CONFIG_KSU_SUSFS
extern bool ksu_selinux_hide_running __read_mostly;
static int my_setprocattr(const char *name, void *value, size_t size)
{
    u32 mysid = current_sid(), sid = 0;
    int error;
    char *str = value;
    if (likely(current_uid().val < 10000 ||
               !ksu_selinux_hide_running ||
               strcmp(name, "current")))
        return selinux_setprocattr(name, value, size);
    error = avc_has_perm(mysid, mysid, SECCLASS_PROCESS,
                         PROCESS__SETCURRENT, NULL);
    if (error)
        return error;
    if (size && str[0] && str[0] != '\\n') {
        error = security_context_to_sid_with_policy(
            backup_sepolicy, str, size, &sid, SECSID_NULL, GFP_KERNEL);
        if (error)
            return error;
    }
    return selinux_setprocattr(name, value, size);
}
#endif // #ifdef CONFIG_KSU_SUSFS

static struct security_hook_list selinux_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(setprocattr, my_setprocattr),
};
"""

ksu_fixture = r"""
#ifdef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
#define ksu_handle_selinux_setprocattr my_setprocattr
#endif
int __nocfi ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)
{
    return 0;
}
bool security_context_to_sid_live_marker(void);
"""

with tempfile.TemporaryDirectory(prefix="selinux-hide-bridge-test-") as temp:
    root = Path(temp)
    common = root / "common"
    ksu = root / "BakaSU"
    hooks = common / "security/selinux/hooks.c"
    source = ksu / "kernel/feature/selinux_hide.c"
    hooks.parent.mkdir(parents=True)
    source.parent.mkdir(parents=True)
    hooks.write_text(hooks_fixture, encoding="utf-8")
    source.write_text(ksu_fixture, encoding="utf-8")

    first = subprocess.run(
        [sys.executable, str(patcher), str(common), str(ksu)],
        check=True, capture_output=True, text=True,
    )
    updated = hooks.read_text(encoding="utf-8")
    assert "static int susfs_setprocattr_bridge(" in updated
    assert "return my_setprocattr(name, value, size);" in updated
    assert "LSM_HOOK_INIT(setprocattr, susfs_setprocattr_bridge)" in updated
    assert "static int my_setprocattr(" not in updated

    second = subprocess.run(
        [sys.executable, str(patcher), str(common), str(ksu)],
        check=True, capture_output=True, text=True,
    )
    assert "already applied" in second.stdout.lower()
    print(first.stdout.strip())
    print("Idempotency check: PASS")
