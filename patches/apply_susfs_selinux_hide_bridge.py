#!/usr/bin/env python3
"""Connect SUSFS setprocattr to BakaSU's patched SELinux Hide handler."""
from pathlib import Path
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: apply_susfs_selinux_hide_bridge.py COMMON_KERNEL_FOLDER KSU_FOLDER")

common = Path(sys.argv[1]).resolve()
ksu_root = Path(sys.argv[2]).resolve()
hooks_path = common / 'security/selinux/hooks.c'
ksu_path = ksu_root / 'kernel/feature/selinux_hide.c'

if not hooks_path.is_file():
    raise SystemExit(f"missing SELinux hooks source: {hooks_path}")
if not ksu_path.is_file():
    raise SystemExit(f"missing BakaSU SELinux Hide source: {ksu_path}")

hooks = hooks_path.read_text(encoding='utf-8')
ksu = ksu_path.read_text(encoding='utf-8')

# The BakaSU integration deliberately exports this handler under the name
# referenced by the SUSFS hook. Refuse to patch an incompatible source layout.
required_ksu = [
    '#define ksu_handle_selinux_setprocattr my_setprocattr',
    'int __nocfi ksu_handle_selinux_setprocattr(',
    'KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE',
    'security_context_to_sid_live',
    'error = security_context_to_sid_live(value, size, &sid);',
]
for token in required_ksu:
    if token not in ksu:
        raise SystemExit(f"BakaSU source does not expose the expected SUSFS handler: {token}")

if 'ksu_selinux_hide_running' not in hooks:
    raise SystemExit("SUSFS hide-state flag not found in security/selinux/hooks.c")

bridge_name = 'susfs_setprocattr_bridge'
if bridge_name in hooks:
    if 'LSM_HOOK_INIT(setprocattr, susfs_setprocattr_bridge)' not in hooks:
        raise SystemExit("bridge exists but the SELinux hook is not routed through it")
    print('SUSFS setprocattr bridge already applied.')
    raise SystemExit(0)

# SUSFS v2.4.0's in-file callback checks the backup policy and then calls
# stock selinux_setprocattr(), causing a second parse against the modified
# live policy. Route the enabled app-UID path to BakaSU's #3969/#3981 handler.
function_anchor = "static int my_setprocattr(const char *name, void *value, size_t size)"
if hooks.count(function_anchor) != 1:
    raise SystemExit(f"expected exactly one SUSFS callback function, found {hooks.count(function_anchor)}")
start = hooks.index(function_anchor)
open_brace = hooks.find("{", start + len(function_anchor))
if open_brace < 0:
    raise SystemExit("SUSFS my_setprocattr opening brace not found")
depth = 0
function_end = -1
for pos in range(open_brace, len(hooks)):
    if hooks[pos] == "{":
        depth += 1
    elif hooks[pos] == "}":
        depth -= 1
        if depth == 0:
            function_end = pos + 1
            break
if function_end < 0:
    raise SystemExit("SUSFS my_setprocattr closing brace not found")
replacement_start = start
replacement_end = function_end

replacement = '''extern int my_setprocattr(const char *name, void *value, size_t size);

static int susfs_setprocattr_bridge(const char *name, void *value, size_t size)
{
    /* Preserve SUSFS's original UID/feature/name gate. */
    if (likely(current_uid().val < 10000 ||
               !ksu_selinux_hide_running ||
               strcmp(name, "current")))
        return selinux_setprocattr(name, value, size);

    /* Use BakaSU's one-pass parser plus original-type generation checks. */
    return my_setprocattr(name, value, size);
}'''

hooks = hooks[:replacement_start] + replacement + hooks[replacement_end:]

hook_old = 'LSM_HOOK_INIT(setprocattr, my_setprocattr)'
hook_new = 'LSM_HOOK_INIT(setprocattr, susfs_setprocattr_bridge)'
if hooks.count(hook_old) != 1:
    raise SystemExit(f"expected one {hook_old!r} registration")
hooks = hooks.replace(hook_old, hook_new, 1)

# Structural postconditions: callback has the feature gate and delegates to
# the exported BakaSU symbol; stock callback is not registered directly.
for token in [
    'static int susfs_setprocattr_bridge(',
    '!ksu_selinux_hide_running',
    'return my_setprocattr(name, value, size);',
    hook_new,
]:
    if token not in hooks:
        raise SystemExit(f"post-patch verification failed: missing {token}")
if hook_old in hooks:
    raise SystemExit("post-patch verification failed: stale hook registration remains")

hooks_path.write_text(hooks, encoding='utf-8')
print('SUSFS setprocattr now delegates active app-UID writes to BakaSU SELinux Hide (#3969/#3981).')
print('The original SELinux path remains active for UID < 10000, disabled hide, and non-current attributes.')
