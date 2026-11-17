#!/usr/bin/env python3
"""Port SELinux Hide timing fixes #3969 + #3981 to BakaSU/ReSukiSU's policy-pair code.

The script is intentionally fail-closed: any source-layout drift aborts before
compilation instead of silently producing an unpatched kernel.
"""
from pathlib import Path
import os
import subprocess
import sys

root = Path(sys.argv[1]).resolve()

def read(rel):
    p = root / rel
    if not p.is_file():
        raise SystemExit(f"missing source file: {rel}")
    return p, p.read_text(encoding="utf-8")

def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)

# 1) Original SELinux type cache: adapted from the policy-pair implementation
# of KernelSU #3969.
p, s = read("kernel/selinux/sepolicy.c")
if "ksu_original_types_lock" in s:
    raise SystemExit("original-type cache already exists; refusing duplicate patch")
if "#include <linux/seqlock.h>" not in s:
    s = replace_once(s, "#include <linux/printk.h>\n",
                     "#include <linux/printk.h>\n#include <linux/seqlock.h>\n",
                     "seqlock include")

cache_code = r'''
static DEFINE_SEQLOCK(ksu_original_types_lock);
static const struct policydb *ksu_original_types_policy;
static const struct policydb *ksu_original_types_backup;
static u32 ksu_original_types_limit;
static u32 ksu_original_types_generation;

static void invalidate_original_types_locked(void)
{
    WRITE_ONCE(ksu_original_types_policy, NULL);
    WRITE_ONCE(ksu_original_types_backup, NULL);
    WRITE_ONCE(ksu_original_types_limit, 0);
    WRITE_ONCE(ksu_original_types_generation, 0);
}

bool ksu_set_original_types(struct policydb *db, struct policydb *orig_db, u32 policy_generation)
{
    unsigned long flags;
    bool valid = db && orig_db && policy_generation && orig_db->p_types.nprim &&
                 orig_db->p_types.nprim == db->p_types.nprim;

    write_seqlock_irqsave(&ksu_original_types_lock, flags);
    if (valid) {
        WRITE_ONCE(ksu_original_types_policy, db);
        WRITE_ONCE(ksu_original_types_backup, orig_db);
        WRITE_ONCE(ksu_original_types_limit, orig_db->p_types.nprim);
        WRITE_ONCE(ksu_original_types_generation, policy_generation);
    } else {
        invalidate_original_types_locked();
    }
    write_sequnlock_irqrestore(&ksu_original_types_lock, flags);
    return valid;
}

bool ksu_advance_original_types(struct policydb *db, struct policydb *old_db, u32 old_policy_generation,
                                u32 policy_generation)
{
    unsigned long flags;
    bool valid;

    write_seqlock_irqsave(&ksu_original_types_lock, flags);
    valid = db && old_db && old_policy_generation && policy_generation &&
            policy_generation == old_policy_generation + 1 &&
            READ_ONCE(ksu_original_types_policy) == old_db &&
            READ_ONCE(ksu_original_types_generation) == old_policy_generation &&
            READ_ONCE(ksu_original_types_limit) &&
            old_db->p_types.nprim >= READ_ONCE(ksu_original_types_limit) &&
            db->p_types.nprim >= old_db->p_types.nprim;
    if (valid) {
        WRITE_ONCE(ksu_original_types_policy, db);
        WRITE_ONCE(ksu_original_types_generation, policy_generation);
    } else {
        invalidate_original_types_locked();
    }
    write_sequnlock_irqrestore(&ksu_original_types_lock, flags);
    return valid;
}

int ksu_type_is_original(struct policydb *db, struct policydb *orig_db, u32 policy_generation, u32 type_value)
{
    const struct policydb *policy, *backup;
    u32 limit, generation;
    unsigned int seq;

    do {
        seq = read_seqbegin(&ksu_original_types_lock);
        policy = READ_ONCE(ksu_original_types_policy);
        backup = READ_ONCE(ksu_original_types_backup);
        limit = READ_ONCE(ksu_original_types_limit);
        generation = READ_ONCE(ksu_original_types_generation);
    } while (read_seqretry(&ksu_original_types_lock, seq));

    if (!db || !orig_db || !policy_generation || policy != db || backup != orig_db ||
        generation != policy_generation || !limit || limit != orig_db->p_types.nprim ||
        type_value > db->p_types.nprim)
        return -1;

    return type_value && type_value <= limit ? 1 : 0;
}

static void forget_original_types(struct policydb *db)
{
    unsigned long flags;

    write_seqlock_irqsave(&ksu_original_types_lock, flags);
    if (READ_ONCE(ksu_original_types_policy) == db || READ_ONCE(ksu_original_types_backup) == db)
        invalidate_original_types_locked();
    write_sequnlock_irqrestore(&ksu_original_types_lock, flags);
}
'''
anchor = "static bool add_typeattribute(struct policydb *db, const char *type, const char *attr);\n"
s = replace_once(s, anchor, anchor + "\n" + cache_code + "\n", "original-type cache insertion")
destroy_anchor = "void ksu_destroy_sepolicy(struct selinux_policy *pol)\n{\n    ksu_destroy_policydb(&pol->policydb);"
s = replace_once(s, destroy_anchor,
                 "void ksu_destroy_sepolicy(struct selinux_policy *pol)\n{\n    forget_original_types(&pol->policydb);\n    ksu_destroy_policydb(&pol->policydb);",
                 "policy-destruction invalidation")
p.write_text(s, encoding="utf-8")

# 2) Export the cache helpers.
p, s = read("kernel/selinux/sepolicy.h")
header_anchor = "bool ksu_exists(struct policydb *db, const char *type);\n"
header_add = """bool ksu_set_original_types(struct policydb *db, struct policydb *orig_db, u32 policy_generation);
bool ksu_advance_original_types(struct policydb *db, struct policydb *old_db, u32 old_policy_generation,
                                u32 policy_generation);
int ksu_type_is_original(struct policydb *db, struct policydb *orig_db, u32 policy_generation, u32 type_value);
"""
s = replace_once(s, header_anchor, header_anchor + header_add, "sepolicy header declarations")
p.write_text(s, encoding="utf-8")

# 3) Seed the original-type boundary at initial policy publication, then
# advance it when handle_sepolicy publishes a replacement live policy.
p, s = read("kernel/selinux/rules.c")
apply_start = s.index("void apply_kernelsu_rules()")
apply_end = s.index("#define KSU_SEPOLICY_MAX_BATCH_SIZE", apply_start)
apply_part = s[apply_start:apply_end]
apply_anchor = "    db = &pol->policydb;\n#else\n"
apply_replacement = """    db = &pol->policydb;
    pol->latest_granting = old_pol->latest_granting + 1;
    if (!ksu_set_original_types(&pol->policydb,
                                backup_sepolicy ? &backup_sepolicy->policydb : NULL,
                                pol->latest_granting))
        pr_warn("original SELinux type metadata unavailable; using backup lookups\\n");
#else
"""
apply_part = replace_once(apply_part, apply_anchor, apply_replacement, "initial policy marker")
s = s[:apply_start] + apply_part + s[apply_end:]

handle_start = s.index("int handle_sepolicy(")
publish = "    rcu_assign_pointer(selinux_state.policy, pol);"
publish_pos = s.find(publish, handle_start)
if publish_pos < 0:
    raise SystemExit("handle_sepolicy: publication anchor not found")
advance = """    pol->latest_granting = old_pol->latest_granting + 1;
    if (!ksu_advance_original_types(&pol->policydb, &old_pol->policydb,
                                    old_pol->latest_granting, pol->latest_granting))
        pr_warn("original SELinux type metadata stale; using backup lookups\\n");

"""
s = s[:publish_pos] + advance + s[publish_pos:]
p.write_text(s, encoding="utf-8")

# 4) Add the single-parse path from #3981. Keep BakaSU's existing dual parser
# as the fallback when the original-type generation marker is stale.
p, s = read("kernel/feature/selinux_hide.c")
if "security_context_to_sid_live" in s:
    raise SystemExit("SELinux live parser already exists; refusing duplicate patch")
proto_anchor = """static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len,
                                               u32 *sid, u32 def_sid, gfp_t gfp_flags, u32 *orig_sid_p, int *orig_rc_p);
"""
proto_add = "static int security_context_to_sid_live(const char *scontext, u32 scontext_len, u32 *sid);\n"
s = replace_once(s, proto_anchor, proto_anchor + proto_add, "live parser prototype")

helper_code = r'''
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
static int backup_string_to_context_struct(struct policydb *pol, struct policydb *live_pol,
                                           struct sidtab *sidtabp, char *scontext, struct context *ctx,
                                           u32 policy_generation, u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = 0, type_is_original;

    context_init(ctx);
    rc = -EINVAL;
    scontextp = scontext;

    p = scontextp;
    while (*p && *p != ':')
        p++;
    if (*p == 0)
        goto out;
    *p++ = 0;

    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (!usrdatum)
        goto out;
    ctx->user = usrdatum->value;

    scontextp = p;
    while (*p && *p != ':')
        p++;
    if (*p == 0)
        goto out;
    *p++ = 0;

    role = symtab_search(&pol->p_roles, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;

    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;

    type_is_original = ksu_type_is_original(live_pol, pol, policy_generation, typdatum->value);
    if (type_is_original <= 0) {
        rc = -EAGAIN;
        goto out;
    }
    ctx->type = typdatum->value;

    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
    if (rc)
        goto out;

    rc = -EINVAL;
    if (!policydb_context_isvalid(pol, ctx) || !policydb_context_isvalid(live_pol, ctx))
        goto out;
    rc = 0;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}

/* Parse against the backup policy once, then share the context with both SID tables. */
static int security_context_to_sid_live(const char *scontext, u32 scontext_len, u32 *sid)
{
    struct selinux_policy *policy;
    struct context context;
    char *scontext2;
    u32 backup_sid;
    int rc;

    if (!scontext_len)
        return -EINVAL;
    if (!backup_sepolicy || !backup_sepolicy->sidtab)
        return -EINVAL;

    scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);
    if (!scontext2)
        return -ENOMEM;

    *sid = SECSID_NULL;
retry:
    rcu_read_lock();
    policy = rcu_dereference(selinux_state.policy);
    if (!policy) {
        rc = -EINVAL;
        goto out_unlock;
    }

    rc = backup_string_to_context_struct(&backup_sepolicy->policydb, &policy->policydb,
                                         backup_sepolicy->sidtab, scontext2, &context,
                                         policy->latest_granting, SECSID_NULL);
    if (rc)
        goto out_unlock;

    rc = sidtab_context_to_sid(backup_sepolicy->sidtab, &context, &backup_sid);
    if (!rc)
        rc = sidtab_context_to_sid(policy->sidtab, &context, sid);
    context_destroy(&context);
    if (rc == -ESTALE) {
        rcu_read_unlock();
        memcpy(scontext2, scontext, scontext_len);
        scontext2[scontext_len] = '\0';
        goto retry;
    }
out_unlock:
    rcu_read_unlock();
    kfree(scontext2);
    return rc;
}
#endif
'''
helper_anchor = "static int context_struct_to_string(struct policydb *p, struct context *context, char **scontext, u32 *scontext_len)\n"
s = replace_once(s, helper_anchor, helper_code + "\n" + helper_anchor, "live parser helper insertion")

start = s.index("    /* Obtain a SID for the context, if one was specified. */")
end = s.index("\n\n    new = prepare_creds();", start)
old_block = s[start:end]
legacy_start = old_block.index("#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)")
legacy_end = old_block.rfind("\n#endif")
if legacy_start < 0 or legacy_end < legacy_start:
    raise SystemExit("setprocattr: legacy fallback block layout changed")
legacy = old_block[legacy_start:legacy_end].replace("#elif", "#if", 1)
new_block = r'''    /* Obtain a SID for the context, if one was specified. */
    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
        error = security_context_to_sid_live(value, size, &sid);
        if (error == -EAGAIN) {
            error2 = security_context_to_sid_with_policy(backup_sepolicy, value, size, &tmp_sid, SECSID_NULL,
                                                         GFP_KERNEL, &sid, &error);
            if (error2 || error)
                return error2 ?: error;
        } else if (error) {
            return error;
        }
#else
''' + legacy + r'''
        if (error2 || error)
            return error2 ?: error;
#endif /* legacy policy parser selection */
#endif /* modern policy-struct fast-path selection */
    }'''
s = s[:start] + new_block + s[end:]
p.write_text(s, encoding="utf-8")

# Structural assertions, whitespace check, and build provenance marker.
for rel, required in [
    ("kernel/selinux/sepolicy.c", ["ksu_original_types_lock", "ksu_type_is_original", "forget_original_types"]),
    ("kernel/selinux/sepolicy.h", ["ksu_type_is_original", "ksu_advance_original_types"]),
    ("kernel/selinux/rules.c", ["ksu_set_original_types", "ksu_advance_original_types", "latest_granting"]),
    ("kernel/feature/selinux_hide.c", ["backup_string_to_context_struct", "security_context_to_sid_live",
                                       "error = security_context_to_sid_live(value, size, &sid);"]),
]:
    text = (root / rel).read_text(encoding="utf-8")
    for token in required:
        if token not in text:
            raise SystemExit(f"verification failed: {rel} missing {token}")

# Validate preprocessor nesting in the patched translation unit before clang.
def check_preprocessor_nesting(path):
    stack = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        directive = line.lstrip()
        if directive.startswith(("#if ", "#ifdef ", "#ifndef ")):
            stack.append(number)
        elif directive.startswith("#endif"):
            if not stack:
                raise SystemExit(f"preprocessor verification failed: unmatched #endif at {path}:{number}")
            stack.pop()
        elif directive.startswith(("#else", "#elif")) and not stack:
            raise SystemExit(f"preprocessor verification failed: orphan {directive.split()[0]} at {path}:{number}")
    if stack:
        raise SystemExit(f"preprocessor verification failed: unclosed #if from {path}:{stack[-1]}")

check_preprocessor_nesting(root / "kernel/feature/selinux_hide.c")

result = subprocess.run(["git", "diff", "--check"], cwd=root, capture_output=True, text=True)
if result.returncode:
    sys.stderr.write(result.stdout + result.stderr)
    raise SystemExit("git diff --check failed")

artifact_dir = Path(os.environ.get("ARTIFACTS_FOLDER", ""))
if artifact_dir.is_dir():
    marker = artifact_dir / "SELINUX_HIDE_FIX.txt"
    marker.write_text(
        "BakaSU/ReSukiSU SELinux Hide policy-pair port\n"
        "KernelSU upstream fixes: #3969 + #3981\n"
        "Target: OnePlus Ace 5 Pro PKR110 / Android 16 / kernel 6.6.89\n",
        encoding="utf-8",
    )

print("SELinux Hide #3969/#3981 BakaSU port applied and structurally verified.")
print("BakaSU commit:", subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip())
print("NOTE: successful compilation and device runtime tests are still required.")
