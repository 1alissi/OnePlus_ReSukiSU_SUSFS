// SPDX-License-Identifier: GPL-2.0
/*
 * Experimental runtime seqno override for the pinned PKR110 6.6.89 source.
 * Hooks security_compute_av() on return and changes only av_decision.seqno.
 * This is temporary: unloading the module unregisters the kretprobe.
 */
#include <asm/ptrace.h>
#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/kernel.h>

struct av_decision_layout {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static_assert(offsetof(struct av_decision_layout, seqno) == 12);

static bool enabled = true;
static uint forced_seqno = 1;
static atomic64_t patched_count = ATOMIC64_INIT(0);

module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable runtime av_decision.seqno override");
module_param(forced_seqno, uint, 0644);
MODULE_PARM_DESC(forced_seqno, "Value written to av_decision.seqno (default: 1)");

static int get_patched_count(char *buffer, const struct kernel_param *kp)
{
    atomic64_t *count = kp->arg;
    return scnprintf(buffer, PAGE_SIZE, "%lld\n", atomic64_read(count));
}

static const struct kernel_param_ops patched_count_ops = {
    .get = get_patched_count,
};
module_param_cb(patched_count, &patched_count_ops, &patched_count, 0444);
MODULE_PARM_DESC(patched_count, "Number of decisions whose seqno was overridden");

struct probe_instance_data {
    struct av_decision_layout *avd;
};

static int av_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_instance_data *data = ri->data;

#if defined(CONFIG_ARM64)
    /* Pinned source ABI: security_compute_av(ssid, tsid, tclass, avd, xperms). */
    data->avd = (struct av_decision_layout *)regs->regs[3];
    return 0;
#else
    data->avd = NULL;
    return 1;
#endif
}

static int av_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_instance_data *data = ri->data;

    (void)regs;
    if (READ_ONCE(enabled) && data->avd) {
        WRITE_ONCE(data->avd->seqno, READ_ONCE(forced_seqno));
        atomic64_inc(&patched_count);
    }
    return 0;
}

static struct kretprobe avd_seqno_probe = {
    .kp.symbol_name = "security_compute_av",
    .entry_handler = av_entry_handler,
    .handler = av_return_handler,
    .data_size = sizeof(struct probe_instance_data),
    .maxactive = 256,
};

static int __init avd_seqno_kprobe_init(void)
{
    int ret = register_kretprobe(&avd_seqno_probe);

    if (ret) {
        pr_err("selinux_avd_seqno_kprobe: register_kretprobe failed: %d\n", ret);
        return ret;
    }
    pr_info("selinux_avd_seqno_kprobe: active on security_compute_av; enabled=%d seqno=%u\n",
            READ_ONCE(enabled), READ_ONCE(forced_seqno));
    return 0;
}

static void __exit avd_seqno_kprobe_exit(void)
{
    unregister_kretprobe(&avd_seqno_probe);
    pr_info("selinux_avd_seqno_kprobe: unloaded; patched=%lld missed=%lu\n",
            atomic64_read(&patched_count), avd_seqno_probe.nmissed);
}

module_init(avd_seqno_kprobe_init);
module_exit(avd_seqno_kprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Experimental local build");
MODULE_DESCRIPTION("Temporary Kretprobe override of SELinux av_decision seqno");
