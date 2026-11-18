# Temporary SELinux seqno Kretprobe

Target: the pinned PKR110 / Android 16 / android15-6.6.89 kernel source in `manifests/oos16/oneplus_ace5_pro_6.6.89_w.xml`.

The pinned `security/selinux/ss/services.c` has a local `avd_init(struct selinux_policy *, struct av_decision *)`; it is not a separately visible symbol. The module therefore registers a kretprobe on the global `security_compute_av()` and changes only `av_decision.seqno` at function return. The pinned `struct av_decision` layout places `seqno` at byte offset 12.

This is an experimental, temporary module. It does not change the permission bitmasks (`allowed`, `auditallow`, `auditdeny`). It can be disabled at runtime with `echo 0 > /sys/module/selinux_avd_seqno_kprobe/parameters/enabled` and fully removed with `rmmod selinux_avd_seqno_kprobe`.

The `patched_count` parameter reports how many decisions were modified. Do not load it until the `.ko` has been built against the exact kernel build output and its vermagic / symbol versions have been checked.
