// SPDX-License-Identifier: GPL-2.0
/* 43-kfuncs: a kernel module that registers a custom kfunc for BPF programs.
 *
 * Build (needs kernel headers + kbuild):
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 * Load:
 *   insmod bpf_kfunc_demo.ko
 *
 * The registered kfunc `bpf_kfunc_greet` returns a fixed string; BPF programs
 * can call it after registering via BTF_KFUNCS_START.
 */
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

__bpf_kfunc_start_defs();

__bpf_kfunc const char *bpf_kfunc_greet(void)
{
	return "hello from custom kfunc";
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_demo_set)
BTF_ID_FLAGS(func, bpf_kfunc_greet)
BTF_KFUNCS_END(bpf_kfunc_demo_set)

static const struct btf_kfunc_id_set bpf_kfunc_demo_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_kfunc_demo_set,
};

static int __init bpf_kfunc_demo_init(void)
{
	int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					    &bpf_kfunc_demo_kfunc_set);
	pr_info("bpf_kfunc_demo: register_btf_kfunc_id_set returned %d\n", ret);
	return ret;
}

static void __exit bpf_kfunc_demo_exit(void)
{
	pr_info("bpf_kfunc_demo: unloaded\n");
}

module_init(bpf_kfunc_demo_init);
module_exit(bpf_kfunc_demo_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demo BPF kfunc registration");
