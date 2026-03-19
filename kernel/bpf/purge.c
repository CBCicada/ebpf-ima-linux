// SPDX-License-Identifier: GPL-2.0
/*
 * BPF program purge - remove a link-based BPF program from the system.
 *
 * Sets the condemned flag (blocking new references), then removes all
 * tail call map entries, bpffs pins, and kills all FD-holding processes.
 * The condemned flag ensures no new references can be created between
 * phases, eliminating TOCTOU races.
 */
#include <linux/bpf.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>

static void purge_tail_call_maps(struct bpf_prog *target);
static void purge_fd_holders(struct bpf_prog *target);

int bpf_prog_purge_link(struct bpf_prog *prog)
{
	bpf_prog_condemn(prog);
	purge_tail_call_maps(prog);
	bpf_unpin_prog(prog);
	purge_fd_holders(prog);

	if (atomic64_read(&prog->aux->refcnt) > 1)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(bpf_prog_purge_link);

static void purge_tail_call_maps(struct bpf_prog *target)
{
	struct bpf_map *map;
	u32 id = 0;

	while ((map = bpf_map_get_curr_or_next(&id)) != NULL) {
		if (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
			struct bpf_array *array = container_of(map,
						struct bpf_array, map);
			u32 i;

			for (i = 0; i < array->map.max_entries; i++) {
				struct bpf_prog *old;

                // clear entry if it points to target atomically
				old = cmpxchg(array->ptrs + i, target, NULL);
				if (old == target) {
					bpf_prog_put(target);
				}
			}
		}
		bpf_map_put(map);
		id++;
	}
}

static void purge_fd_holders(struct bpf_prog *target)
{
	struct task_struct *task;

	rcu_read_lock();
	for_each_process(task) {
		struct files_struct *files;
		struct fdtable *fdt;
		unsigned int fd;
		bool found = false;

		/* Skip kernel threads */
		files = task->files;
		if (!files)
			continue;

		fdt = rcu_dereference(files->fdt);
		for (fd = 0; fd < READ_ONCE(fdt->max_fds); fd++) {
			struct file *f;

			f = rcu_dereference(fdt->fd[fd]);
			if (!f)
				continue;

			if (bpf_file_references_prog(f, target)) {
				found = true;
				break;
			}
		}

		if (found) {
			if (task->pid == 1) {
				pr_warn("bpf_prog_purge: init (PID 1) holds fd to prog id=%u — not killing\n",
					target->aux->id);
				continue;
			}
			send_sig(SIGKILL, task, 1);
		}
	}
	rcu_read_unlock();
}
