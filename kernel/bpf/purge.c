// SPDX-License-Identifier: GPL-2.0
/*
 * BPF program purge - remove a link-based BPF program from the system.
 *
 * Sets the condemned flag (blocking new references), then removes all
 * tail call map entries, bpffs pins, and closes FDs in holder processes
 * via task_work.
 */
#include <linux/bpf.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/task_work.h>
#include <linux/completion.h>
#include <linux/cgroup.h>
#include <linux/bpf-cgroup.h>
#include <linux/delay.h>

struct cgroup_victim_lst {
	struct cgroup *cgrp;
	struct list_head node;
};

struct bpf_purge_fd {
	struct list_head	node;
	unsigned int		fd;
};

struct bpf_purge_ctx {
	struct bpf_prog		*target;
	int			signal;
	atomic_t		pending;	/* outstanding callbacks + sentinel */
	struct completion	done;
	atomic_t		refcnt;		/* ctx lifetime */
	struct list_head	work_list;	/* pending bpf_purge_work entries */
	spinlock_t		work_lock;
};

struct bpf_purge_work {
	struct callback_head	twork;
	struct bpf_purge_ctx	*ctx;
	struct task_struct	*task;		/* get_task_struct'd */
	struct list_head	node;		/* on ctx->work_list */
	struct list_head	fd_list;	/* list of bpf_purge_fd */
};

static void purge_ctx_put(struct bpf_purge_ctx *ctx)
{
	if (atomic_dec_and_test(&ctx->refcnt)) {
		bpf_prog_put(ctx->target);
		kfree(ctx);
	}
}

static void purge_fd_callback(struct callback_head *cb)
{
	struct bpf_purge_work *work = container_of(cb, struct bpf_purge_work,
						   twork);
	struct bpf_purge_ctx *ctx = work->ctx;
	struct bpf_purge_fd *pfd, *tmp;

	list_for_each_entry_safe(pfd, tmp, &work->fd_list, node) {
		struct file *f = fget(pfd->fd);

		if (f) {
			// in case the process itself closes at the exact right time and reopens something else
			if (bpf_file_references_prog(f, ctx->target)) {
				fput(f);
				close_fd(pfd->fd);
			} else {
				fput(f);
			}
		}
		list_del(&pfd->node);
		kfree(pfd);
	}

	if (ctx->signal)
		send_sig(ctx->signal, current, 1);

	spin_lock(&ctx->work_lock);
	list_del(&work->node);
	spin_unlock(&ctx->work_lock);

	put_task_struct(work->task);
	kfree(work);

	if (atomic_dec_and_test(&ctx->pending))
		complete(&ctx->done);
	purge_ctx_put(ctx);
}

static int queue_fd_close_work(struct bpf_prog *target,
			       struct bpf_purge_ctx *ctx)
{
	struct task_struct *task;
	int queued = 0;

	rcu_read_lock();
	for_each_process(task) {
		struct bpf_purge_work *work = NULL;
		struct files_struct *files;
		struct fdtable *fdt;
		unsigned int fd;
		struct file *f;
		struct bpf_purge_fd *pfd, *tmp;

		files = task->files;
		if (!files)
			continue;

		fdt = rcu_dereference(files->fdt);
		for (fd = 0; fd < READ_ONCE(fdt->max_fds); fd++) {
			f = rcu_dereference(fdt->fd[fd]);
			if (!f)
				continue;

			if (!bpf_file_references_prog(f, target))
				continue;

			if (!work) {

				work = kmalloc(sizeof(*work), GFP_ATOMIC);
				if (!work){
					pr_err("bpf_prog_purge: failed to allocate work for task %d\n",
						task->pid);
					break;
				}
				INIT_LIST_HEAD(&work->fd_list);
			}

			pfd = kmalloc(sizeof(*pfd), GFP_ATOMIC);
			if (!pfd){
				pr_err("bpf_prog_purge: failed to allocate fd for task %d\n",
					task->pid);
				continue;
			}
			pfd->fd = fd;
			list_add_tail(&pfd->node, &work->fd_list);
		}

		if (!work) {
			kfree(work);
			continue;
		}

		get_task_struct(task);
		work->task = task;
		work->ctx = ctx;

		init_task_work(&work->twork, purge_fd_callback);
		if (task_work_add(task, &work->twork, TWA_SIGNAL)) {
			list_for_each_entry_safe(pfd, tmp, &work->fd_list, node)
				kfree(pfd);
			put_task_struct(task);
			kfree(work);
			continue;
		}

		spin_lock(&ctx->work_lock);
		list_add_tail(&work->node, &ctx->work_list);
		spin_unlock(&ctx->work_lock);

		atomic_inc(&ctx->pending);
		atomic_inc(&ctx->refcnt);
		queued++;
	}
	rcu_read_unlock();
	return queued;
}

static void sigkill_stragglers(struct bpf_purge_ctx *ctx)
{
	struct bpf_purge_work *work;

	spin_lock(&ctx->work_lock);
	list_for_each_entry(work, &ctx->work_list, node) {
		send_sig(SIGKILL, work->task, 1);
	}
	spin_unlock(&ctx->work_lock);
}

static void purge_tail_call_maps(struct bpf_prog *target)
{
	struct bpf_map *map;
	u32 id = 0;
	struct bpf_array *array;
	u32 i;
	struct bpf_prog *old;

	while ((map = bpf_map_get_curr_or_next(&id)) != NULL) {
		if (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
			array = container_of(map, struct bpf_array, map);
			for (i = 0; i < array->map.max_entries; i++) {

				old = cmpxchg(array->ptrs + i, target, NULL);
				if (old == target)
					bpf_prog_put(target);
			}
		}
		bpf_map_put(map);
		id++;
	}
}

int bpf_prog_purge_link(struct bpf_prog *prog, int signal, unsigned long timeout_ms,
			bool force)
{
	struct bpf_purge_ctx *ctx;
	int queued, ret;
	unsigned long left = 0;

	bpf_prog_condemn(prog);
	purge_tail_call_maps(prog);
	bpf_unpin_prog(prog);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->target = prog;
	bpf_prog_inc(prog);
	ctx->signal = signal;
	init_completion(&ctx->done);
	atomic_set(&ctx->refcnt, 1);
	atomic_set(&ctx->pending, 1);
	INIT_LIST_HEAD(&ctx->work_list);
	spin_lock_init(&ctx->work_lock);

	queued = queue_fd_close_work(prog, ctx);

	if (atomic_dec_and_test(&ctx->pending))
		complete(&ctx->done);

	if (queued > 0 && timeout_ms > 0) {

		left = wait_for_completion_timeout(&ctx->done,
					msecs_to_jiffies(timeout_ms));
		pr_info("bpf_prog_purge[id=%u]: queued=%d wait_left_jiffies=%lu\n",
			prog->aux->id, queued, left);

		if (!left) {
			pr_warn("bpf_prog_purge: timeout waiting for %d tasks (prog id=%u)\n",
				atomic_read(&ctx->pending),
				prog->aux->id);
			if (force)
				sigkill_stragglers(ctx);
		}
	}

	ret = left > 0 ? -EINPROGRESS : 0;

	purge_ctx_put(ctx);
	return ret;
}
EXPORT_SYMBOL_GPL(bpf_prog_purge_link);

int bpf_prog_purge_cgroup_attachments(struct bpf_prog *prog,
				      unsigned long timeout_ms)
{
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;
	struct cgroup_victim_lst *v, *vtmp;
	LIST_HEAD(victims);
	int atype;
	int ret = 0;

	bpf_prog_condemn(prog);

	cgroup_lock();
	css_for_each_descendant_pre(css, &cgrp_dfl_root.cgrp.self) {
		bool match = false;

		if (!(css->flags & CSS_ONLINE))
			continue;
		cgrp = container_of(css, struct cgroup, self);
		for (atype = 0; atype < MAX_CGROUP_BPF_ATTACH_TYPE && !match; atype++) {
			struct bpf_prog_list *pl;

			hlist_for_each_entry(pl, &cgrp->bpf.progs[atype], node) {
				if (pl->prog == prog && !pl->link) {
					match = true;
					break;
				}
			}
		}
		if (match) {
			v = kmalloc(sizeof(*v), GFP_KERNEL);
			if (!v) {
				ret = -ENOMEM;
				goto unlock_collect;
			}
			v->cgrp = cgrp;
			cgroup_get(cgrp);
			list_add(&v->node, &victims);
		}
	}
unlock_collect:
	cgroup_unlock();

	unsigned long deadline = jiffies + msecs_to_jiffies(timeout_ms);

	list_for_each_entry_safe(v, vtmp, &victims, node) {
		int err;

		do {
			cgroup_lock();
			cgroup_kill(v->cgrp->dom_cgrp);
			cgroup_unlock();

			// no existing mechanism for waiting in kernel land, so we just poll
			while (cgroup_is_populated(v->cgrp)) {
				if (time_after(jiffies, deadline))
					break;
				msleep(20);
			}

			err = cgroup_rmdir(v->cgrp->kn);
		} while (err == -EBUSY && !time_after(jiffies, deadline));

		if (err)
			ret = err;

		list_del(&v->node);
		cgroup_put(v->cgrp);
		kfree(v);
	}

	return ret;
}
