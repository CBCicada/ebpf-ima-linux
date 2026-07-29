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
	struct list_head	signaled_pids;	/* dedup set: tasks to signal */
	spinlock_t		signaled_lock;
};

struct purge_signaled_pid {
	struct list_head	node;
	struct pid		*pid;
};

struct bpf_purge_work {
	struct callback_head	twork;
	struct bpf_purge_ctx	*ctx;
	struct task_struct	*task;		/* get_task_struct'd */
	struct list_head	node;		/* on ctx->work_list */
	struct list_head	fd_list;	/* list of bpf_purge_fd */
};

static void bpf_purge_ctx_track_pid(struct bpf_purge_ctx *ctx, struct pid *pid);

static void purge_ctx_put(struct bpf_purge_ctx *ctx)
{
	if (atomic_dec_and_test(&ctx->refcnt)) {
		struct purge_signaled_pid *sp, *tmp;

		list_for_each_entry_safe(sp, tmp, &ctx->signaled_pids, node) {
			list_del(&sp->node);
			put_pid(sp->pid);
			kfree(sp);
		}
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
		struct file *f = fget_task(current, pfd->fd);

		if (f) {
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
		unsigned int fd = 0;
		struct file *f;
		struct bpf_purge_fd *pfd, *tmp;

		get_task_struct(task);
		while ((f = fget_task_next(task, &fd))) {
			if (!bpf_file_references_prog(f, target))
				goto next_file;

			if (!work) {
				work = kmalloc(sizeof(*work), GFP_ATOMIC);
				if (!work) {
					pr_err("bpf_prog_purge: failed to allocate work for task %d\n",
					       task->pid);
					goto next_file;
				}
				INIT_LIST_HEAD(&work->fd_list);
			}

			pfd = kmalloc(sizeof(*pfd), GFP_ATOMIC);
			if (!pfd) {
				pr_err("bpf_prog_purge: failed to allocate fd for task %d\n",
				       task->pid);
				goto next_file;
			}
			pfd->fd = fd;
			list_add_tail(&pfd->node, &work->fd_list);

next_file:
			fput(f);
			fd++;
		}

		if (!work) {
			put_task_struct(task);
			continue;
		}
		if (list_empty(&work->fd_list)) {
			put_task_struct(task);
			kfree(work);
			continue;
		}

		work->task = task;
		work->ctx = ctx;
		init_task_work(&work->twork, purge_fd_callback);

		spin_lock(&ctx->work_lock);
		list_add_tail(&work->node, &ctx->work_list);
		spin_unlock(&ctx->work_lock);

		atomic_inc(&ctx->pending);
		atomic_inc(&ctx->refcnt);

		if (task_work_add(task, &work->twork, TWA_SIGNAL)) {
			spin_lock(&ctx->work_lock);
			list_del(&work->node);
			spin_unlock(&ctx->work_lock);

			atomic_dec(&ctx->pending);
			purge_ctx_put(ctx);

			list_for_each_entry_safe(pfd, tmp, &work->fd_list, node) {
				list_del(&pfd->node);
				kfree(pfd);
			}
			put_task_struct(task);
			kfree(work);
			continue;
		}

		bpf_purge_ctx_track_pid(ctx, task_tgid(task));
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

static void bpf_purge_ctx_track_pid(struct bpf_purge_ctx *ctx, struct pid *pid)
{
	struct purge_signaled_pid *sp, *new;

	if (!ctx || !pid)
		return;

	new = kmalloc(sizeof(*new), GFP_ATOMIC);
	if (!new)
		return;

	spin_lock(&ctx->signaled_lock);
	list_for_each_entry(sp, &ctx->signaled_pids, node) {
		if (sp->pid == pid) {
			spin_unlock(&ctx->signaled_lock);
			kfree(new);
			return;
		}
	}
	new->pid = get_pid(pid);
	list_add(&new->node, &ctx->signaled_pids);
	spin_unlock(&ctx->signaled_lock);
}

static void deliver_tracked_signals(struct bpf_purge_ctx *ctx, int signal)
{
	struct purge_signaled_pid *sp;

	spin_lock(&ctx->signaled_lock);
	list_for_each_entry(sp, &ctx->signaled_pids, node) {
		kill_pid_info(signal, SEND_SIG_PRIV, sp->pid);
	}
	spin_unlock(&ctx->signaled_lock);
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
	INIT_LIST_HEAD(&ctx->signaled_pids);
	spin_lock_init(&ctx->signaled_lock);

	queued = queue_fd_close_work(prog, ctx);
	bpf_link_purge_for_prog(prog);
	deliver_tracked_signals(ctx, signal);

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

	ret = 0;
	if (queued > 0 && timeout_ms > 0 && !left)
		ret = -EINPROGRESS;

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
		for (atype = 0; atype < MAX_CGROUP_BPF_ATTACH_TYPE && !match;
		     atype++) {
			struct bpf_prog_list *pl;

			hlist_for_each_entry(pl, &cgrp->bpf.progs[atype],
					     node) {
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

			while (cgroup_is_populated(v->cgrp)) {
				if (time_after(jiffies, deadline))
					break;
				msleep(20);
			}

			cgroup_lock();
			if (!(v->cgrp->self.flags & CSS_ONLINE))
				err = 0;
			else
				err = cgroup_destroy_locked(v->cgrp);
			cgroup_unlock();
		} while (err == -EBUSY && !time_after(jiffies, deadline));

		if (err)
			ret = err;

		list_del(&v->node);
		cgroup_put(v->cgrp);
		kfree(v);
	}

	return ret;
}
