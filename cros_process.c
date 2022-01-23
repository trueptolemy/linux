// gcc -g -Wall -Itools/include/ -o cros_process cros_process.c -lpthread

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#ifndef __NR_umcg_ctl
#define __NR_umcg_ctl  450
#define __NR_umcg_wait 451
#define __NR_umcg_kick 452
#endif

#include <linux/list.h>
#include "include/uapi/linux/umcg.h"


//#define CROS_PROCESS 1

/* send/receive fd wrappers */

static int
fdpass_send(int sockout, int fd)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char c = 0;
	union {
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} u;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	memset(&u, 0, sizeof(u));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	iov.iov_base = &c;
	iov.iov_len = 1;

	return sendmsg(sockout, &msg, 0) == 1 ? 0 : -1;
}

static int
fdpass_recv(int sockin)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	int fd;
	char c;
	union {
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr align;
	} u;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	iov.iov_base = &c;
	iov.iov_len = 1;

	if (recvmsg(sockin, &msg, 0) < 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg
	    || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = -EINVAL;
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}


/* syscall wrappers */

static inline int
sys_umcg_ctl(u32 flags, struct umcg_task *self, clockid_t which_clock)
{
	return syscall(__NR_umcg_ctl, flags, self, which_clock);
}

static inline int
sys_umcg_wait(u32 flags, u64 timo)
{
	return syscall(__NR_umcg_wait, flags, timo);
}

static inline int
sys_umcg_kick(u32 flags, pid_t tid)
{
	return syscall(__NR_umcg_kick, flags, tid);
}

/* the 'foo' scheduler */

struct foo_task {
	struct umcg_task	task;
	struct list_head	node;
	pid_t			tid;
};

struct foo_server {
	struct umcg_task	task;
	struct list_head	node;
	pid_t			tid;
	struct foo_task		*cur;
	int			workers;
};

void foo_add(struct foo_server *server, struct umcg_task *t)
{
	struct foo_task *foo = container_of(t, struct foo_task, task);

	t->runnable_workers_ptr = 0ULL;
	list_add_tail(&foo->node, &server->node);
}

struct foo_task *foo_pick_next(struct foo_server *server)
{
	struct foo_task *first = NULL;

	if (list_empty(&server->node))
		return first;

	first = list_first_entry(&server->node, struct foo_task, node);
	list_del(&first->node);
	return first;
}

#define NSEC_PER_SEC 1000000000ULL

u64 foo_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

#define TICK_NSEC NSEC_PER_SEC

static volatile bool foo_preemptible = false;

/* our workers */

static volatile bool done = false;

static void umcg_signal(int signr)
{
	done = true;
}

#define MAX_TASK 1
#define SIZE sizeof(struct foo_server) + MAX_TASK * sizeof(struct foo_task)
#define STACK_SIZE 1024 * 1024

/* event driven worker */
#ifndef CROS_PROCESS
void *worker_fn0(void *arg)
#else
int worker_fn0(void *arg)
#endif
{
	int ret;

	printf("WORKER: A == %d\n", gettid());
	fflush(stdout);

	/*********************************/
	int sfd, fd;
	struct sockaddr_un addr;
	ssize_t nbytes;
	char buffer[256];

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("WORKER: socket: ");
		exit(-1);
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/tmp/fd-pass.socket", sizeof(addr.sun_path) - 1);

	ret = connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
	if (ret == -1) {
		perror("WORKER: connect: ");
		exit(-1);
	}

	fd = fdpass_recv(sfd);
	if (fd < 0) {
		perror("WORKER: fdpass_recv ");
		exit(-1);
	}

	ret = close(sfd);
	if (ret == -1) {
		perror("WORKER: close ");
		exit(-1);
	}

	printf("WORKER: receive the fd: %d successfully!\n", fd);
	fflush(stdout);

	void *ptr1 = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	printf("ptr1 %ld\n", (u64)ptr1);
	struct foo_server *server = (struct foo_server *)ptr1;
	struct foo_task *task = (struct foo_task *)(ptr1 + sizeof(struct foo_server));

	/***************************************/
	task->tid = gettid();
	task->task.server_tid = server->tid;
	task->task.state = UMCG_TASK_BLOCKED;

	printf("WORKER: start register worker...\n");
	fflush(stdout);

	ret = sys_umcg_ctl(UMCG_CTL_REGISTER|UMCG_CTL_WORKER, &task->task, CLOCK_MONOTONIC);
	if (ret) {
		munmap(ptr1, SIZE);
		perror("WORKER: umcg_ctl(A): ");
		exit(-1);
	} else {
		printf("WORKER: register worker successfully!\n");
		fflush(stdout);
	}

	__atomic_add_fetch(&server->workers, 1, __ATOMIC_RELAXED);

	while (!done) {
		printf("A\n");
		fflush(stdout);

		sleep(1);
	}

	printf("WORKER: A == done\n");
	fflush(stdout);

	__atomic_add_fetch(&server->workers, -1, __ATOMIC_RELAXED);

	ret = sys_umcg_ctl(UMCG_CTL_UNREGISTER|UMCG_CTL_WORKER, &task->task, 0);
	if (ret) {
		munmap(ptr1, SIZE);
		perror("WORKER: umcg_ctl(~A): ");
		exit(-1);
	}

	munmap(ptr1, SIZE);

#ifndef CROS_PROCESS
	return NULL;
#else
	return 0;
#endif
}

/* the server */

int main(int argc, char **argv)
{
	struct umcg_task *runnable_ptr, *next;
	u64 timeout = 0;
	u32 tid;
	int ret;

#ifndef CROS_PROCESS
	pthread_t worker;
#endif

	/****************************************/
	int sfd, cfd, fd;
	struct sockaddr_un addr;
	
	/*..........................................*/

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("WORKER: socket: ");
		exit(-1);
	}

	if (unlink("/tmp/fd-pass.socket") == -1 && errno != ENOENT) {
		perror("WORKER: unlink: ");
		exit(-1);
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;;
	strncpy(addr.sun_path, "/tmp/fd-pass.socket", sizeof(addr.sun_path) - 1);

	if (bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
		perror("WORKER: bind: ");
		exit(-1);
	}

	if (listen(sfd, 1) == -1) {
		perror("WORKER: listen: ");
		exit(-1);
	}

	/*****************************************/

	fd = memfd_create("shma", 0);
	if (fd < 0) {
		perror("SERVER: memfd_create: ");
		exit(-1);
	} else {
		printf("SERVER: Opened fd %d in server\n", fd);
		fflush(stdout);
	}

	ftruncate(fd, SIZE);
	void *ptr0 = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	//memset(ptr0, 'A', SIZE);
	void *ptr_w = sizeof(struct foo_server) + ptr0;
	printf("ptr0 %ld, worker %ld\n", (u64)ptr0, (u64)(sizeof(struct foo_server) + ptr0));
	struct foo_server *server = (struct foo_server *)ptr0;

	struct sigaction sa = {
		.sa_handler = umcg_signal,
	};

	sigaction(SIGINT, &sa, NULL);

	printf("SERVER: server == %d\n", gettid());
	fflush(stdout);

	server->tid = gettid();
	INIT_LIST_HEAD(&server->node);
	server->task.server_tid = gettid();
	server->task.state = UMCG_TASK_RUNNING;

	ret = sys_umcg_ctl(UMCG_CTL_REGISTER, &server->task, CLOCK_MONOTONIC);
	if (ret) {
		munmap(ptr0, SIZE);
		perror("SERVER: umcg_ctl: ");
		exit(-1);
	} else {
		printf("SERVER: register server successfully!\n");
		fflush(stdout);
	}

	/* FIXME */
#ifndef CROS_PROCESS
	pthread_create(&worker, NULL, worker_fn0, NULL);
#else
	void *stack = malloc(STACK_SIZE);
	ret = clone(&worker_fn0, (char *)stack + STACK_SIZE, 0, NULL);
	if (ret < 0) {
		munmap(ptr0, SIZE);
		perror("SERVER: umcg_ctl: ");
		exit(-1);
	} else {
		printf("SERVER: create worker successfully!\n");
		fflush(stdout);
	}
#endif

	/*****************************************/
	cfd = accept(sfd, NULL, NULL);
	if (cfd < 0) {
		munmap(ptr0, SIZE);
		perror("SERVER: accept ");
		exit(-1);
	}

	ret = fdpass_send(cfd, fd);
	if (ret) {
		munmap(ptr0, SIZE);
		perror("SERVER: fdpass_send ");
		exit(-1);
	}

	ret = close(sfd);
	if (ret == -1) {
		perror("SERVER: close ");
		exit(-1);
	}

	printf("SERVER: send the fd: %d successfully!\n", fd);
	fflush(stdout);

	/*****************************************/

	if (argc > 1) {
		foo_preemptible = true;
		/*
		 * setup preemption tick
		 */
		timeout = foo_time() + TICK_NSEC;
	}

	while (!(done && !__atomic_load_n(&server->workers, __ATOMIC_RELAXED))) {
		/*
		 * Mark the server as runnable first, so we can detect
		 * additions to the runnable list after we read it.
		 */
		__atomic_store_n(&server->task.state,
				 UMCG_TASK_RUNNABLE | UMCG_TF_COND_WAIT,
				 __ATOMIC_RELAXED);

		/*
		 * comsume the runnable notification list and add
		 * the tasks to our local runqueue.
		 */
		runnable_ptr = (void*)__atomic_exchange_n(&server->task.runnable_workers_ptr,
							  NULL, __ATOMIC_SEQ_CST);
		while (runnable_ptr) {
			printf("runnable ptr %ld\n", (u64)runnable_ptr);
			next = (void *)runnable_ptr->runnable_workers_ptr;
			foo_add(server, runnable_ptr);
			runnable_ptr = next;
		}

		if (server->cur && server->cur->task.state == UMCG_TASK_RUNNING) {
			/*
			 * Assert ::next_tid still points there and has RUNNING bit on
			 */
			if (server->task.next_tid != (server->cur->tid | UMCG_TID_RUNNING)) {
				printf("SERVER: current not running: %d %x\n",
				       server->task.next_tid & UMCG_TID_MASK,
				       server->task.next_tid & ~UMCG_TID_MASK);
				exit(-1);
			}

			putchar('x');
		} else {
			tid = 0;
			server->cur = foo_pick_next(server);
			if (server->cur)
				tid = server->cur->tid;

			__atomic_store_n(&server->task.next_tid, tid, __ATOMIC_RELAXED);

			printf("SERVER: pick: %d\n", tid);
			fflush(stdout);
		}
		fflush(stdout);

		ret = sys_umcg_wait(0, timeout);

		/*
		 * If we set ::next_tid but it hasn't been consumed by the
		 * syscall due to failure, make sure to put the task back on
		 * the queue, lest we leak it.
		 */
		tid = __atomic_load_n(&server->task.next_tid, __ATOMIC_RELAXED);
		if (tid && !(tid & UMCG_TID_RUNNING)) {
			foo_add(server, &server->cur->task);
			server->cur = NULL;
			putchar('*');
		}

		if (!ret)
			continue;

		switch (errno) {
		case EAGAIN:
			/*
			 * Got a wakeup, try again.
			 */
			continue;

		case ETIMEDOUT:
			/*
			 * timeout: drive preemption
			 */
			putchar('t');
			fflush(stdout);

			/*
			 * Next tick..
			 */
			timeout += TICK_NSEC;

			/*
			 * If we have a current, cmpxchg set TF_PREEMPT and on success
			 * send it a signal to kick it into the kernel such that
			 * it might re-report itself runnable.
			 */
			if (server->cur) {
				struct foo_task *t = server->cur;
				u32 val = UMCG_TASK_RUNNING;
				u32 new = UMCG_TASK_RUNNING | UMCG_TF_PREEMPT;

				if (__atomic_compare_exchange_n(&t->task.state, &val, new,
								false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
					sys_umcg_kick(0, t->tid);
				}
			}
			/*
			 * Either way around, if the cmpxchg
			 * failed the task will have blocked
			 * and we should re-start the loop.
			 */
			continue;

		default:
			munmap(ptr0, SIZE);
			perror("SERVER: wait:");
			exit(-1);
		}
	}

#ifndef CROS_PROCESS
	pthread_join(worker, NULL);
#endif

	munmap(ptr0, SIZE);

	return 0;
}
