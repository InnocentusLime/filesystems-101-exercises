#include <solution.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <liburing.h>
#include <fs_malloc.h>
#include <assert.h>

#define QUEUE_DEPTH 4
#define BUFF_SIZE 256*1024
// #define BUFF_SIZE 4

enum file_op_t
{
	FILE_OP_READ = 0,
	FILE_OP_WRITE = 1,
};

struct file_op
{
	int fd;
	off_t offset;
	enum file_op_t t;
	char data[];
};

int get_file_size(int fd, off_t *out) {
	int err = 0;
    struct stat st;

    if((err = fstat(fd, &st)) < 0) {
        return -err;
    }

    assert(S_ISREG(st.st_mode));

    *out = st.st_size;

	return 0;
}

int copy(int in, int out)
{
	int err = 0, n = 0, res = 0;
	struct io_uring ring;
	struct io_uring_sqe *sqe = NULL;
	struct io_uring_cqe *cqe = NULL;
	off_t sz_file = 0, to_read = 0;
	struct file_op* pool[QUEUE_DEPTH], *op = NULL;

	// Init the op pool and stuff them with read requests
	for (n = 0; n < QUEUE_DEPTH; n++)
	{
		pool[n] = fs_xzalloc(sizeof(struct file_op) + BUFF_SIZE);
		pool[n]->fd = in;
		pool[n]->offset = to_read;
		pool[n]->t = FILE_OP_READ;

		to_read += BUFF_SIZE;
	}

	if ((err = get_file_size(in, &sz_file)) < 0)
	{
		return err;
	}

	if ((err = io_uring_queue_init(QUEUE_DEPTH, &ring, 0)) < 0)
	{
		return err;
	}

	/* submit initial requests */
	for (n = 0; n < QUEUE_DEPTH; n++)
	{
		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_read(
			sqe,
			pool[n]->fd,
			pool[n]->data,
			BUFF_SIZE,
			pool[n]->offset
		);
		io_uring_sqe_set_data(sqe, pool[n]);
	}
	io_uring_submit(&ring);

	while (1)
	{
		if ((err = io_uring_wait_cqe(&ring, &cqe)) < 0) {
			return err;
		}

		res = cqe->res;

		if (res < 0)
		{
			return res;
		}

		op = io_uring_cqe_get_data(cqe);
		if (op->t == FILE_OP_WRITE && op->offset + res >= sz_file)
		{
			break;
		}

		switch (op->t)
		{
			case FILE_OP_READ:
				op->fd = out;
				op->t = FILE_OP_WRITE;
				break;
			case FILE_OP_WRITE:
				op->fd = in;
				op->offset = to_read;
				op->t = FILE_OP_READ;
				to_read += res;
				break;
		}

		io_uring_cqe_seen(&ring, cqe);

		switch (op->t)
		{
			case FILE_OP_READ:
				sqe = io_uring_get_sqe(&ring);
				io_uring_prep_read(
					sqe,
					op->fd,
					op->data,
					BUFF_SIZE,
					op->offset
				);
				break;
			case FILE_OP_WRITE:
				sqe = io_uring_get_sqe(&ring);
				io_uring_prep_write(
					sqe,
					op->fd,
					op->data,
					res,
					op->offset
				);
				break;
		}

		io_uring_sqe_set_data(sqe, op);
		io_uring_submit(&ring);
	}

	io_uring_queue_exit(&ring);

	for (n = 0; n < QUEUE_DEPTH; n++)
	{
		fs_xfree(pool[n]);
	}

	return 0;
}
