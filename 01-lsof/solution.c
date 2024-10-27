#include <solution.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define BUFFER_SIZE 255

struct path_buff
{
	char* mem;
	size_t cap;
};

struct path_buff path_buff_new()
{
	struct path_buff res;

	res.mem = malloc(16);
	res.cap = 16;

	assert(res.mem);

	return res;
}

void path_buff_grow(struct path_buff *buff)
{
	// realloc promises to free the mem
	char* new = realloc(buff->mem, buff->cap * 2);
	assert(new);

	buff->mem = new;
	buff->cap *= 2;
}

void path_buff_free(struct path_buff *buff)
{
	free(buff->mem);

	buff->cap = 0;
	buff->mem = NULL;
}

static struct dirent* x_readdir(const char *dir, DIR *d)
{
	int err;
	struct dirent *ent = NULL;

	errno = 0; // zero out errno as recommended by man
	ent = readdir(d);
	err = errno;

	if (ent == NULL && err)
	{
		report_error(dir, err);
	}

	return ent;
}

static ssize_t x_readlink(
	const char *restrict pathname,
	struct path_buff *restrict buff
)
{
	int err;
	ssize_t n;

	while ((n = readlink(pathname, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
	{
		path_buff_grow(buff);
	}

	err = errno;
	if (n < 0)
	{
		report_error(pathname, err);
	}
	else
	{
		buff->mem[n] = '\0';
	}

	return n;
}

DIR *x_opendir(const char* name)
{
	int err;
	DIR* res = opendir(name);

	err = errno;
	if (!res)
	{
		report_error(name, err);
	}

	return res;
}

void fds_of(const char* fds, int pid, struct path_buff *buff)
{
	DIR *fdfs = NULL;
	struct dirent *ent = NULL;
	char fd[BUFFER_SIZE + 1];
	int descriptor = 0;

	fdfs = x_opendir(fds);
	if (!fdfs)
	{
		return;
	}

	while ((ent = x_readdir(fds, fdfs)) != NULL)
	{
		descriptor = atoi(ent->d_name);
		if (!descriptor)
		{
			continue;
		}

		snprintf(fd, BUFFER_SIZE, "/proc/%d/fd/%d", pid, descriptor);

		if (x_readlink(fd, buff) >= 0)
		{
			report_file(buff->mem);
		}
	}

	closedir(fdfs);
}

void lsof(void)
{
	DIR *proc = opendir("/proc");
	char fds[BUFFER_SIZE + 1];
	struct dirent *ent = NULL;
	int pid = 0;
	struct path_buff buff = path_buff_new();

	while ((ent = x_readdir("/proc", proc)) != NULL)
	{
		/* Filter off non-PID stuff */
		pid = atoi(ent->d_name);
		if (!pid)
		{
			continue;
		}

		/* Get the process fds */
		snprintf(fds, BUFFER_SIZE, "/proc/%d/fd", pid);

		/* Do the thing */
		fds_of(fds, pid, &buff);
	}

	closedir(proc);
	path_buff_free(&buff);
}