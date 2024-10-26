#include <solution.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define BUFFER_SIZE 255

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
	char *restrict buf,
	size_t bufsiz
)
{
	int err;
	ssize_t n = readlink(pathname, buf, bufsiz);
	err = errno;

	if (n < 0)
	{
		report_error(pathname, err);
	}

	buf[n] = '\0';

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

int x_lstat(const char *restrict pathname, struct stat *restrict statbuf)
{
	int err;
	int n;

	n = lstat(pathname, statbuf);

	if (n < 0)
	{
		err = errno;
		report_error(pathname, err);
	}

	return n;
}

void fds_of(const char* fds, int pid)
{
	DIR *fdfs = NULL;
	struct dirent *ent = NULL;
	char fd[BUFFER_SIZE + 1];
	int descriptor = 0;
	struct stat st;
	char* buff = NULL;

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

		if (x_lstat(fd, &st) < 0)
		{
			continue;
		}

		buff = malloc(st.st_size + 1);

		if (x_readlink(fd, buff, st.st_size) >= 0)
		{
			report_file(buff);
		}

		free(buff);
	}

	closedir(fdfs);
}

void lsof(void)
{
	DIR *proc = opendir("/proc");
	char fds[BUFFER_SIZE + 1];
	struct dirent *ent = NULL;
	int pid = 0;

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
		fds_of(fds, pid);
	}

	closedir(proc);
}