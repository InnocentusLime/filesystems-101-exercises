#include <solution.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 255

static struct dirent* x_readdir(DIR *d)
{
	int err;
	struct dirent *ent = NULL;

	errno = 0; // zero out errno as recommended by man
	ent = readdir(d);
	err = errno;

	if (ent == NULL && err)
	{
		report_error("/proc", err);
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

void lsof(void)
{
	DIR *proc = opendir("/proc");
	char path[BUFFER_SIZE + 1];
	char exe[BUFFER_SIZE + 1];
	struct dirent *ent = NULL;
	int pid = 0;

	while ((ent = x_readdir(proc)) != NULL)
	{
		/* Filter off non-PID stuff */
		pid = atoi(ent->d_name);
		if (!pid)
		{
			continue;
		}

		/* Get the process exe */
		snprintf(path, BUFFER_SIZE, "/proc/%d/exe", pid);
		if (x_readlink(path, exe, BUFFER_SIZE) < 0)
		{
			continue;
		}

		report_file(exe);
	}

	closedir(proc);
}