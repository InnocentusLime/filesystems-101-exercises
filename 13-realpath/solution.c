#include <solution.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <fs_malloc.h>

#define BUFF_SIZE 255

struct path_segment
{
	char name[BUFF_SIZE + 1];
};

struct path
{
	size_t segment_count;
	size_t segment_cap;
	struct path_segment segments[];
};

struct path *path_empty(size_t cap)
{
	struct path *res = NULL;

	res = fs_xzalloc(
		sizeof(struct path) +
		cap * sizeof(struct path_segment)
	);
	res->segment_cap = cap;

	return res;
}

struct path *path_new(const char *str)
{
	struct path *res = NULL;
	size_t segment_count = 0, n = 0;
	const char *segments[PATH_MAX], **curr = NULL, *p = NULL;
	char *out = NULL;

	memset(segments, 0, sizeof(segments));
	for (p = str, curr = segments ; *p ;)
	{
		while (*p == '/')
		{
			p++;
		}

		if (!*p)
		{
			break;
		}

		segment_count++;
		*(curr++) = p;

		while (*p != '/' && *p != '\0')
		{
			p++;
		}
	}

	res = path_empty(segment_count);
	res->segment_count = segment_count;
	for (; n < segment_count; ++n)
	{
		for (out = res->segments[n].name; *(segments[n]) != '/' && *(segments[n]) != '\0'; ++out)
		{
			*out = *(segments[n]++);
		}
	}

	return res;
}

void path_pop(struct path *p)
{
	if (!p->segment_count)
	{
		return;
	}

	p->segment_count--;
}

void path_clear(struct path *p)
{
	p->segment_count = 0;
}

void path_grow(struct path **p)
{
	(*p)->segment_cap *= 2;
	*p = fs_xrealloc(
		*p,
		sizeof(struct path) +
		(*p)->segment_cap * sizeof(struct path_segment)
	);
}

void path_push(struct path **p, const char *add)
{
	if ((*p)->segment_count == (*p)->segment_cap)
	{
		path_grow(p);
	}

	strcpy((*p)->segments[(*p)->segment_count++].name, add);
}

char *path_format(struct path *p, const char *extra)
{
	char *res = NULL, *ptr = NULL;
	size_t n = 0;

	res = fs_xzalloc(p->segment_count * (BUFF_SIZE + 1) + strlen(extra) + 1);
	ptr = res;

	*(ptr++) = '/';
	for (n = 0; n < p->segment_count; ++n)
	{
		strcpy(ptr, p->segments[n].name);
		ptr += strlen(p->segments[n].name);
		*(ptr++) = '/';
	}

	strcpy(ptr, extra);

	return res;
}

static ssize_t x_readlinkat(
	int fd,
	const char* child,
	char *restrict buff
)
{
	ssize_t n = readlinkat(fd, child, buff, PATH_MAX);

	if (n < 0)
	{
		exit(1);
	}
	else
	{
		buff[n] = '\0';
	}

	return n;
}

void abspath(const char *path)
{
	char link[PATH_MAX + 1], *name = "", *out = NULL;
	int currdir = -1, nextdir = -1;
	size_t n = 0;
	struct stat st;
	struct path *toresolve, *ready, *tmp;

	toresolve = path_new(path);
	ready = path_empty(8);
	tmp = NULL;

	currdir = open("/", O_RDONLY);
	assert(currdir >= 0);

	while (n < toresolve->segment_count)
	{
		name = toresolve->segments[n].name;

		if (strcmp(name, ".") == 0)
		{
			n++;
			continue;
		}

		if (strcmp(name, "..") == 0)
		{
			nextdir = openat(currdir, "..", O_RDONLY | O_NOFOLLOW);
			if (nextdir < 0)
			{
				out = path_format(ready, "");
				report_error(out, name, errno);
				goto terminate;
			}

			close(currdir);

			currdir = nextdir;
			nextdir = -1;
			path_pop(ready);
			n++;
			continue;
		}

		if (fstatat(currdir, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
		{
			out = path_format(ready, "");
			report_error(out, name, errno);
			goto terminate;
		}

		if (!S_ISLNK(st.st_mode))
		{
			if (n == toresolve->segment_count - 1 && !S_ISDIR(st.st_mode))
			{
				break;
			}

			/* change dir */
			path_push(&ready, name);
			nextdir = openat(currdir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
			if (nextdir < 0)
			{
				out = path_format(ready, "");
				report_error(out, name, errno);
				goto terminate;
			}

			close(currdir);
			currdir = nextdir;
			nextdir = -1;
			n++;
			name = "";

			continue;
		}

		if (x_readlinkat(currdir, name, link) < 0)
		{
			goto terminate;
		}

		tmp = path_new(link);
		for (n++; n < toresolve->segment_count; ++n)
		{
			path_push(&tmp, toresolve->segments[n].name);
		}
		fs_xfree(toresolve);
		toresolve = tmp;
		tmp = NULL;
		n = 0;
		path_clear(ready);

		close(currdir);
		currdir = open("/", O_RDONLY);
		assert(currdir >= 0);
	}

	out = path_format(ready, name);
	report_path(out);

terminate:
	if (currdir >= 0)
	{
		close(currdir);
	}

	if (nextdir >= 0)
	{
		close(nextdir);
	}

	fs_xfree(toresolve);
	fs_xfree(ready);
	fs_xfree(tmp);
	fs_xfree(out);
}
