#include <solution.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#define START_CAP 64
#define BUFF_SIZE 255

struct path_buff
{
	char* mem;
	size_t cap;
	size_t sz;
};

static struct path_buff path_buff_new()
{
	struct path_buff res;

	res.mem = calloc(START_CAP, 1);
	res.cap = START_CAP;
	res.sz  = 0;

	return res;
}

static void path_buff_grow(struct path_buff* buff)
{
	char* new = realloc(buff->mem, buff->cap * 2);
	assert(new);

	buff->mem = new;
	buff->cap *= 2;
}

static void path_buff_cpy_push(
	struct path_buff *buff,
	const char* data,
	size_t amount
)
{
	while (buff->cap - buff->sz < amount + 1)
	{
		path_buff_grow(buff);
	}

	memcpy(buff->mem + buff->sz, data, amount);
	buff->sz += amount;
	buff->mem[buff->sz] = '\0';
}

static void path_buff_push(struct path_buff* buff, const char* src)
{
	size_t amount = strlen(src);
	path_buff_cpy_push(buff, src, amount);
}

static void path_buff_set(struct path_buff* buff, const char* src)
{
	buff->sz = 0;
	path_buff_push(buff, src);
}

static void path_buff_free(struct path_buff* buff)
{
	free(buff->mem);

	buff->mem = NULL;
	buff->cap = 0;
	buff->sz = 0;
}

static void path_buff_up(struct path_buff* buff)
{
	if (buff->sz <= 1)
	{
		return;
	}

	buff->sz--;
	while (buff->mem[--buff->sz] != '/') {}

	buff->mem[++buff->sz] = '\0';
}

static ssize_t x_readlinkat(
	int fd,
	const char* child,
	struct path_buff *restrict buff
)
{
	ssize_t n;

	while ((n = readlinkat(fd, child, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
	{
		path_buff_grow(buff);
	}

	if (n < 0)
	{
		assert(0);
	}
	else
	{
		buff->mem[n] = '\0';
	}

	buff->sz = n;

	return n;
}

void abspath(const char *path)
{
	int currdir, nextdir;
	char child[BUFF_SIZE + 1], *child_ptr, *p;
	struct stat st;
	struct path_buff ready, toresolve, link;

	ready = path_buff_new();
	toresolve = path_buff_new();
	link = path_buff_new();

	path_buff_set(&toresolve, "/");
	path_buff_push(&toresolve, path);
	path_buff_set(&ready, "/");

	child_ptr = toresolve.mem;
	currdir = open("/", O_RDONLY);
	assert(currdir >= 0);

	while (1)
	{
		while (*child_ptr == '/') {
			++child_ptr;
		}

		if (*child_ptr == '\0')
		{
			break;
		}

		p = child;
		while (*child_ptr != '/' && *child_ptr != '\0')
		{
			*(p++) = *(child_ptr++);
		}
		*p = '\0';

		if (strcmp(child, ".") == 0)
		{
			continue;
		}

		if (strcmp(child, "..") == 0)
		{
			path_buff_up(&ready);
			currdir = open(ready.mem, O_RDONLY | O_NOFOLLOW);
			assert(currdir >= 0);
			continue;
		}

		if (fstatat(currdir, child, &st, AT_SYMLINK_NOFOLLOW) < 0)
		{
			report_error(ready.mem, child, errno);
			goto terminate;
		}

		if (!S_ISLNK(st.st_mode))
		{
			if (!*child_ptr && !S_ISDIR(st.st_mode))
			{
				path_buff_push(&ready, child);
				break;
			}

			/* change dir */
			nextdir = openat(currdir, child, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
			if (nextdir < 0)
			{
				report_error(ready.mem, child, errno);
				goto terminate;
			}
			currdir = nextdir;

			path_buff_push(&ready, child);
			path_buff_push(&ready, "/");
			continue;
		}

		if (x_readlinkat(currdir, child, &link) < 0)
		{
			goto terminate;
		}

		path_buff_push(&link, child_ptr);
		path_buff_set(&toresolve, link.mem);
		path_buff_set(&ready, "/");

		child_ptr = toresolve.mem;

		currdir = open("/", O_RDONLY);
		assert(currdir >= 0);
	}

	report_path(ready.mem);

terminate:
	path_buff_free(&toresolve);
	path_buff_free(&link);
	path_buff_free(&ready);
}
