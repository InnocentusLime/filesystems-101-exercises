#include <solution.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

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

static void path_buff_put_char(struct path_buff* buff, char ch)
{
	path_buff_cpy_push(buff, &ch, 1);
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
	if (buff->sz == 0)
	{
		return;
	}

	buff->sz -= 2;
	while (buff->mem[buff->sz] != '/') {
		buff->sz--;
	}

	buff->mem[++buff->sz] = '\0';
}

static ssize_t x_readlink(
	struct path_buff *restrict path,
	struct path_buff *restrict buff
)
{
	ssize_t n;

	while ((n = readlink(path->mem, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
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
	int err;
	char child[BUFF_SIZE + 1], *child_ptr, *p;
	struct stat st;
	struct path_buff ready, toresolve, link, buff;

	ready = path_buff_new();
	toresolve = path_buff_new();
	link = path_buff_new();
	buff = path_buff_new();

	path_buff_set(&toresolve, "/");
	path_buff_push(&toresolve, path);
	path_buff_set(&ready, "/");

	child_ptr = toresolve.mem;

	while (1)
	{
		while (*child_ptr == '/') {
			++child_ptr;
		}

		p = child;
		while (*child_ptr != '/' && *child_ptr != '\0')
		{
			*(p++) = *(child_ptr++);
		}
		*p = '\0';

		if (p == child)
		{
			break;
		}

		if (strcmp(child, ".") == 0)
		{
			continue;
		}

		if (strcmp(child, "..") == 0)
		{
			path_buff_up(&ready);
			continue;
		}

		path_buff_set(&buff, "");
		path_buff_push(&buff, ready.mem);
		path_buff_push(&buff, child);
		if (lstat(buff.mem, &st) < 0)
		{
			err = errno;
			report_error(ready.mem, child, err);
			return;
		}

		path_buff_push(&ready, child);

		if (S_ISDIR(st.st_mode))
		{
			path_buff_put_char(&ready, '/');
			continue;
		}

		if (!S_ISLNK(st.st_mode))
		{
			continue;
		}

		if (x_readlink(&buff, &link) < 0)
		{
			return;
		}

		path_buff_set(&buff, "");
		path_buff_push(&buff, link.mem);
		path_buff_push(&buff, child_ptr);
		path_buff_set(&toresolve, buff.mem);
		path_buff_set(&ready, "/");

		child_ptr = toresolve.mem;
	}

	report_path(ready.mem);

	path_buff_free(&buff);
	path_buff_free(&toresolve);
	path_buff_free(&link);
	path_buff_free(&ready);
}
