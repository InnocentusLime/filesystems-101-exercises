#include <solution.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#define START_CAP 64

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

static ssize_t x_readlink(
	struct path_buff *restrict path,
	struct path_buff *restrict buff
)
{
	int err;
	ssize_t n;

	while ((n = readlink(path->mem, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
	{
		path_buff_grow(buff);
	}

	err = errno;
	if (n < 0)
	{
		report_error("ERR2", "", err);
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
	struct stat st;
	struct path_buff resolved_path, buff, childbuff, linkbuff, constructed_path;
	char *child, *child_end;

	constructed_path = path_buff_new();
	resolved_path = path_buff_new();
	buff = path_buff_new();
	childbuff = path_buff_new();
	linkbuff = path_buff_new();

	path_buff_put_char(&resolved_path, '/');
	while (*path == '/')
	{
		path++;
	}
	path_buff_push(&resolved_path, path);

	child = resolved_path.mem;

	while (1)
	{
		/* 0. Nudge if we are on a slash */
		while (*(child++) == '/') { }

		/* 1. locate child */
		child_end = child;
		while (*child_end != '\0' && *child_end != '/')
		{
			child_end++;
		}

		if (child == child_end)
		{
			break; // we failed to progress
		}

		path_buff_set(&childbuff, "");
		path_buff_cpy_push(&childbuff, child, child_end - child);

		/* 2. lstat child by its absolute path */
		path_buff_set(&buff, "");
		path_buff_cpy_push(&buff, resolved_path.mem, child_end - resolved_path.mem);
		if (lstat(buff.mem, &st) < 0)
		{
			err = errno;
			report_error("ERR1", childbuff.mem, err);
			return;
		}

		/* 3. check */
		if (!S_ISLNK(st.st_mode))
		{
			child = child_end;
			continue;
		}

		/* 4. symlinks make us backtrack */
		if (x_readlink(&buff, &linkbuff) < 0)
		{
			return;
		}

		path_buff_set(&buff, "");
		path_buff_push(&buff, linkbuff.mem);
		path_buff_push(&buff, child_end);
		path_buff_set(&resolved_path, buff.mem);

		child = resolved_path.mem;
	}

	report_path(resolved_path.mem);

	path_buff_free(&resolved_path);
	path_buff_free(&buff);
	path_buff_free(&linkbuff);
	path_buff_free(&childbuff);
	path_buff_free(&constructed_path);
}