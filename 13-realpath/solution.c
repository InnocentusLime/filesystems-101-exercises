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

static void path_buff_push(struct path_buff* buff, const char* src)
{
	size_t extra = strlen(src);

	while (buff->cap - buff->sz < extra + 1)
	{
		path_buff_grow(buff);
	}

	strcpy(buff->mem + buff->sz, src);
	buff->sz += extra;
}

static void path_buff_put_char(struct path_buff* buff, char ch)
{
	char tmp[2] = { ch, '\0' };

	path_buff_push(buff, tmp);
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

static char path_buff_last_char(const struct path_buff* buff)
{
	return buff->mem[buff->sz];
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
		report_error("STUB", pathname, err);
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
	char ch;
	const char* remaining = NULL;
	struct path_buff prefix, linkbuff;
	struct stat st;

	remaining = path;
	prefix = path_buff_new();
	linkbuff = path_buff_new();

	path_buff_put_char(&prefix, '/');

	if (*remaining == '/')
	{
		remaining++;
	}

	while ((ch = *(remaining++)))
	{
		if (ch != '/')
		{
			path_buff_put_char(&prefix, ch);
			continue;
		}

		if (lstat(prefix.mem, &st) < 0)
		{
			err = errno;
			report_error("STUB", prefix.mem, err);
			return;
		}

		if (st.st_mode & S_IFDIR)
		{
			path_buff_put_char(&prefix, '/');
			continue; /* All good */
		}

		if (!(st.st_mode & S_IFLNK))
		{
			if (*(remaining + 1))
			{
				printf("File neither dir or link. And it's not done. I am confused.\n");
				return;
			}
			else
			{
				/* It may be us finally reaching the end */
				continue;
			}
		}

		if (x_readlink(prefix.mem, &linkbuff) < 0)
		{
			break;
		}

		path_buff_set(&prefix, linkbuff.mem);
		if (path_buff_last_char(&linkbuff) != '/')
		{
			path_buff_put_char(&prefix, '/');
		}
	}

	if (lstat(prefix.mem, &st) < 0)
	{
		err = errno;
		report_error("STUB", prefix.mem, err);
		return;
	}

	if (st.st_mode & S_IFDIR)
	{
		path_buff_put_char(&prefix, '/');
	}

	report_path(prefix.mem);

	path_buff_free(&prefix);
	path_buff_free(&linkbuff);
}
