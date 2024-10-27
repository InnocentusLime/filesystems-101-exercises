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
	const char *restrict path,
	struct path_buff *restrict buff
)
{
	ssize_t n;

	while ((n = readlink(path, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
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
	char child[BUFF_SIZE + 1], *child_ptr, *p, *parent = NULL;
	struct stat st;
	struct path_buff toresolve, buff;

	toresolve = path_buff_new();
	buff = path_buff_new();

	path_buff_set(&toresolve, "/");
	path_buff_push(&toresolve, path);

	child_ptr = toresolve.mem;

	assert(chdir("/") == 0);

	while (*child_ptr)
	{
		while (*child_ptr == '/')
		{
			++child_ptr;
		}

		for (p = child; *child_ptr != '/' && *child_ptr != '\0';)
		{
			*(p++) = *(child_ptr++);
		}
		*p = 0;

		if (strcmp(child, ".") == 0)
		{
			continue;
		}

		if (strcmp(child, "..") == 0)
		{
			assert(chdir("..") == 0);
			continue;
		}

		parent = getcwd(NULL, 0);

		if (lstat(child, &st) < 0)
		{
			report_error(parent, child, errno);
			goto terminate;
		}

		if (!S_ISLNK(st.st_mode))
		{
			if (*child_ptr == '\0')
			{
				continue;
			}

			if(chdir(child) < 0)
			{
				report_error(parent, child, errno);
				goto terminate;
			}

			continue;
		}

		x_readlink(child, &buff);
		path_buff_push(&buff, child_ptr);
		path_buff_set(&toresolve, buff.mem);

		child_ptr = toresolve.mem;
		assert(chdir("/") == 0);

		free(parent); parent = NULL;
	}

	parent = getcwd(NULL, 0);
	path_buff_set(&buff, parent);
	path_buff_push(&buff, "/");
	path_buff_push(&buff, child);

	report_path(buff.mem);

terminate:
	path_buff_free(&toresolve);
	path_buff_free(&buff);
	free(parent);
}
