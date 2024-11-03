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

struct path
{
	struct path *next;
	char name[BUFF_SIZE + 1];
};

struct path *path_new(const char* str)
{
	char *ch = NULL;
	struct path *p = NULL, *head = NULL;

	while (*str)
	{
		while (*str == '/')
		{
			str++;
		}

		if (*str == '\0')
		{
			break;
		}

		if (!head)
		{
			head = fs_xzalloc(sizeof(*p));
			p = head;
			ch = p->name;
		}
		else
		{
			p->next = fs_xzalloc(sizeof(*p));
			p = p->next;
			ch = p->name;
		}

		while (*str != '/' && *str != '\0')
		{
			*(ch++) = *(str++);
		}
	}

	return head;
}

void path_detach(struct path *dst, struct path *until)
{
	assert(dst);

	if (!until)
	{
		return;
	}

	if (dst->next == until)
	{
		dst->next = NULL;
		return;
	}

	path_detach(dst->next, until);
}

void path_append(struct path *dst, struct path *src)
{
	assert(dst);

	if (!dst->next)
	{
		dst->next = src;
		return;
	}

	path_append(dst->next, src);
}

void path_free(struct path* p)
{
	if (!p)
	{
		return;
	}

	path_free(p->next);
	p->next = NULL;
	fs_xfree(p);
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

char *path_format(const struct path *p)
{
	const struct path *ptr = p;
	size_t sz = 1;
	char *res = NULL, *ch = NULL;

	for (ptr = p; ptr; ptr = ptr->next)
	{
		sz += 1;
		sz += strlen(ptr->name);
	}

	res = fs_xmalloc(sz);
	ch = res;

	for (ptr = p; ptr; ptr = ptr->next)
	{
		*(ch++) = '/';
		strcpy(ch, ptr->name);
		ch += strlen(ptr->name);
	}

	return res;
}

void abspath(const char *path)
{
	char link[PATH_MAX + 1], *res = NULL;
	int currdir = -1, nextdir = -1;
	struct stat st;
	struct path *toresolve, *curr, *p;

	toresolve = path_new(path);
	curr = toresolve;

	currdir = open("/", O_RDONLY);
	assert(currdir >= 0);

	while (curr)
	{
		if (strcmp(curr->name, ".") == 0)
		{
			curr = curr->next;
			continue;
		}

		if (strcmp(curr->name, "..") == 0)
		{
			nextdir = openat(currdir, "..", O_RDONLY | O_NOFOLLOW);
			if (nextdir < 0)
			{
				report_error("STUB1", curr->name, errno);
				goto terminate;
			}

			close(currdir);
			currdir = nextdir;
			nextdir = -1;

			curr = curr->next;
			continue;
		}

		if (fstatat(currdir, curr->name, &st, AT_SYMLINK_NOFOLLOW) < 0)
		{
			report_error("STUB2", curr->name, errno);
			goto terminate;
		}

		if (!S_ISLNK(st.st_mode))
		{
			if (!curr->next && !S_ISDIR(st.st_mode))
			{
				break;
			}

			/* change dir */
			nextdir = openat(currdir, curr->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
			if (nextdir < 0)
			{
				report_error("STUB3", curr->name, errno);
				goto terminate;
			}

			close(currdir);
			currdir = nextdir;
			nextdir = -1;

			curr = curr->next;
			continue;
		}

		if (x_readlinkat(currdir, curr->name, link) < 0)
		{
			goto terminate;
		}

		p = path_new(link);
		path_append(p, curr->next);
		path_detach(toresolve, curr->next);
		path_free(toresolve);
		curr = p;
		toresolve = p;

		close(currdir);
		currdir = open("/", O_RDONLY);
		assert(currdir >= 0);
	}

	res = path_format(toresolve);
	report_path(res);

terminate:
	fs_xfree(res);

	if (currdir >= 0)
	{
		close(currdir);
	}

	if (nextdir >= 0)
	{
		close(nextdir);
	}

	path_free(toresolve);
}
