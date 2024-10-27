#include <solution.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

#define BUFFER_SIZE 255

struct string_buff
{
	char* mem;
	size_t cap;
};

static struct string_buff string_buff_new()
{
	struct string_buff res;

	res.mem = malloc(16);
	res.cap = 16;

	assert(res.mem);

	return res;
}

static void string_buff_grow(struct string_buff *buff)
{
	// realloc promises to free the mem
	char* new = realloc(buff->mem, buff->cap * 2);
	assert(new);

	buff->mem = new;
	buff->cap *= 2;
}

static void string_buff_free(struct string_buff *buff)
{
	free(buff->mem);

	buff->cap = 0;
	buff->mem = NULL;
}

struct str_ptr_buff
{
	char** mem;
	size_t cap;
};

static struct str_ptr_buff str_ptr_buff_new()
{
	struct str_ptr_buff res;

	res.mem = malloc(4 * sizeof(char*));
	res.cap = 4;

	assert(res.mem);

	return res;
}

static void str_ptr_buff_prep_cap(struct str_ptr_buff* buff, size_t required)
{
	if (buff->cap >= required)
	{
		return;
	}

	char** new = realloc(buff->mem, required * 2 * sizeof(char*));
	assert(new);

	buff->mem = new;
	buff->cap = required * 2;
}

static void str_ptr_buff_free(struct str_ptr_buff* buff)
{
	free(buff->mem);

	buff->mem = NULL;
	buff->cap = 0;
}

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
	struct string_buff *restrict buff
)
{
	int err;
	ssize_t n;

	while ((n = readlink(pathname, buff->mem, buff->cap - 1)) == (ssize_t)(buff->cap - 1))
	{
		string_buff_grow(buff);
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

static ssize_t read_to_eof(const char* path, struct string_buff* buff)
{
	int f, err;
	ssize_t n = 0;
	ptrdiff_t off = 0;

	f = open(path, O_RDONLY);

	while ((n = read(f, buff->mem + off, buff->cap - (size_t)off)) != 0)
	{
		off += n;

		if ((size_t)off >= buff->cap)
		{
			string_buff_grow(buff);
		}
	}

	err = errno;
	if (n < 0)
	{
		report_error(path, err);
	}

	close(f);

	return n < 0 ? -1 : (ssize_t)off;
}

static void split_record(char* str, size_t buffsz, struct str_ptr_buff* out)
{
	int rec_cnt = 0;
	char* start = str;
	char** ptr = NULL;

	for (ptrdiff_t i = 0; i < (ptrdiff_t)buffsz; ++i)
	{
		if (str[i] == '\0')
		{
			rec_cnt++;
		}
	}

	str_ptr_buff_prep_cap(out, rec_cnt + 1);
	out->mem[rec_cnt] = NULL;
	ptr = out->mem;

	for (ptrdiff_t i = 0; i < (ptrdiff_t)buffsz; ++i)
	{
		if (str[i] == '\0')
		{
			*ptr = start;
			start = str + (i + 1);
			++ptr;
		}
	}
}

void ps(void)
{
	DIR *proc = NULL;
	char path[BUFFER_SIZE + 1];
	struct dirent *ent = NULL;
	int pid = 0;
	ssize_t arglen = 0, envlen = 0;
	struct string_buff exe_buff, arg_buff, env_buff;
	struct str_ptr_buff argv, envp;

 	proc = opendir("/proc");
	exe_buff = string_buff_new();
	arg_buff = string_buff_new();
	env_buff = string_buff_new();
	argv = str_ptr_buff_new();
	envp = str_ptr_buff_new();

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
		if (x_readlink(path, &exe_buff) < 0)
		{
			continue;
		}

		/* Parse the arguments */
		snprintf(path, BUFFER_SIZE, "/proc/%d/cmdline", pid);
		arglen = read_to_eof(path, &arg_buff);
		if (arglen < 0)
		{
			continue;
		}
		split_record(arg_buff.mem, arglen, &argv);

		/* Parse the env */
		snprintf(path, BUFFER_SIZE, "/proc/%d/environ", pid);
		envlen = read_to_eof(path, &env_buff);
		if (envlen < 0)
		{
			continue;
		}
		split_record(env_buff.mem, envlen, &envp);

		report_process(pid, exe_buff.mem, argv.mem, envp.mem);
	}

	closedir(proc);
	string_buff_free(&exe_buff);
	string_buff_free(&arg_buff);
	string_buff_free(&env_buff);
	str_ptr_buff_free(&argv);
	str_ptr_buff_free(&envp);
}
