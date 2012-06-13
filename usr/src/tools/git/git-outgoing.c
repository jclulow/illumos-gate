/*
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

int vflag = 0;

struct changeline {
	int type;
	char *path;
	struct changeline *next;
};

char known_types[] = "MAD";
#define	TYPE_NAME(c) \
	((c) == 'M' ? "modified" : \
	(c) == 'A' ? "added" : \
	(c) == 'D' ? "deleted" : \
	"unknown")

struct wc {
	pid_t pid;
	int infd;

	int state;

	struct changeline *clist;
};

#define	STATE_PRE_DESC	0
#define	STATE_DESC	1
#define	STATE_CHANGES	2

void
addchange(struct wc *wc, struct changeline *cl)
{
	if (wc->clist == NULL) {
		wc->clist = cl;
	} else {
		struct changeline *last = wc->clist;
		while (last->next != NULL)
			last = last->next;
		last->next = cl;
	}
}

struct wc *
whatchanged(char *parent)
{
	char *treeish;
	struct wc *wc;
	int pd[2];
	int i;

	if (vflag)
		printf("comparing with %s\nsearching for changes\n\n", parent);

	if ((wc = malloc(sizeof (struct wc))) == NULL ||
	    asprintf(&treeish, "%s..", parent) < 0)
		err(10, NULL);
	memset(wc, 0, sizeof (struct wc));

	if (pipe(pd) != 0)
		err(11, NULL);

	switch ((wc->pid = fork())) {
		case -1:
			err(12, "could not fork git");
			break;
		case 0:
			(void) close(pd[0]);
			(void) dup2(pd[1], STDOUT_FILENO);
			(void) close(STDIN_FILENO);
			execlp("git", "git", "whatchanged", treeish, (char *)0);
			break;
	}

	(void) close(pd[1]);
	wc->infd = pd[0];

	return (wc);
}

void
walklines(int fd, void (*func)(char *, void *), void *arg)
{
	char buf[1024];
	int eof = 0;
	int last = -1;

	for (;;) {
		int i;

		if (eof && last == -1)
			break;

		/* get more bytes if we need/have them */
		if (!eof && (last + 1) < (int)sizeof (buf)) {
			int rsz = read(fd, &buf[last + 1],
			    sizeof (buf) - (last + 1));
			if (rsz == 0)
				eof = 1;
			else
				last += rsz;
		}

		for (i = 0; i <= last; i++) {
			if (buf[i] == '\n') {
				char *x;
				buf[i] = '\0';
				x = strdup(buf);
				memmove(buf, &buf[i + 1], (last + 1) - (i + 1));
				func(x, arg);
				free(x);
				last -= i + 1;
				break;
			}
		}
	}
}

char *
trim(char *str)
{
	char *out;
	int len = strlen(str);
	int i;
	int start = 0;
	int end = len - 1;

	/* left trim */
	for (i = start; i <= end; i++) {
		if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
			start++;
		else
			break;
	}
	/* right trim */
	for (i = end; i > start; i--) {
		if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
			end--;
		else
			break;
	}
	out = malloc(end - start + 2);
	if (out == NULL)
		err(27, NULL);
	memcpy(out, &str[start], end - start + 1);
	out[end - start + 1] = 0;
	return (out);
}

struct changeline *
to_changeline(char *line)
{
	char *lasts = NULL;
	int i = 0;
	char *this;
	struct changeline *cl;

	if ((cl = malloc(sizeof (*cl))) == NULL)
		err(29, NULL);

	this = strtok_r(line, " ", &lasts);
	while (this != NULL) {
		switch (++i) {
			case 5:
				if (strlen(this) < 3 || this[1] != '\t')
					errx(36, "malformed changes line");
				cl->type = this[0];
				cl->path = strdup(&this[2]);
				cl->next = NULL;
				break;
		}
		this = strtok_r(NULL, " ", &lasts);
	}
	if (i < 5)
		errx(35, "malformed changes line");
	return (cl);
}

void
printchanges(struct wc *wc)
{
	int l = strlen(known_types);
	int i;
	for (i = 0; i < l; i++) {
		int header = 0;
		char type = known_types[i];
		struct changeline *cl = wc->clist;
		while (cl != NULL) {
			if (cl->type == type) {
				if (!header) {
					printf("%s:\n", TYPE_NAME(cl->type));
					header = 1;
				}
				printf("    %s\n", cl->path);
			}
			cl = cl->next;
		}
	}
}

void
resetchanges(struct wc *wc)
{
	if (wc->clist != NULL) {
		struct changeline *this = wc->clist;
		while (this != NULL) {
			struct changeline *tmp = this;
			this = this->next;

			free(tmp->path);
			free(tmp);
		}
		wc->clist = NULL;
	}
}

void
awesome(char *line, void *arg)
{
	struct wc *wc = arg;
	struct changeline *cl;

	switch (wc->state) {
	case STATE_PRE_DESC:
		if (strlen(line) == 0) {
			printf("\ndescription:\n");
			wc->state = STATE_DESC;
		} else {
			if (strstr(line, "commit ") == line)
				printf("commit: %s\n", &line[7]);
			else
				printf("%s\n", line);
		}
		break;
	case STATE_DESC:
		if (strlen(line) == 0) {
			wc->state = STATE_CHANGES;
			printf("\n");
		} else {
			char *t = trim(line);
			printf("\t%s\n", t);
			free(t);
		}
		break;
	case STATE_CHANGES:
		if (strlen(line) == 0) {
			printchanges(wc);
			printf("\n");
			resetchanges(wc);
			wc->state = STATE_PRE_DESC;
			printf("\n------------------------------------"
			    "--------------\n");
		} else {
			cl = to_changeline(line);
			addchange(wc, cl);
		}
		break;
	}
}

int
main(int argc, char *argv[])
{
	struct wc *wc;
	int c;
	char *parent = "origin/master";

	while ((c = getopt(argc, argv, ":p:v")) != -1) {
		switch (c) {
		case 'v':
			vflag = 1;
			break;
		case 'p':
			parent = optarg;
			break;
		case '?':
			errx(1, "option -%c is not recognised", optopt);
			break;
		case ':':
			errx(1, "option -%c requires an operand", optopt);
			break;
		}
	}

	wc = whatchanged(parent);

	walklines(wc->infd, awesome, wc);
	if (wc->state != STATE_CHANGES)
		errx(17, "did not see all expected sections!");
	printchanges(wc);

	waitpid(wc->pid, NULL, 0);

	return (0);
}
