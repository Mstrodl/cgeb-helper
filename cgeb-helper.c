// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CGEB userspace helper
 *
 * Copyright (c) 2024 Mary Strodl
 *
 * Based on code from Congatec AG, Sascha Hauer, and Evgeniy Polyakov
 *
 * CGEB is a BIOS interface found on congatech modules. It consists of
 * code found in the BIOS memory map which is called in a ioctl like
 * fashion. This program provides a userspace component to the Linux
 * driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/io.h>
#include <sys/mman.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>

#include <linux/connector.h>

#define CN_IDX_CGEB			0xB	/* congatec CGEB */
#define CN_VAL_CGEB			0x1

#pragma pack(push,4)

struct cgeb_low_desc {
	char magic[8];          /* descriptor magic string */
	uint16_t size;               /* size of this descriptor */
	uint16_t reserved;
	char bios_name[8];      /* BIOS name and revision "ppppRvvv" */
	uint32_t hi_desc_phys_addr;  /* phys addr of the high descriptor, can be 0 */
};

/* CGEB High Descriptor located in 0xfff00000-0xffffffff */
#ifdef CONFIG_X86_64
#define CGEB_HD_MAGIC "$CGEBQD$"
#else
#define CGEB_HD_MAGIC "$CGEBHD$"
#endif

struct cgeb_high_desc {
	char magic[8];          /* descriptor magic string */
	uint16_t size;               /* size of this descriptor */
	uint16_t reserved;
	uint32_t data_size;          /* CGEB data area size */
	uint32_t code_size;          /* CGEB code area size */
	uint32_t entry_rel;          /* CGEB entry point relative to start */
};

struct cgeb_far_ptr {
	void* off;
	uint16_t seg;
	uint16_t pad;
};

struct cgeb_fps {
	uint32_t size;               /* size of the parameter structure */
	uint32_t fct;                /* function number */
	struct cgeb_far_ptr data;       /* CGEB data area */
	void* cont;             /* private continuation pointer */
	void* subfps;           /* private sub function parameter
				 * structure pointer
				 */
	void* subfct;           /* sub function pointer */
	uint32_t status;             /* result codes of the function */
	uint32_t unit;               /* unit number or type */
	uint32_t pars[4];            /* input parameters */
	uint32_t rets[2];            /* return parameters */
	void *iptr;             /* input pointer */
	void *optr;             /* output pointer */
};

/* continuation status codes */
#define CGEB_SUCCESS            0
#define CGEB_NEXT               1
#define CGEB_DELAY              2
#define CGEB_NOIRQS             3

#define CGEB_DBG_STR        0x100
#define CGEB_DBG_HEX        0x101
#define CGEB_DBG_DEC        0x102

struct cgeb_map_mem {
	void* phys;             /* physical address */
	uint32_t size;               /* size in bytes */
	struct cgeb_far_ptr virt;
};

struct cgeb_map_mem_list {
	uint32_t count;              /* number of memory map entries */
	struct cgeb_map_mem entries[];
};

#pragma pack(pop)

struct cgeb_board {
	void* code;
	#if __x86_64__
	void (*entry)(void*, struct cgeb_fps *, struct cgeb_fps *, void*);
	#else
	/*
	 * entry points to a bimodal C style function that expects a far pointer
	 * to a fps. If cs is 0 then it does a near return, otherwise a far
	 * return. If we ever need a far return then we must not pass cs at all.
	 * parameters are removed by the caller.
	 */
	void __attribute__((regparm(0)))(*entry)(unsigned short,
			  struct cgeb_fps *, unsigned short);
	#endif
	int mem_fd;
};

#define NETLINK_CONNECTOR 	11

#define DEBUG
#ifdef DEBUG
#define ulog(f, a...) fprintf(stdout, f, ##a)
#else
#define ulog(f, a...) do {} while (0)
#endif

static int need_exit;
static FILE *log_output;
static __u32 seq;

enum cgeb_msg_type {
	CGEB_MSG_ACK = 0,
	CGEB_MSG_ERROR,
	CGEB_MSG_FPS,
	CGEB_MSG_MAPPED,
	CGEB_MSG_MAP,
	CGEB_MSG_CODE,
	CGEB_MSG_ALLOC,
	CGEB_MSG_ALLOC_CODE,
	CGEB_MSG_FREE,
	CGEB_MSG_MUNMAP,
	CGEB_MSG_CALL,
	CGEB_MSG_PING,
};

struct cgeb_msg {
	enum cgeb_msg_type type;
	union {
		struct cgeb_msg_mapped {
			void* virt;
		} mapped;
		struct cgeb_msg_fps {
			size_t optr_size;
			void* optr;
			struct cgeb_fps fps;
		} fps;
		struct cgeb_msg_code {
			size_t length;
			uint32_t entry_rel;
			void* data;
		} code;
		struct cgeb_msg_map {
			uint32_t phys;
			size_t size;
		} map;
	};
};

static int netlink_send(int s, struct cn_msg *msg)
{
	struct nlmsghdr *nlh;
	unsigned int size;
	int err;
	char buf[NLMSG_SPACE(sizeof(struct cgeb_msg) + sizeof(struct cn_msg))];
	struct cn_msg *m;

	size = NLMSG_SPACE(sizeof(struct cn_msg) + msg->len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq = seq++;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = 0;

	m = NLMSG_DATA(nlh);
#if 0
	ulog("%s: [%08x.%08x] len=%u, seq=%u, ack=%u.\n",
	       __func__, msg->id.idx, msg->id.val, msg->len, msg->seq, msg->ack);
#endif
	memcpy(m, msg, sizeof(*m) + msg->len);

	err = send(s, nlh, size, 0);
	if (err == -1)
		ulog("Failed to send: %s [%d].\n",
			strerror(errno), errno);

	return err;
}

static void usage(void)
{
	printf(
		"Usage: ucon [options] [output file]\n"
		"\n"
		"\t-h\tthis help screen\n"
		"\t-s\tsend buffers to the test module\n"
		"\n"
		"The default behavior of ucon is to subscribe to the test module\n"
		"and wait for state messages.  Any ones received are dumped to the\n"
		"specified output file (or stdout).  The test module is assumed to\n"
		"have an id of {%u.%u}\n"
		"\n"
		"If you get no output, then verify the cn_test module id matches\n"
		"the expected id above.\n"
		, CN_IDX_CGEB, CN_VAL_CGEB
	);
}

static struct cgeb_msg handle_message(struct cgeb_msg* msg, struct cgeb_board* board) {
	ulog("Got message of type: %d\n", msg->type);
	struct cgeb_msg out = {0};
	switch(msg->type) {
	case CGEB_MSG_CODE:
		board->code = msg->code.data;
		ulog("Attempting to mark page at %p executable\n", board->code);
		/* Allow exec. Sadly, it seems to need write too... */
		if (mprotect(board->code, msg->code.length,
			     PROT_EXEC | PROT_READ | PROT_WRITE)) {
			perror("Failed to change memory protections");
			ulog("Failed to change memory protections!\n");
		}
		board->entry = (void*)((char*)board->code + msg->code.entry_rel);
		out.type = CGEB_MSG_ACK;
		break;
	case CGEB_MSG_ALLOC:
		out.code.data = malloc(msg->code.length);
		out.type = CGEB_MSG_CODE;
		ulog("Allocated memory for kernel at %p!\n", out.code.data);
		break;
	case CGEB_MSG_ALLOC_CODE:
		if (board->code) {
			ulog("An allocation already exists! D:\n");
		}
		board->code = mmap(NULL, msg->code.length,
				   PROT_READ | PROT_WRITE,
				   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		ulog("We allocated a page at %p\n", board->code);
		out.code.data = board->code;
		out.type = CGEB_MSG_CODE;
		break;
	case CGEB_MSG_MAP:
		out.mapped.virt = mmap(NULL, msg->map.size, PROT_READ,
				       MAP_SHARED, board->mem_fd,
				       msg->map.phys);
		if (out.mapped.virt == MAP_FAILED) {
			ulog("Bad memory: 0x%08x\n", msg->map.phys);
			perror("Failed to map memory!");
		}
		out.type = CGEB_MSG_MAPPED;
		break;
	case CGEB_MSG_CALL:
		out.type = CGEB_MSG_FPS;
		out.fps.fps = msg->fps.fps;
		if (msg->fps.optr_size) {
			out.fps.optr = malloc(msg->fps.optr_size);
			out.fps.fps.optr = out.fps.optr;
			ulog("FPS optr is %p\n", out.fps.optr);
		}
#ifdef __x86_64__
		board->entry(NULL, &out.fps.fps, &out.fps.fps, NULL);
#else
		board->entry(0, &out.fps.fps, out.fps.fps.data.seg);
#endif
		break;
	case CGEB_MSG_FREE:
		ulog("Freeing memory allocated for the kernel at %p!\n",
		     msg->code.data);
		free(msg->code.data);
		out.type = CGEB_MSG_ACK;
		break;
	case CGEB_MSG_MUNMAP:
		ulog("Unmapping memory allocated for the kernel at %p!\n",
		     msg->code.data);
		out.type = CGEB_MSG_ACK;
		if(munmap(msg->code.data, msg->code.length)) {
			perror("Failed to unmap memory");
			ulog("Failed to unmap memory!\n");
			out.type = CGEB_MSG_ERROR;
		}
		break;
	case CGEB_MSG_PING:
		out.type = CGEB_MSG_ACK;
		break;
	default:
		ulog("Unknown message type: %d!\n", msg->type);
		out.type = CGEB_MSG_ERROR;
	}
	ulog("Replying to message! Res=%d\n", out.type);
	return out;
}

int main(int argc, char *argv[])
{
	/* TODO: Which ports? */
	if (iopl(3)) {
		perror("Couldn't set IO permissions!\n");
		ulog("Couldn't set IO permissions!\n");
		return -1;
	}

	log_output = fopen("/tmp/wompwomp", "a");
	int s;
	struct nlmsghdr buf;
	int len;
	struct nlmsghdr *reply;
	struct sockaddr_nl l_local;
	struct cn_msg *data;
	struct cn_msg *response_data;
	struct cgeb_msg response;
	time_t tm;
	struct pollfd pfd;
	struct cgeb_board board = {0};
	board.mem_fd = open("/dev/mem", O_RDONLY);
	if (board.mem_fd < 0) {
		ulog("couldn't open /dev/mem!\n");
		perror("Couldn't open /dev/mem!");
		return -1;
	}

	memset(&buf, 0, sizeof(buf));

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (s == -1) {
		ulog("socket failure\n");
		perror("socket");
		return -1;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = -1; /* bitmask of requested groups */
	l_local.nl_pid = 0;

	ulog("subscribing to %u.%u\n", CN_IDX_CGEB, CN_VAL_CGEB);

	if (bind(s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
		ulog("binding error\n");
		perror("bind");
		close(s);
		return -1;
	}

	/* if (send_msgs) { */
	/* 	int i, j; */

	/* 	memset(&buf, 0, sizeof(buf)); */

	/* 	data = &buf; */

	/* 	data->id.idx = CN_IDX_CGEB; */
	/* 	data->id.val = CN_VAL_CGEB; */
	/* 	data->seq = seq++; */
	/* 	data->ack = 0; */
	/* 	data->len = 0; */

	/* 	for (j=0; j<10; ++j) { */
	/* 		for (i=0; i<1000; ++i) { */
	/* 			len = netlink_send(s, data); */
	/* 		} */

	/* 		ulog("%d messages have been sent to %08x.%08x.\n", i, data->id.idx, data->id.val); */
	/* 	} */

	/* 	return 0; */
	/* } */


	pfd.fd = s;

	while (!need_exit) {
		pfd.events = POLLIN;
		pfd.revents = 0;
		ulog("still pollin'\n");
		switch (poll(&pfd, 1, -1)) {
			case 0:
				ulog("womp womp\n");
				need_exit = 1;
				break;
			case -1:
				if (errno != EINTR) {
					need_exit = 1;
					break;
				}
				continue;
		}
		if (need_exit)
			break;

		memset(&buf, 0, sizeof(buf));
		len = recv(s, &buf, sizeof(buf), MSG_PEEK | MSG_WAITALL);
		if (len == -1) {
			ulog("recv buf bad\n");
			perror("recv buf");
			close(s);
			return -1;
		}
		reply = &buf;

		ulog("msg type! %d\n", reply->nlmsg_type);
		switch (reply->nlmsg_type) {
		case NLMSG_ERROR:
			ulog("Error message received.\n");
			break;
		case NLMSG_DONE:
			len = reply->nlmsg_len;
			reply = (struct nlmsghdr *)malloc(len);
			ulog("Got a message of size %d\n", len);
			len = recv(s, reply, len, MSG_WAITALL);
			if (len == -1) {
				ulog("recv next buf bad\n");
				perror("recv next buf");
				close(s);
				free(reply);
				return -1;
			}
			ulog("Actually got message of size %d!\n", len);
			data = (struct cn_msg *)NLMSG_DATA(reply);

			time(&tm);
			ulog("%.24s : [%x.%x] [%08u.%08u].\n",
				ctime(&tm), data->id.idx, data->id.val, data->seq, data->ack);

			response = handle_message((struct cgeb_msg*) data->data, &board);
			response_data = (struct cn_msg*) malloc(sizeof(response) + sizeof(*data));
			response_data->id.idx = CN_IDX_CGEB;
			response_data->id.val = CN_VAL_CGEB;
			response_data->ack = data->ack;
			response_data->seq = data->seq;

			response_data->len = sizeof(response);
			memcpy(&response_data->data, &response, sizeof(response));
			
			ulog("Sending the message!\n");
			netlink_send(s, response_data);
			ulog("Sent!\n");

			free(reply);


			break;
		default:
			break;
		}
	}

	close(s);
	return 0;
}
