#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>

#include "cr_options.h"
#include "pstree.h"
#include "protobuf.h"
#include "sk-inet.h"
#include "rst-malloc.h"
#include "imgset.h"
#include "image.h"
#include "images/fdinfo.pb-c.h"
#include "images/sk-inet.pb-c.h"

#include "pico-defs.h"
#include "binsearch.h"
#include "quicksort.h"

#define SHUTDOWN    0
#define CONTAINS_SK 1
#define REQUEST_SK  2

#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4

static InetSkEntry *inet_sk_ents[1024] = { 0 };
static int inet_data_size = 0;
static char has_collect_inet_sks = 0;

static int pico_collect_cache_inet_sks(void*, ProtobufCMessage*, struct cr_img *);

static int pico_open_inet_sk(struct file_desc *d);
static int pico_post_open_inet_sk(struct file_desc *d, int sk);

int pico_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p);

struct file_desc_ops pico_inet_desc_ops = {
	.type = FD_TYPES__INETSK,
	.open = pico_open_inet_sk,
	.post_open = pico_post_open_inet_sk,
};

struct fdtype_ops pico_inet_dump_ops = {
	.type		= FD_TYPES__INETSK,
	.dump		= pico_dump_one_inet_fd,
};

int do_pico_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p, int family)
{
	struct inet_sk_desc *sk;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	IpOptsEntry ipopts = IP_OPTS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1, err = -1, proto;

	ret = do_dump_opt(lfd, SOL_SOCKET, SO_PROTOCOL,
					&proto, sizeof(proto));
	if (ret)
		goto err;

	if (!can_dump_ipproto(p->stat.st_ino, proto))
		goto err;

	sk = (struct inet_sk_desc *)lookup_socket(p->stat.st_ino, family, proto);
	if (IS_ERR(sk))
		goto err;
	if (!sk) {
		sk = gen_uncon_sk(lfd, p, proto);
		if (!sk)
			goto err;
	}

	BUG_ON(sk->sd.already_dumped);

	ie.id		= id;
	ie.ino		= sk->sd.ino;
	ie.family	= family;
	ie.proto	= proto;
	ie.type		= sk->type;
	ie.state	= sk->state;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;

	ie.fown		= (FownEntry *)&p->fown;
	ie.opts		= &skopts;
	ie.ip_opts	= &ipopts;

    ie.pico_addr = opts.pico_addr.s_addr;
    ie.has_pico_addr = true;

	ie.n_src_addr = PB_ALEN_INET;
	ie.n_dst_addr = PB_ALEN_INET;

	ie.src_addr = xmalloc(pb_repeated_size(&ie, src_addr));
	ie.dst_addr = xmalloc(pb_repeated_size(&ie, dst_addr));

	if (!ie.src_addr || !ie.dst_addr)
		goto err;

	memcpy(ie.src_addr, sk->src_addr, pb_repeated_size(&ie, src_addr));
	memcpy(ie.dst_addr, sk->dst_addr, pb_repeated_size(&ie, dst_addr));

	if (dump_ip_opts(lfd, &ipopts))
		goto err;

	if (dump_socket_opts(lfd, &skopts))
		goto err;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_INETSK), &ie, PB_INET_SK))
		goto err;

	pr_info("Dumping inet socket at %d\n", p->fd);
	sk->sd.already_dumped = 1;
	sk->cpt_reuseaddr = skopts.reuseaddr;

    // send file descriptor to sk-holder
    int rsk = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un rskaddr = { 0 };
    rskaddr.sun_family = AF_UNIX;
    strcpy(rskaddr.sun_path, opts.pico_pin_inet_sks);

    if (connect(rsk, (struct sockaddr *)&rskaddr, sizeof(rskaddr))) {
        pr_err("connect");
        goto connerr;
    }

    struct msghdr msg = { 0 };
    struct cmsghdr *cmptr = malloc(CMSG_LEN(sizeof(int)));
    memset(cmptr, 0, CMSG_LEN(sizeof(int)));
    int buf[2] = { 0 };
    struct iovec iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmptr;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type  = SCM_RIGHTS;
    cmptr->cmsg_len   = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(cmptr) = lfd;
    buf[0] = CONTAINS_SK;
    buf[1] = p->fd;

    if (sendmsg(rsk, &msg, 0) < 0) {
        pr_err("sendmsg");
        goto senderr;
    }

    err = 0;

senderr:
    free(cmptr);
connerr:
    close(rsk);

err:
	release_skopts(&skopts);
	xfree(ie.src_addr);
	xfree(ie.dst_addr);
	return err;
}

int pico_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
    return do_pico_dump_one_inet_fd(lfd, id, p, PF_INET);
}

static int pico_open_inet_sk(struct file_desc *d)
{
    int ret = -1;
	struct inet_sk_info *ii;

    ii = container_of(d, struct inet_sk_info, d);
    if (ii->ie->pico_addr != opts.pico_addr.s_addr) {
        pr_warn("CONNOR: fd addr, pico_addr (%d, %d)\n", ii->ie->pico_addr, opts.pico_addr.s_addr);
        return PICO_PINNED_FD;
    }

    // recv file descriptor from sk-holder
    int rsk = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un rskaddr = { 0 };
    rskaddr.sun_family = AF_UNIX;
    strcpy(rskaddr.sun_path, opts.pico_pin_inet_sks);

    if (connect(rsk, (struct sockaddr *)&rskaddr, sizeof(rskaddr))) {
        pr_err("connect");
        goto connerr;
    }

    struct msghdr msg = { 0 };
    struct cmsghdr *cmptr = malloc(CMSG_LEN(sizeof(int)));
    int buf[2] = { 0 };
    struct iovec iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmptr;
    msg.msg_controllen = 0;
    buf[0] = REQUEST_SK;
    buf[1] = currFle->fe->fd;
    pr_debug("Requesting fd %d\n", buf[1]);

    if (sendmsg(rsk, &msg, 0) < 0) {
        pr_perror("sendmsg");
        goto err;
    }

    msg.msg_controllen = CMSG_LEN(sizeof(int));

    if (recvmsg(rsk, &msg, 0) < 0) {
        pr_err("recvmsg");
        goto err;
    }

    ret = *(int*)CMSG_DATA(cmptr);
    pr_debug("CONNOR: (criufd, procfd) = (%d, %d)\n", ret, currFle->fe->fd);
    pr_debug("CONNOR: CMSG_LEN = %lu\n", msg.msg_controllen);

err:
    free(cmptr);
connerr:
    close(rsk);

    return ret;
}

static int pico_post_open_inet_sk(struct file_desc *d, int sk)
{
    return 0;
}

static struct collect_image_info pico_inet_sk_cinfo = {
	.fd_type = CR_FD_INETSK,
	.pb_type = PB_INET_SK,
	.priv_size = sizeof(struct inet_sk_info),
	.collect = pico_collect_cache_inet_sks,
};

static int collect_image_at_once(int dfd, struct collect_image_info *cinfo)
{
    if (has_collect_inet_sks)
        return 0;
    has_collect_inet_sks = 1;

	int ret;
	struct cr_img *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n",
			cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image_at(dfd, cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

		ret = cinfo->collect(obj, msg, img);
		if (ret < 0) {
			o_free(obj);
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
			break;
		}

		if (!cinfo->priv_size)
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
	}

	close_image(img);
	pr_debug(" `- ... done\n");
	return ret;
}

static int pico_collect_cache_inet_sks(void *o, ProtobufCMessage *base, struct cr_img *i)
{
    // 1. add inetskentry to inet_sk_ents
    struct inet_sk_info *ii = o;
    ii->ie = pb_msg(base, InetSkEntry);

    inet_sk_ents[inet_data_size] = ii->ie;
    inet_data_size++;

    return 0;
}

void pico_dump_cache_inet_sks(array *fdarr, int *fdarr_data, int fdarr_size, struct pstree_item *item, struct cr_img *img)
{
    struct cr_img *fdimg;

    if (!opts.pico_cache)
        return;

    fdarr->size = fdarr_size;

    // 0. populate fdarr with fdarr_data
    int i;
    for (i=0; i<fdarr_size; i++)
        fdarr->elems[i] = &fdarr_data[i];

    // 1. sort fdarr
    quicksort(0, fdarr->size-1, fdarr);

    // 1. open old fdinfo and inetsk files
    int dfd = open(opts.pico_cache, O_RDONLY);
	fdimg = open_image_at(dfd, CR_FD_FDINFO, O_RSTR, item->ids->files_id);

	if (!fdimg) {
        pr_err("CONNOR: fdinfo image not in cache!\n");
        return;
    }

    collect_image_at_once(dfd, &pico_inet_sk_cinfo);

    // populate array, sort inetskentry array and use for binary search
    array skarr;
    array_init(&skarr, inet_data_size, comp_InetSkEntry);
    for (i=0; i<inet_data_size; i++)
        skarr.elems[i] = inet_sk_ents[i];
    quicksort(0, skarr.size-1, &skarr);

	while (1) {
		FdinfoEntry *e;
        int ret_fd;

        pr_debug("CONNOR: trying to read one old fdinfo!\n");
		ret_fd = pb_read_one_eof(fdimg, &e, PB_FDINFO);
		if (ret_fd <= 0)
			break;
        pr_debug("CONNOR: successfully read one old fdinfo!\n");

        // 2. if fdinfo->fd has not been dumped (is not in fdarr):
        int other = e->fd;
        if (!binsearch(fdarr, &other, 0, fdarr->size-1)) {
            // 2b. dump old inetsk entry
            InetSkEntry other_inet;
            other_inet.id = e->id;
            InetSkEntry *ie = binsearch(&skarr, &other_inet, 0, skarr.size-1);

            if (ie->pico_addr != opts.pico_addr.s_addr) {
                pb_write_one(img_from_set(glob_imgset, CR_FD_INETSK), ie, PB_INET_SK);
                // TODO BUG only dump InetSkEntry once
                pr_warn("CONNOR: copied old inetsk!\n");

                // 2a. dump old fdinfo
                pb_write_one(img, e, PB_FDINFO);
                pr_debug("CONNOR: copied old fdinfo!\n");
            }
            else {
                pr_debug("CONNOR: skipping cached fd\n");
            }
        }

		fdinfo_entry__free_unpacked(e, NULL);
	}

	close_image(fdimg);
    close(dfd);
    array_free(&skarr);
}

char comp_fds(void *a, void *b)
{
    int *x = a;
    int *y = b;

    if (*x < *y)
        return 1;
    else if (*x > *y)
        return -1;
    else
        return 0;
}

char comp_InetSkEntry(void *a, void *b)
{
    InetSkEntry *x = a;
    InetSkEntry *y = b;

    if (x->id < y->id)
        return 1;
    else if (x->id > y->id)
        return -1;
    else
        return 0;
}
