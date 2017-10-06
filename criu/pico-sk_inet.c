#include <fcntl.h>
#include <net/if.h>
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
#include "sk-inet.h"
#include "namespaces.h"

#include "pico-sk_inet.h"
#include "binsearch.h"
#include "quicksort.h"

#define SHUTDOWN    0
#define CONTAINS_SK 1
#define REQUEST_SK  2

#define PB_ALEN_INET    1
#define PB_ALEN_INET6   4

static int next_id = 100000;

static struct dumped_id dumped_fds_data[1024] = { 0 };
static int dumped_fds_size = 0;
static array dumped_fds;

static FileEntry *file_ents[1024] = { 0 };
static int file_ents_size = 0;

static int pico_collect_one_file(void *o, ProtobufCMessage *base, struct cr_img *i);

static int pico_open_inet_sk(struct file_desc *d, int *new_fd);
static int pico_post_open_inet_sk(struct file_desc *d, int sk);

static int pico_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p);

struct file_desc_ops pico_inet_desc_ops = {
    .type = FD_TYPES__INETSK,
    .open = pico_open_inet_sk
};

struct fdtype_ops pico_inet_dump_ops = {
    .type       = FD_TYPES__INETSK,
    .dump       = pico_dump_one_inet_fd,
};

static char
comp_dumped_id(void *a, void *b)
{
    struct dumped_id *x = a;
    struct dumped_id *y = b;

    if (x->old_id < y->old_id)
        return 1;
    else if (x->old_id > y->old_id)
        return -1;
    else
        return 0;
}

static int
pico_do_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p, int family)
{
	struct inet_sk_desc *sk;
	FileEntry fe = FILE_ENTRY__INIT;
	InetSkEntry ie = INET_SK_ENTRY__INIT;
	IpOptsEntry ipopts = IP_OPTS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	int ret = -1, err = -1, proto;

	ret = do_dump_opt(lfd, SOL_SOCKET, SO_PROTOCOL,
					&proto, sizeof(proto));
	if (ret)
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
	if (sk->sd.sk_ns) {
		ie.ns_id	= sk->sd.sk_ns->id;
		ie.has_ns_id	= true;
	}
	ie.family	= family;
	ie.proto	= proto;
	ie.type		= sk->type;
	ie.src_port	= sk->src_port;
	ie.dst_port	= sk->dst_port;
	ie.backlog	= sk->wqlen;
	ie.flags	= p->flags;

	ie.fown		= (FownEntry *)&p->fown;
	ie.opts		= &skopts;
	ie.ip_opts	= &ipopts;

	ie.n_src_addr = PB_ALEN_INET;
	ie.n_dst_addr = PB_ALEN_INET;
	if (ie.family == AF_INET6) {
		int val;
		char device[IFNAMSIZ];
		socklen_t len = sizeof(device);

		ie.n_src_addr = PB_ALEN_INET6;
		ie.n_dst_addr = PB_ALEN_INET6;

		ret = dump_opt(lfd, SOL_IPV6, IPV6_V6ONLY, &val);
		if (ret < 0)
			goto err;

		ie.v6only = val ? true : false;
		ie.has_v6only = true;

		/* ifindex only matters on source ports for bind, so let's
		 * find only that ifindex. */
		if (sk->src_port && needs_scope_id(sk->src_addr)) {
			if (getsockopt(lfd, SOL_SOCKET, SO_BINDTODEVICE, device, &len) < 0) {
				pr_perror("can't get ifname");
				goto err;
			}

			if (len > 0) {
				ie.ifname = xstrdup(device);
				if (!ie.ifname)
					goto err;
			} else {
				pr_err("couldn't find ifname for %d, can't bind\n", id);
				goto err;
			}
		}
	}

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

	pr_info("Dumping inet socket at %d\n", p->fd);
	show_one_inet("Dumping", sk);
	show_one_inet_img("Dumped", &ie);
	sk->sd.already_dumped = 1;
	sk->cpt_reuseaddr = skopts.reuseaddr;

	ie.state = sk->state;

	fe.type = FD_TYPES__INETSK;
	fe.id = ie.id;
	fe.isk = &ie;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		goto err;

    // send file descriptor to sk-holder
    int rsk = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un rskaddr = { 0 };
    rskaddr.sun_family = AF_UNIX;
    strcpy(rskaddr.sun_path, opts.pico_pin_fds);

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

static int
pico_dump_one_inet_fd(int lfd, u32 id, const struct fd_parms *p)
{
    return pico_do_dump_one_inet_fd(lfd, id, p, PF_INET);
}

static int
pico_open_inet_sk(struct file_desc *d, int *new_fd)
{
    int ret = -1;
	struct fdinfo_list_entry *fle = file_master(d);

	if (fle->stage >= FLE_OPEN)
		return pico_post_open_inet_sk(d, fle->fe->fd);

    // recv file descriptor from sk-holder
    int rsk = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un rskaddr = { 0 };
    rskaddr.sun_family = AF_UNIX;
    strcpy(rskaddr.sun_path, opts.pico_pin_fds);

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
    buf[1] = file_master(d)->fe->fd;
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
    pr_debug("CONNOR: (criufd, procfd) = (%d, %d)\n", ret, file_master(d)->fe->fd);
    pr_debug("CONNOR: CMSG_LEN = %lu\n", msg.msg_controllen);

err:
    free(cmptr);
connerr:
    close(rsk);

    *new_fd = ret;

    return 0;
}

static int
pico_post_open_inet_sk(struct file_desc *d, int sk)
{
    return 0;
}

struct collect_image_info pico_files_cinfo = {
	.fd_type = CR_FD_FILES,
	.pb_type = PB_FILE,
	.priv_size = 0,
	.collect = pico_collect_one_file,
    .flags = COLLECT_NOFREE,
};

static int
pico_collect_one_file(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	FileEntry *fe;

	fe = pb_msg(base, FileEntry);

    file_ents[file_ents_size] = fe;
    file_ents_size++;

    return 0;
}

static int
collect_image_at_once(int dfd, struct collect_image_info *cinfo)
{
    int ret;
    struct cr_img *img;
    void *(*o_alloc)(size_t size) = malloc;
    void (*o_free)(void *ptr) = free;

    pr_info("Collecting %d/%d (flags %x)\n",
            cinfo->fd_type, cinfo->pb_type, cinfo->flags);

    img = open_image_at(dfd, cinfo->fd_type, O_RSTR);
    if (!img)
        return -1;

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

        cinfo->flags |= COLLECT_HAPPENED;
        ret = cinfo->collect(obj, msg, img);
        if (ret < 0) {
            o_free(obj);
            cr_pb_descs[cinfo->pb_type].free(msg, NULL);
            break;
        }

        if (!cinfo->priv_size && !(cinfo->flags & COLLECT_NOFREE))
            cr_pb_descs[cinfo->pb_type].free(msg, NULL);
    }

    close_image(img);
    pr_debug(" `- ... done\n");
    return ret;
}

void
pico_dump_cache_fds(array *fdarr, int *fdarr_data, int fdarr_size, struct pstree_item *item, struct cr_img *img)
{
    int i;
    struct cr_img *fdimg;

    if (!opts.pico_cache)
        return;

    array_init(&dumped_fds, 1024, comp_dumped_id);
    for (i = 0; i < dumped_fds_size; i++)
        dumped_fds.elems[i] = &dumped_fds_data[i];

    // 0. populate fdarr with fdarr_data
    for (i=0; i<fdarr_size; i++)
        fdarr->elems[i] = &fdarr_data[i];

    // 1. sort fdarr
    quicksort(0, fdarr_size-1, fdarr);

    // 2. open old fdinfo and 'files' files
    int dfd = open(opts.pico_cache, O_RDONLY);
    fdimg = open_image_at(dfd, CR_FD_FDINFO, O_RSTR, item->ids->files_id);

    if (!fdimg) {
        pr_err("CONNOR: fdinfo image not in cache!\n");
        return;
    }

    if (collect_image_at_once(dfd, &pico_files_cinfo))
        return;

    // populate array, sort inetskentry array and use for binary search
    array skarr;
    array_init(&skarr, file_ents_size, comp_FileEntry);
    for (i=0; i<file_ents_size; i++)
        skarr.elems[i] = file_ents[i];

    quicksort(0, skarr.size-1, &skarr);

    while (1) {
        FdinfoEntry *e;
        int ret_fd;

        ret_fd = pb_read_one_eof(fdimg, &e, PB_FDINFO);
        if (ret_fd <= 0)
            break;

        // 2. if fdinfo->fd has not been dumped (is not in fdarr):
        int other = e->fd;
        if (!binsearch(fdarr, &other, 0, fdarr_size-1)) {
            // 2b. dump old file entry
            FileEntry other_file;
            other_file.id = e->id;
            FileEntry *fe = binsearch(&skarr, &other_file, 0, skarr.size-1);

            if (fe != NULL && e->pico_addr != opts.pico_addr.s_addr) {
                quicksort(0, dumped_fds_size-1, &dumped_fds);
                struct dumped_id other_id = { .old_id = e->id };
                struct dumped_id *di = binsearch(&dumped_fds, &other_id, 0, dumped_fds_size-1);
                if (di == NULL) {
                    // record dumped_id; create new_id
                    dumped_fds_data[dumped_fds_size].old_id = e->id;
                    dumped_fds_data[dumped_fds_size].new_id = next_id;
                    dumped_fds.elems[dumped_fds_size] = &dumped_fds_data[dumped_fds_size];

                    // fixup new id
                    fe->id = next_id;
                    switch (fe->type) {
                        case FD_TYPES__INETSK:
                            fe->isk->id = next_id;
                            break;
                        case FD_TYPES__REG:
                            fe->reg->id = next_id;
                            break;
                        default:
                            break;
                    }

                    // dump file
                    pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), fe, PB_FILE);

                    // reset ie->id
                    // TODO connor's shit coding practice
                    fe->id = dumped_fds_data[dumped_fds_size].old_id;

                    // set e->id
                    e->id = next_id;

                    next_id++;
                    dumped_fds_size++;
                }
                else {
                    // set e->id based on already dumped_id
                    e->id = di->new_id;
                }

                // 2a. dump old fdinfo
                pb_write_one(img, e, PB_FDINFO);

                pr_debug("CONNOR: copied cached fd %d\n", e->fd);
            }
            else {
                pr_debug("CONNOR: skipping cached fd %d\n", e->fd);
            }
        }

        fdinfo_entry__free_unpacked(e, NULL);
    }

    close_image(fdimg);
    close(dfd);
    array_free(&skarr);
    array_free(&dumped_fds);
}

char
comp_fds(void *a, void *b)
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

char
comp_FileEntry(void *a, void *b)
{
    FileEntry *x = a;
    FileEntry *y = b;

    if (x->id < y->id)
        return 1;
    else if (x->id > y->id)
        return -1;
    else
        return 0;
}
