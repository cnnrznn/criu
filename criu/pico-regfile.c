#include "pico-regfile.h"

#include <stdio.h>

#include "external.h"
#include "files-reg.h"
#include "imgset.h"
#include "mount.h"
#include "namespaces.h"
#include "pico-sk_inet.h"
#include "protobuf.h"
#include "xmalloc.h"

const struct fdtype_ops pico_regfile_dump_ops = {
	.type		= FD_TYPES__REG,
	.dump		= pico_dump_regfile,
};

int
pico_dump_regfile(int lfd, u32 id, const struct fd_parms *p)
{
	struct fd_link _link, *link;
	struct ns_id *nsid;
	struct cr_img *rimg;
	char ext_id[64];
	FileEntry fe = FILE_ENTRY__INIT;
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;



	snprintf(ext_id, sizeof(ext_id), "file[%x:%"PRIx64"]", p->mnt_id, p->stat.st_ino);
	if (external_lookup_id(ext_id)) {
		/* the first symbol will be cut on restore to get an relative path*/
		rfe.name = xstrdup(ext_id);
		rfe.ext = true;
		rfe.has_ext = true;
		goto ext;
	}

	nsid = lookup_nsid_by_mnt_id(p->mnt_id);
	if (nsid == NULL) {
		pr_err("Can't lookup mount=%d for fd=%d path=%s\n",
			p->mnt_id, p->fd, link->name + 1);
		return -1;
	}

	if (p->mnt_id >= 0 && (root_ns_mask & CLONE_NEWNS)) {
		rfe.mnt_id = p->mnt_id;
		rfe.has_mnt_id = true;
	}

	pr_info("Dumping path for %d fd via self %d [%s]\n",
			p->fd, lfd, &link->name[1]);

	/*
	 * The regular path we can handle should start with slash.
	 */
	if (link->name[1] != '/') {
		pr_err("The path [%s] is not supported\n", &link->name[1]);
		return -1;
	}

	if (check_path_remap(link, p, lfd, id, nsid))
		return -1;
	rfe.name	= &link->name[1];
ext:
	rfe.id		= id;
	rfe.flags	= p->flags;
	rfe.pos		= p->pos;
	rfe.fown	= (FownEntry *)&p->fown;
	rfe.has_mode	= true;
	rfe.mode	= p->stat.st_mode;

	if (S_ISREG(p->stat.st_mode) && should_check_size(rfe.flags)) {
		rfe.has_size = true;
		rfe.size = p->stat.st_size;
	}

	fe.type = FD_TYPES__REG;
	fe.id = rfe.id;
	fe.reg = &rfe;

    // send lfd to manager
    pico_send_fd(p->fd, lfd);

	rimg = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(rimg, &fe, PB_FILE);
}

int
pico_open_regfile(struct file_desc *d, int *new_fd)
{
	int tmp = -1;

    // retrieve file descriptor from manager
    pico_rtrv_fd(file_master(d)->fe->fd, &tmp);

	if (tmp < 0)
		return -1;
	*new_fd = tmp;
	return 0;
}
