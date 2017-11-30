#ifndef _PJ_REGFILE_H
#define _PJ_REGFILE_H

#include "files.h"
#include "int.h"

int
pico_dump_regfile(int lfd, u32 id, const struct fd_parms *p);

int
pico_open_regfile(struct file_desc *fd, int *new_fd);

extern const struct fdtype_ops pico_regfile_dump_ops;

#endif /* _PJ_REGFILE_H */
