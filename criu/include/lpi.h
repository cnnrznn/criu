#ifndef __LPI_H_
#define __LPI_H_

struct lazy_pages_info {
	int pid;
	int uffd;

	struct list_head pages;

	struct page_read pr;

	unsigned long total_pages;
	unsigned long copied_pages;

	struct hlist_node hash;
};

#endif /* __LPI_H_ */
