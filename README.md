## CRIU (Checkpoint and Restore in Userspace)

### Misc Definitions

dump == checkpoint

### Lazy vs Full

When CRIU dumps a process tree rooted at \<pid>,it serializes *all* information about the process to disk. This includes all data necessary to reinstantiate task_struct's, memory pages, file descriptors, etc. When it dumps, this data is stored in a set of .img files (created by protobuf). There are two .img files that are of particular interest to us: pagemap-\<pid>.img and pages-\<#>.img.

CRIU comes with a useful tool for examining these .img files in their de-serialized form: `crit`. For example, running `crit decode --pretty < {pagemap-<pid>.img}` yields:

```
{
    "magic": "PAGEMAP", 
    "entries": [
        {
            "pages_id": 1
        }, 
        {
            "vaddr": "0x400000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x8ea000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x8f7000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x8fd000", 
            "nr_pages": 11, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x90b000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x90d000", 
            "nr_pages": 6, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x915000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x918000", 
            "nr_pages": 7, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x922000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x927000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x961000", 
            "nr_pages": 1, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x962000", 
            "nr_pages": 30, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x984000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x1a4b000", 
            "nr_pages": 166, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x1af2000", 
            "nr_pages": 11, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x1b05000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f216f604000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f216f81e000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f216fa21000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f216fc25000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f216ffe6000", 
            "nr_pages": 6, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f216ffec000", 
            "nr_pages": 2, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f216ffef000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f2170207000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f217020c000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f21702b2000", 
            "nr_pages": 50, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f21702f2000", 
            "nr_pages": 310, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f2170430000", 
            "nr_pages": 2, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7f2170432000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }, 
        {
            "vaddr": "0x7f2170434000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7ffcbd06e000", 
            "nr_pages": 7, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7ffcbd076000", 
            "nr_pages": 1, 
            "flags": "PE_LAZY"
        }, 
        {
            "vaddr": "0x7ffcbd13a000", 
            "nr_pages": 2, 
            "flags": "PE_PRESENT"
        }
    ]
}
```
