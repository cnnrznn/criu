## CRIU (Checkpoint and Restore in Userspace)

### Misc Definitions

dump == checkpoint
lazy-pages:
    Pages that are private or anon-shared can be lazily loaded. This does not include, however, file-backed pages.  

### Cons of Current CRIU Migration Model
* A process cannot be killed completely prior to migration; the source machine must stay on
* The page server cannot serve pages from the filesystem; it expects the task to still be present in the kernel
* A process is moved *completely*; demand paging is only used to "kick-start" the restore procedure
* There is no notion of block page loading on fault (although there are options for it)
* Activeset
