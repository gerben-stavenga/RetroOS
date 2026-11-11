#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { dprintf(2, "OPEN_CLEAN_FAIL line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
int main(void) {
    CHECK(mkdir("/home/retroos/cleanup", 0700) == 0);
    int lock = open("/home/retroos/cleanup/.lock", O_CREAT|O_RDWR, 0600);
    CHECK(lock >= 0 && flock(lock, LOCK_EX|LOCK_NB) == 0);
    CHECK(write(lock, "old", 3) == 3);
    CHECK(symlink("/missing", "/home/retroos/cleanup/link") == 0);
    CHECK(unlink("/home/retroos/cleanup/link") == 0);
    CHECK(unlink("/home/retroos/cleanup/.lock") == 0);
    struct stat st;
    CHECK(lstat("/home/retroos/cleanup/.lock", &st) == -1 && errno == ENOENT);
    CHECK(rmdir("/home/retroos/cleanup") == 0);
    DIR *directory = opendir("/home/retroos");
    CHECK(directory != NULL);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        CHECK(strncmp(entry->d_name,".retroos-unlinked-",17) != 0);
    CHECK(closedir(directory) == 0);
    char bytes[4] = {0};
    CHECK(pread(lock, bytes, 3, 0) == 3 && memcmp(bytes,"old",3) == 0);
    CHECK(pwrite(lock, "new", 3, 0) == 3);
    CHECK(close(lock) == 0);
    // Independent opens must keep the old inode after unlink/recreation,
    // including a descriptor that has not yet upgraded its SMB write access.
    CHECK(mkdir("/home/retroos/cleanup", 0700) == 0);
    int seed = open("/home/retroos/cleanup/file", O_CREAT|O_RDWR, 0600);
    CHECK(seed >= 0 && write(seed,"old",3)==3 && close(seed)==0);
    int old = open("/home/retroos/cleanup/file", O_RDWR);
    int other = open("/home/retroos/cleanup/file", O_RDONLY);
    CHECK(old >= 0 && other >= 0);
    CHECK(unlink("/home/retroos/cleanup/file") == 0);
    int fresh = open("/home/retroos/cleanup/file", O_CREAT|O_EXCL|O_RDWR, 0600);
    CHECK(fresh >= 0 && write(fresh,"keep",4)==4);
    struct timespec times[2] = {{1234567890,0},{1234567890,0}};
    CHECK(utimensat(AT_FDCWD,"/home/retroos/cleanup/file",times,0)==0);
    CHECK(pwrite(old,"new",3,0)==3);
    CHECK(pread(other,bytes,3,0)==3 && memcmp(bytes,"new",3)==0);
    CHECK(pread(fresh,bytes,4,0)==4 && memcmp(bytes,"keep",4)==0);
    CHECK(fstat(fresh,&st)==0 && st.st_mtime==1234567890);
    CHECK(close(old)==0 && close(other)==0 && close(fresh)==0);
    CHECK(unlink("/home/retroos/cleanup/file")==0);
    CHECK(rmdir("/home/retroos/cleanup")==0);
    dprintf(2, "OPEN_CLEAN_PASS\n");
    return 0;
}
