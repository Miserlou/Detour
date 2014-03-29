// This file is basically utility functions from various places mashed together, including
// from my helper library libjh.

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/select.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define JH_TCP_HINTS (&libjh_tcp_hints)
const struct addrinfo libjh_tcp_hints = {
  .ai_flags = AI_ADDRCONFIG,
  .ai_family = AF_UNSPEC,
  .ai_socktype = SOCK_STREAM,
  .ai_protocol = 0
};

int netopen_server(const char *node /*NULL for ANY*/, const char *service, const struct addrinfo *hints) {
  struct addrinfo hints_;
  if (hints == &libjh_tcp_hints) {
    hints_ = *hints;
    hints_.ai_flags |= AI_PASSIVE;
    hints_.ai_flags &= ~AI_ADDRCONFIG;
    hints = &hints_;
  }

  struct addrinfo *addrs;
  int gai_res = getaddrinfo(node, service, hints, &addrs);
  if (gai_res) return gai_res;

  int s = socket(addrs[0].ai_family, addrs[0].ai_socktype, addrs[0].ai_protocol);
  if (s == -1) goto err_socket;

  if (bind(s, addrs[0].ai_addr, addrs[0].ai_addrlen)) goto err_bind_n_listen;
  if (listen(s, 16)) goto err_bind_n_listen;

  freeaddrinfo(addrs);
  return s;

err_bind_n_listen:;
  int errno_ = errno;
  close(s);
  errno = errno_;
err_socket:
  freeaddrinfo(addrs);
  return EAI_SYSTEM;
}

ssize_t read_nointr(int fd, void *buf, size_t count, int *last_res) {
  errno = 0;
  size_t done = 0;
  while (done < count) {
    ssize_t part_res = read(fd, buf+done, count-done);
    if (part_res == -1 && errno == EINTR) continue;
    if (part_res <= 0) {
      if (last_res) *last_res = part_res;
      if (done) return done;
      return part_res;
    }
    done += part_res;
  }
  if (last_res) *last_res = 1;
  return done;
}

void *slurp_fd(int fd, size_t *len_out) {
  int errno_;
  
  size_t size_guess;
  
  struct stat st;
  if (fstat(fd, &st) == 0) {
    if (st.st_size > 0) {
      size_guess = st.st_size;
    }
  }
  
  char *buf = NULL;
  int done = 0;
  
  while (1) {
    buf = realloc(buf, size_guess);
    if (buf == NULL) return NULL;
    int last_res;
    ssize_t read_res = read_nointr(fd, buf+done, size_guess-done, &last_res);
    if (last_res == -1) { errno_=errno; free(buf); errno=errno_; return NULL; }
    done += read_res;
    if (len_out) *len_out = done;
    return buf;
  }
}

void *slurp_file(char *path, size_t *len_out) {
  int fd = open(path, O_RDONLY|O_CLOEXEC);
  if (fd == -1) return NULL;
  char *res = slurp_fd(fd, len_out);
  int errno_ = errno;
  close(fd);
  errno = errno_;
  return res;
}

time_t real_seconds(void) {
  struct timespec t;
  int s = clock_gettime(CLOCK_REALTIME, &t);
  assert(s==0);
  return t.tv_sec;
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
    y->tv_nsec -= 1000000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_nsec - y->tv_nsec > 1000000000) {
    int nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
    y->tv_nsec += 1000000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_nsec = x->tv_nsec - y->tv_nsec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

void sleep_until(time_t dst_sec) {
  struct timespec dst;
  dst.tv_sec = dst_sec;
  dst.tv_nsec = 0;
  while (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &dst, NULL)) /* nothing */;
}

time_t round_up(time_t t, int align) {
  t = t - 1; /* counter bad +t for aligned things in last step */
  t = t - t%align; /* round down to align */
  t = t + align; /* add alignment to make it a round up */
  return t;
}
