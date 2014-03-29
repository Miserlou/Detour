#include <stdlib.h>
#include <stdio.h>
#include <jh.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

time_t real_seconds(void) {
  struct timespec t;
  int s = clock_gettime(CLOCK_REALTIME, &t);
  assert(s==0);
  return t.tv_sec;
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

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

void handle_connection(int s) {
  dup2(s, 1);
  dup2(s, 0);

  char line_in[100];
  if (!fgets(line_in, 100, stdin)) return;
  char *p = line_in + strlen("GET /");

  setbuf(stdout, NULL);
  printf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!--");

  char *spaaaace = malloc(1024*64);
  memset(spaaaace, ' ', 1024*64);
  spaaaace[0] = 'A';

  time_t t = round_up(real_seconds(), 4);
  while (1) {
    if (*p != '0' && *p != '1') return;
    if (*p == '1') t+=2;
    sleep_until(t);
    if (fwrite(spaaaace, 1024, 64, stdout) <= 0) return;
    t += (*p == '1') ? 2 : 4;
    p++;
  }
}

int main(void) {
  int s = netopen_server(NULL, "4422", JH_TCP_HINTS);
  while (1) {
    int s_ = accept(s, NULL, NULL);
    pid_t p = fork();
    if (p == 0) {
      handle_connection(s_);
      return 0;
    }
    close(s_);
  }
}
