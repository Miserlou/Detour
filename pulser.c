#include "common.c"

void handle_connection(int s) {
  dup2(s, 1);
  dup2(s, 0);

  char line_in[100];
  if (!fgets(line_in, 100, stdin)) return;
  if (!strncmp(line_in, "GET /", strlen("GET /"))) return;
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
