#include "common.c"

int main(int argc, char **argv) {
  if (argc != 2) puts("invocation: ./pulsehunter <bits>"), exit(1);
  char *bits = argv[1];
  int nbits = strlen(bits);

  if (chdir("out")) perror("unable to enter directory 'out'"), exit(1);
  DIR *d = opendir(".");
  if (!d) perror("unable to open directory 'out'"), exit(1);
  for (struct dirent *e = (errno=0,readdir(d)); e; e = (errno=0,readdir(d))) {
    if (e->d_name[0] == '.') continue;
    size_t len;
    char *data = slurp_file(e->d_name, &len);
    if (!data) { perror("error while slurping dirent"); continue; }
    int maxbits = 0;
    for (int i=0; i<((int)len)-nbits; i++) {
      int matching = 0;
      for (int j=0; j<nbits; j++) if (bits[j]==data[i+j]) matching++;
      if (matching > maxbits) maxbits = matching;
    }
    printf("%d\t%s\n", maxbits, e->d_name);
    free(data);
  }
  if (errno) perror("error while reading directory 'out'"), exit(1);
  return 0;
}