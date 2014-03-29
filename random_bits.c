#include "devurandom.c"
#include <stdint.h>
#include <stdio.h>

int main(void) {
  // yup, this is cheap and slow :D
  char bits[65];
  randombytes(bits, sizeof(bits));
  for (int i=0; i<sizeof(bits); i++) bits[i] = '0' + (1&bits[i]);
  bits[sizeof(bits)-1] = '\0';
  puts(bits);
  return 0;
}
