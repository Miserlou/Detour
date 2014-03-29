#!/bin/sh
gcc -g -Wall -o pulser pulser.c -std=gnu99 -lrt
gcc -g -Wall -o pulserecord pulserecord.c -std=gnu99 -lpcap -lrt
gcc -g -Wall -o random_bits random_bits.c -std=gnu99
gcc -g -Wall -o pulsehunter pulsehunter.c -std=gnu99 -lrt

