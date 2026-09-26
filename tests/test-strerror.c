#include "compiler.h"
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

/* DO NOT MERGE: crash inside libunwind, called from libc. */
static int
cmp (const void *a, const void *b)
{
  unw_word_t ip;
  unw_get_reg (NULL, UNW_REG_IP, &ip);
  return *(const int *) a - *(const int *) b;
}

int
main (int argc, char **argv UNUSED)
{
  int i, verbose = argc > 1;
  const char *msg;

  for (i = 0; i < 16; ++i)
    {
      msg = unw_strerror (-i);
      if (verbose)
	printf ("%6d -> %s\n", -i, msg);
    }
  int v[] = { 2, 1 };
  qsort (v, 2, sizeof v[0], cmp);
  return 0;
}
