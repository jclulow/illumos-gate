#include <stdlib.h>
#include <errno.h>
#include "liblofiadm.h"

int
lofiadm_init(lofiadm_t **loap)
{
	errno = EINVAL;
	*loap = NULL;
	return (-1);
}

void
lofiadm_fini(lofiadm_t *loa)
{
}
