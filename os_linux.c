#include <acl/libacl.h>

int get_perm(acl_permset_t permset, acl_perm_t perm)
{
    return acl_get_perm(permset, perm);
}
