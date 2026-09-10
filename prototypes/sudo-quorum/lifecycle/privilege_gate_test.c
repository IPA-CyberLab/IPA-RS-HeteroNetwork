/* Pure parser/ABI tests; never connects or changes identity. */
#include "privilege_gate.c"
#include <assert.h>

int main(void)
{
    uint32_t n;
    assert(number("4294967295", &n) && n == UINT32_MAX);
    assert(!number("4294967296", &n));
    assert(!number("-1", &n));
    assert(!number(" 0", &n));
    assert(!number("0junk", &n));
    assert(!number(NULL, &n));
    char *valid[] = { "runas_uid=0", "runas_euid=0", NULL };
    char *duplicate[] = { "runas_uid=0", "runas_euid=0", "runas_euid=1000", NULL };
    char *malformed[] = { "runas_uid", NULL };
    assert(valid_fields(valid));
    assert(!valid_fields(duplicate));
    assert(!valid_fields(malformed));
    assert(!valid_fields(NULL));
    assert(gate_open(0, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL) == -1);
    assert(gate_check(NULL, NULL, NULL, NULL) == 0);
    return 0;
}
