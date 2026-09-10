#include <assert.h>
#include <stddef.h>
#include <sudo_plugin.h>

extern struct approval_plugin quorum_deny_gate;

int main(void)
{
    const char *error = NULL;
    assert(quorum_deny_gate.open(SUDO_API_VERSION, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, &error) == 1);
    assert(quorum_deny_gate.open(SUDO_API_VERSION + 1, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, &error) == -1);
    assert(quorum_deny_gate.open(0, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, NULL) == -1);
    assert(quorum_deny_gate.check(NULL, NULL, NULL, &error) == 0);
    assert(error != NULL);
    assert(quorum_deny_gate.check(NULL, NULL, NULL, NULL) == 0);
    return 0;
}
