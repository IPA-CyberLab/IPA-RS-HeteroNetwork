/* Fixed benign fixture: emits booleans only; no argv/env values or execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char cwd[4096];
    const char *marker = getenv("QUORUM_LIFECYCLE_SESSION");
    int exact_argv = argc == 4 && strcmp(argv[0], "/opt/quorum-lifecycle/command") == 0
        && strcmp(argv[1], "") == 0 && strcmp(argv[2], "two words") == 0
        && strcmp(argv[3], "\xff") == 0;
    printf("EXECUTED uid=%d argv=%d cwd=%d session_marker=%d\n",
        getuid() == 0 && geteuid() == 0, exact_argv,
        getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/opt/quorum-lifecycle/work") == 0,
        marker != NULL && strcmp(marker, "after-approval") == 0);
    return 0;
}
