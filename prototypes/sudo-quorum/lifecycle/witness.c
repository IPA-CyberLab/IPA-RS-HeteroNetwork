/* Disposable-container measurement ONLY. Not a quorum authorization plugin. */
#ifndef DISPOSABLE_LIFECYCLE_TEST
#error "The witness must not be built as an approval adapter"
#endif
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sudo_plugin.h>

static sudo_printf_t report;
static int caller_metadata_matches;

static const char *value(char * const entries[], const char *name)
{
    const char *found = NULL;
    size_t n = strlen(name);
    if (entries == NULL)
        return NULL;
    for (size_t i = 0; i < 512; i++) {
        if (entries[i] == NULL)
            return found;
        size_t len = strnlen(entries[i], 65537);
        if (len > 65536)
            return NULL;
        if (len > n && memcmp(entries[i], name, n) == 0 && entries[i][n] == '=') {
            if (found != NULL)
                return NULL;
            found = entries[i] + n + 1;
        }
    }
    return NULL;
}

static int matches(char * const entries[], const char *name, const char *expected)
{
    const char *v = value(entries, name);
    return v != NULL && strcmp(v, expected) == 0;
}

static int witness_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], int submit_optind, char * const submit_argv[],
    char * const submit_envp[], char * const plugin_options[], const char **errstr)
{
    (void)conversation; (void)settings; (void)submit_optind; (void)submit_argv;
    (void)submit_envp; (void)plugin_options; (void)errstr;
    if (version != SUDO_API_VERSION || plugin_printf == NULL)
        return -1;
    report = plugin_printf;
    caller_metadata_matches = matches(user_info, "uid", "1000");
    return 1;
}

static int witness_check(char * const info[], char * const argv[],
    char * const env[], const char **errstr)
{
    (void)errstr;
    int argc = 0;
    if (argv == NULL)
        return -1;
    while (argc < 256 && argv[argc] != NULL)
        argc++;
    if (argc == 256)
        return -1;
    int exact_argv = argc == 4 && strcmp(argv[0], "/opt/quorum-lifecycle/command") == 0
        && strcmp(argv[1], "") == 0 && strcmp(argv[2], "two words") == 0
        && strcmp(argv[3], "\xff") == 0;
    report(SUDO_CONV_INFO_MSG,
        "WITNESS caller_metadata=%d real_uid_matches=%d runas=%d argv=%d cwd=%d execfd=%d session_marker=%d\n",
        caller_metadata_matches, getuid() == 1000,
        matches(info, "runas_uid", "0"), exact_argv,
        matches(info, "cwd", "/opt/quorum-lifecycle/work"),
        value(info, "execfd") != NULL,
        matches(env, "QUORUM_LIFECYCLE_SESSION", "after-approval"));
    /* Observation only: sudoers/password still authorize the fixed test command. */
    return 1;
}

struct approval_plugin lifecycle_witness = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = witness_open,
    .check = witness_check,
};
