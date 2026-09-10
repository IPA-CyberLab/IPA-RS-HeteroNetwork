/* Non-deployable gate: no invocation is supported until final context is bound. */
#include <stddef.h>
#include <sudo_plugin.h>

static sudo_printf_t report;

static int gate_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], int submit_optind, char * const submit_argv[],
    char * const submit_envp[], char * const plugin_options[], const char **errstr)
{
    (void)conversation; (void)settings; (void)user_info;
    (void)submit_optind; (void)submit_argv; (void)submit_envp;
    (void)plugin_options; (void)errstr;
    /* open == 0 disables an approval plugin. Never use it for a gate failure. */
    report = NULL;
    if (version != SUDO_API_VERSION)
        return -1;
    report = plugin_printf;
    return 1;
}

static int gate_check(char * const command_info[], char * const run_argv[],
    char * const run_envp[], const char **errstr)
{
    (void)command_info; (void)run_argv; (void)run_envp;
    if (errstr != NULL)
        *errstr = "quorum prototype: final execution context is not bound";
    if (report != NULL)
        report(SUDO_CONV_ERROR_MSG, "%s\n",
            "quorum prototype: final execution context is not bound");
    return 0;
}

struct approval_plugin quorum_deny_gate = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = gate_open,
    .check = gate_check,
};
