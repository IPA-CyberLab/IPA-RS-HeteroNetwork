/* Separate build/symbol/protocol; the v1 gate remains unchanged unless explicitly selected. */
#define SUDO_LOCAL_V2
#define quorum_privilege_gate quorum_v2_gate
#include "privilege_gate.c"
