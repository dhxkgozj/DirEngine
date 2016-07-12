
/* Copy this file (test_main.h.in) to test_main.h, and edit */

/* DEBUG RUN, ON V */
#if 1
#define TEST_N_ITERS   1
#define TEST_N_BBS     1

/* vex_traceflags values */
#define VEX_TRACE_FE     (1 << 7)  /* show conversion into IR */
#define VEX_TRACE_OPT1   (1 << 6)  /* show after initial opt */
#define VEX_TRACE_INST   (1 << 5)  /* show after instrumentation */
#define VEX_TRACE_OPT2   (1 << 4)  /* show after second opt */
#define VEX_TRACE_TREES  (1 << 3)  /* show after tree building */
#define VEX_TRACE_VCODE  (1 << 2)  /* show selected insns */
#define VEX_TRACE_RCODE  (1 << 1)  /* show after reg-alloc */
#define VEX_TRACE_ASM    (1 << 0)  /* show final assembly */


#endif

/* CHECKING RUN, ON V */
#if 0
#define TEST_N_ITERS   1
#define TEST_N_BBS     100000
#define TEST_FLAGS     0
#endif

/* PROFILING RUN, NATIVE */
#if 0
#define TEST_N_ITERS   100
#define TEST_N_BBS     1000
#define TEST_FLAGS     0
#endif

/* PROFILING RUN, REDUCED WORKLOAD */
#if 0
#define TEST_N_ITERS   3
#define TEST_N_BBS     1000
#define TEST_FLAGS     0
#endif

