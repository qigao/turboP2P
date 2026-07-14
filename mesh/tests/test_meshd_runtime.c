#include <tinytest.h>

#define MESHD_NO_MAIN
#include "../examples/meshd.c"

static void meshd_test_reset_signal_state(void) {
    g_running = 1;
#ifndef _WIN32
    g_status_flush_requested = 0;
#endif
}

#ifndef _WIN32
static void test_posix_sighup_requests_single_status_flush(void) {
    meshd_test_reset_signal_state();

    check(meshd_is_running());
    check_false(meshd_take_status_flush_request());

    meshd_signal_handler(SIGHUP);

    check(meshd_is_running());
    check(meshd_take_status_flush_request());
    check_false(meshd_take_status_flush_request());
    check(meshd_is_running());
}

static void test_posix_shutdown_signal_does_not_request_status_flush(void) {
    meshd_test_reset_signal_state();

    meshd_signal_handler(SIGTERM);

    check_false(meshd_is_running());
    check_false(meshd_take_status_flush_request());
}
#else
static void test_windows_console_shutdown_signal_stops_runtime(void) {
    meshd_test_reset_signal_state();

    check(meshd_console_handler(CTRL_C_EVENT));

    check_false(meshd_is_running());
}

static void test_windows_console_ignores_unhandled_signal(void) {
    meshd_test_reset_signal_state();

    check_false(meshd_console_handler(9999));
    check(meshd_is_running());
}
#endif

spec("meshd runtime") {
    describe("signal handling") {
#ifndef _WIN32
        it("turns SIGHUP into one status flush request without stopping") {
            test_posix_sighup_requests_single_status_flush();
        }

        it("turns shutdown signals into runtime stop without status flush request") {
            test_posix_shutdown_signal_does_not_request_status_flush();
        }
#else
        it("turns console shutdown signals into runtime stop") {
            test_windows_console_shutdown_signal_stops_runtime();
        }

        it("ignores unrelated console signals") {
            test_windows_console_ignores_unhandled_signal();
        }
#endif
    }
}
