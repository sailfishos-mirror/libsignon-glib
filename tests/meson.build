signon_glib_testsuite = executable(
    'signon-glib-checksuite',
    'check_signon.c',
    dependencies: [libsignon_glib_dep, check_dep],
)

test_env = environment()
test_env.set('TESTDIR', meson.current_source_dir())
test_env.set('TEST_APP', signon_glib_testsuite.full_path())

# Environment variables for the signon daemon
test_env.set('SSO_LOGGING_LEVEL', '2')
test_env.set('SSO_STORAGE_PATH', '/tmp')
test_env.set('SSO_DAEMON_TIMEOUT', '1')
test_env.set('SSO_IDENTITY_TIMEOUT', '3')
test_env.set('SSO_AUTHSESSION_TIMEOUT', '3')
test_env.set('SSO_EXTENSIONS_DIR', '/tmp') # this disables all extensions

#Environment variables for the test application
test_env.set('G_MESSAGES_DEBUG', 'all')

dbus_test_runner = find_program('dbus-test-runner', required: false)
if dbus_test_runner.found()
    message('Using dbus-test-runner')
    test(
        meson.project_name(),
        dbus_test_runner,
        args: [
            '-m', '180', '--keep-env',
            '-t', 'signond', '-r',
            '-t', signon_glib_testsuite, '-f', 'com.google.code.AccountsSSO.SingleSignOn',
        ],
        timeout: 300, # Timeout after 5 minutes
        env: test_env
    )
else
    message('Using existing D-Bus session and signond instance')
    test(
        meson.project_name(),
        signon_glib_testsuite,
        timeout: 300, # Timeout after 5 minutes
        env: test_env
    )
endif
