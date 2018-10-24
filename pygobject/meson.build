py_override = get_option('py-overrides-dir')

if py_override == ''
    python_exec = find_program(['python3', 'python'])

    py_override_cmd = run_command(
        python_exec,
        ['-c', 'import gi;print (gi._overridesdir, end="")'],
    )

    if py_override_cmd.returncode() != 0
        error('Error getting the GObject Introspection override directory: ' + py_override_cmd.stderr())
    endif

    py_override = py_override_cmd.stdout()   
endif

install_data(
    'Signon.py',
    install_dir: py_override,
)
