libsignon_glib_public_headers = files(
    'signon-auth-service.h',
    'signon-auth-session.h',
    'signon-errors.h',
    'signon-identity.h',
    'signon-identity-info.h',
    'signon-glib.h',
    'signon-types.h',
)

libsignon_glib_private_headers = files(
    'signon-internals.h',
    'signon-proxy.h',
    'signon-utils.h',
    'sso-auth-service.h',
)

libsignon_glib_public_sources = files(
    'signon-auth-service.c',
    'signon-auth-session.c',
    'signon-errors.c',
    'signon-identity.c',
    'signon-identity-info.c',
)

libsignon_glib_sources = libsignon_glib_public_sources + files(
    'signon-proxy.c',
    'signon-utils.c',
    'sso-auth-service.c',
)

sso_interface_prefix = 'com.google.code.AccountsSSO.SingleSignOn.'

dbus_auth_service_xml = files (join_paths('interfaces', 'com.google.code.AccountsSSO.SingleSignOn.AuthService.xml'))
dbus_auth_service_gen = gnome.gdbus_codegen(
    'sso-auth-service-gen',
    dbus_auth_service_xml,
    interface_prefix: sso_interface_prefix,
    namespace: 'Sso',
    docbook: 'sso-auth-service-gen-doc',
)

dbus_auth_session_xml = files (join_paths('interfaces', 'com.google.code.AccountsSSO.SingleSignOn.AuthSession.xml'))
dbus_auth_session_gen = gnome.gdbus_codegen(
    'sso-auth-session-gen',
    dbus_auth_session_xml,
    interface_prefix: sso_interface_prefix,
    namespace: 'Sso',
    docbook: 'sso-auth-session-gen-doc',
)

dbus_identity_xml = files (join_paths('interfaces', 'com.google.code.AccountsSSO.SingleSignOn.Identity.xml'))
dbus_identity_gen = gnome.gdbus_codegen(
    'sso-identity-gen',
    dbus_identity_xml,
    interface_prefix: sso_interface_prefix,
    namespace: 'Sso',
    docbook: 'sso-identity-gen-doc',
)

signon_marshal = gnome.genmarshal(
    'signon-marshal',
    sources: 'signon-marshal.list',
    prefix: '_signon_marshal'
)

signon_enum_types = gnome.mkenums_simple(
    'signon-enum-types',
    sources: 'signon-errors.h',
    install_header: true,
    install_dir: join_paths(get_option('includedir'), meson.project_name()),
)

python_exec = find_program(['python', 'python3'])
gen_error_map = files(join_paths(meson.source_root (), 'build-aux', 'gen-error-map.py'))
signon_errors_map = custom_target (
    'signon-errors-map.c',
    input: 'signon-errors.h',
    command: [python_exec, gen_error_map, '@INPUT@', '@OUTPUT@'],
    output: 'signon-errors-map.c'
)

libsignon_glib_deps = [
    gio_dep,
    gio_unix_dep,
    glib_dep,
    gobject_dep,
]

symbols_map = 'libsignon-glib.map'
libsignon_glib_lib = shared_library(
    'signon-glib',
    libsignon_glib_public_headers,
    libsignon_glib_private_headers,
    libsignon_glib_sources,
    dbus_auth_service_gen,
    dbus_auth_session_gen,
    dbus_identity_gen,
    signon_marshal,
    signon_enum_types,
    signon_errors_map,
    dependencies: libsignon_glib_deps,
    include_directories: root_dir,
    link_args : [
        '-Wl,--no-undefined',
        '-Wl,--version-script,' + join_paths(meson.current_source_dir(), symbols_map)
    ],
    link_depends : symbols_map,
    soversion: '1',
    version: '1.0.0',
    install: true,
)

libsignon_glib_dir = include_directories('.')

libsignon_glib_dep = declare_dependency(
    link_with: libsignon_glib_lib,
    dependencies: libsignon_glib_deps,
    include_directories: [root_dir, libsignon_glib_dir],
)

libsignon_glib_pkgs = [
    'gobject-2.0',
    'glib-2.0',
    'gio-2.0',
    'gio-unix-2.0',
]

install_headers(
    libsignon_glib_public_headers,
    subdir: meson.project_name(),
)

pkg.generate(
    filebase: meson.project_name(),
    name: meson.project_name(),
    description: 'A low-level library for managing account credentials.',
    libraries: libsignon_glib_lib,
    requires: libsignon_glib_pkgs,
    version: meson.project_version(),
)

if get_option('introspection')
    libsignon_glib_gir = gnome.generate_gir(
        libsignon_glib_lib,
        namespace: 'Signon',
        nsversion: '1.0',
        sources: [
            libsignon_glib_public_sources,
            libsignon_glib_public_headers,
            signon_enum_types,
        ],
        dependencies: libsignon_glib_deps,
        includes: ['GObject-2.0', 'Gio-2.0'],
        identifier_prefix: 'Signon',
        symbol_prefix: 'signon',
        header: 'libsignon-glib/signon-glib.h',
        extra_args: '--warn-all',
        install: true,
    )

    gnome.generate_vapi('libsignon-glib',
        sources: libsignon_glib_gir[0],
        packages: libsignon_glib_pkgs,
        install: true,
    )
endif
