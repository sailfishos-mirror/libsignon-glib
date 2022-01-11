version_data = configuration_data()
version_data.set('PACKAGE_VERSION', meson.project_version())

configure_file(
    input: 'version.xml.in',
    output: '@BASENAME@',
    configuration: version_data,
)

glib_prefix = glib_dep.get_pkgconfig_variable('prefix')
glib_docpath = join_paths(glib_prefix, 'share', 'gtk-doc', 'html')

#FIXME: requires Meson 0.46
doc_content_files = []
if (meson.version().version_compare('>=0.46'))
    doc_content_files += dbus_auth_service_gen[2]
    doc_content_files += dbus_auth_session_gen[2]
    doc_content_files += dbus_identity_gen[2]
endif

gnome.gtkdoc(
    meson.project_name(),
    main_xml: meson.project_name() + '-docs.xml',
    src_dir: libsignon_glib_dir,
    dependencies: libsignon_glib_dep,
    ignore_headers: [
        'signon-auth-session-client-glib-gen.h',
        'signon-client-glib-gen.h',
        'signon-identity-glib-gen.h',
        'signon-internals.h',
        'signon-proxy.h',
        'signon-utils.h',
        'signon-marshal.h',
        'sso-auth-service-gen.h',
        'sso-auth-service.h',
        'sso-auth-session-gen.h',
        'sso-identity-gen.h',
    ],
    scan_args: [
        '--rebuild-types',
        '--deprecated-guards="SIGNON_DISABLE_DEPRECATED"',
    ],
    mkdb_args: [
        '--name-space=signon',
    ],
    gobject_typesfile: [
        'libsignon-glib.types',
    ],
    content_files: doc_content_files,
    expand_content_files: [
        'migrating-1to2.xml'
    ],
    fixxref_args: [
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'glib')),
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gobject')),
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gio')),
    ],
    install: true,
)
