project('libsignon-glib', 'c',
    version: '2.1'
)

library_major = '2'

gnome = import('gnome')
pkg = import('pkgconfig')

gio_dep = dependency('gio-2.0', version: '>=2.36')
gio_unix_dep = dependency('gio-unix-2.0')
glib_dep = dependency('glib-2.0', version: '>=2.32')
gobject_dep = dependency('gobject-2.0', version: '>=2.35.1')

if get_option('tests')
    check_dep = dependency('check', version: '>=0.9.4')
endif

if get_option('debugging')
    add_project_arguments('-DENABLE_DEBUG=1', language : 'c')
endif

root_dir = include_directories ('.')

subdir('libsignon-glib')
if get_option('documentation')
    subdir('docs')
endif

if get_option('python')
    subdir('pygobject')
endif

if get_option('tests')
    subdir('tests')
endif
