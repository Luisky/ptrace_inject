project('ptrace_inject', 'c', default_options : ['c_std=c11'])

hotpatchor_src = [
    'lib/hotpatchor/hotpatchor.c', 
    'lib/hotpatchor/hotpatchor.h'
]

lib = include_directories('lib/hotpatchor')
thread_dep = dependency('threads') # this adds pthread

# inject_v1
injector_v1_src = [
    'src/inject_v1/injector_v1.c',
    hotpatchor_src
]
executable('injector_v1', injector_v1_src, include_directories : lib)
executable('dummy_v1', 'src/inject_v1/dummy_v1.c')

# inject_v2
injector_v2_src = [
    'src/inject_v2/injector_v2.c',
    hotpatchor_src
]
executable('injector_v2', injector_v2_src, include_directories : lib)
executable('dummy_v2', 'src/inject_v2/dummy_v2.c', dependencies : thread_dep)

# test_elf
executable('test_elf', 'src/test_elf/test_elf.c', link_args : ['-lelf'])
