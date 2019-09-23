project('ptrace_inject', 'c', default_options : ['c_std=c11'])

# inject_v1
injector_v1_src = [
    'src/inject_v1/injector_v1.c',
    'lib/hotpatchor/hotpatchor.c', 
    'lib/hotpatchor/hotpatchor.h'
]
executable('injector_v1', injector_v1_src)
executable('dummy_v1', 'src/inject_v1/dummy_v1.c')

# inject_v2
injector_v2_src = [
    'src/inject_v2/injector_v2.c',
    'lib/hotpatchor/hotpatchor.c', 
    'lib/hotpatchor/hotpatchor.h'
]
executable('injector_v2', injector_v2_src)
thread_dep = dependency('threads') # this adds pthread
executable('dummy_v2', 'src/inject_v2/dummy_v2.c', dependencies : thread_dep)

# test_elf
executable('test_elf', 'src/test_elf/test_elf.c', link_args : ['-lelf'])
