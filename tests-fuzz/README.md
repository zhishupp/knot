# Fuzzing

Knot DNS 2.0 includes two fuzzing tests in `tests-fuzz/`: a) a simple
test harness that exercises the packet parsing logic in
`packet.c` and more through test that replaces UDP handler with reads
from stdin in `knotd_stdio.c`.  This compiles into a test harness that
is designed to be used with lcamtuf's [American Fuzzy Lop (AFL)
fuzzer](http://lcamtuf.coredump.cx/afl/).  We will use knotd_stdio in
the following examples.

## How it works

AFL 1.83b includes an experimental feature called ["persistent
mode"](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html)
that can be used to control AFL's fork server to fuzz inputs and
exercise the program without restarting it.  You can use this new
feature along with the included Knot DNS test harness.

## Using the AFL persistent harness

### Gathering seed inputs

Gathering DNS packets for use in fuzzing is left to the tester, but
note that the fuzzing shim includes an environment variable to support
test cases minimization with `afl-cmin`:

```
$ cat > knot-afl.conf << EOF
server:
    listen: 0.0.0.0@5353

log:
    - target: stderr
      any: error

control:
    listen: /tmp/knot.sock
EOF			
$ afl-cmin -i ~/knot-seeds -o ~/knot-seeds-cmin -m 1000000 -t 400000 -- tests-fuzz/knotd_stdio -c knot-afl.conf
```

You might want to configure some sample zones and have a test set of
fuzzing data that would end up querying those zones.

### Compiling the test harness.

See the AFL [blog post](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html)
and README for details on how to use LLVM mode and compile binaries
for use with persistent mode.  For reference, you can use these
commands to build Knot with the fuzzing harness:

```
$ CC=afl-clang-fast ./configure --disable-shared
$ make check
```

### Fuzz

A basic AFL run can then be kicked off as follows:

```
AFL_PERSISTENT=1 afl-fuzz -i my_seeds -o my_output_dir -t 10000 -m 100000 -- tests-fuzz/knotd_stdio -c knot-afl.conf
```

Note that AFL can be scaled up by supplying the `-M` flag and starting
multiple instances of the fuzzer.
