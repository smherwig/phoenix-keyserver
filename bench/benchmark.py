#!/usr/bin/env python

import collections
import getopt
import re
import subprocess
import sys

_USAGE = """
usage: ./benchmark.py [options]

Runs the `openssl speed -elapsed rsa2048' test ITERATIONS number of times
for each level of concurrency.  T

    -h, --help

    -i, --iterations ITERATIONS
        The number of times to repeat a single test.
        Default is 1

    -m, --multi LOW:HIGH
        The level of concurreny; that is, the number of processes to run at the
        same time.  For instance, --multi 2:8 says to run the tests for
        2 processes at a time, then 3, then 4, etc.
        Default is 1 process.

    -n, --nsm LIB,SERVER
        Use the nsm-engine (instead of OpenSSL's default RSA method
        implementation).

        LIB is a path to the nsm-engine.so.

        SERVER is the URL for the nsm-server.

    -o, --output-file FILE
        The file to write the stats to.  The format of the file is:

            nprocs  mean_signs_per_sec  std_signs_per_sec

        Default is to print to stdout.

    -t, --trimmed-mean
        Trim the low 30% and high 30% of test results
        before computing the mean (that is, take the mean
        of the middle 40%).

        By default, results are not trimmed.

    -v, --verbose
        Verbose logging


A typical invocation for the purpose of presenting results would be:

    ./benchmark --iterations 10 --trimmed-mean --multi 1:8 \\
            --output-file linux-rsa2048.dat 

and for the nsm-engine:

    ./benchmark --iterations 10 --trimmed-mean --multi 1:8 \\
            --nsm /home/anonymous/lib/nsm-engine.so,tcp://127.0.0.1:9000 \\
            --output-file nsm-rsa2048.dat
""".strip()

# We want to match the following stdout output line (the second one) from the
# `openssl speed rsa2048' command:
# 
#                    sign    verify    sign/s verify/s
# rsa 2048 bits 0.000592s 0.000017s   1690.5  57470.6
# 
# We only capture the sign/s field, since the nsm-engine
# only performs private key operations.  Also, 1/(sign/s) is the sign field.
_REGEX = re.compile(r'rsa 2048 bits\s+[\d\.]+s\s+[\d\.]+s\s+(?P<signs_per_sec>[\d\.]+)\s+[\d\.]+')


# For nsm, we need to issue two openssl cmds; one to load the engine, and then
# one to run the speed test.  The first %s is for the nsmserver URL
# (e.g., tcp://127.0.0.1:9000); the second %s is for the nsm-engine.so path
# (e.g.,  /home/anonymous/lib/nsm-engine.so).
# 
# Note that we need to use the HEREFILE syntax.  Simply doing:
#
#   $ openssl
#   > engine -v ...
#   > speed -engine -nsm-engine -multi 2 -elapsed rssa2048
#
# causes openssl to hang waiting for the last child processes to exit (when
# -multi is specified).  This isn't a bug in nsm;  it's a bug in the openssl
# command-line program.
_NSM_OPENSSL_CMD = """
openssl <<EOT
engine -v -c -t -pre NSM_SERVER:%s %s
speed -engine nsm-engine -elapsed rsa2048
EOT
""".strip()

_NSM_OPENSSL_MULTI_CMD = """
openssl <<EOT
engine -v -c -t -pre NSM_SERVER:%s %s
speed -engine nsm-engine -multi %d -elapsed rsa2048
EOT
""".strip()

verbose = False

# avg is average signs/sec, std is stddev of signs/sec
StatRecord = collections.namedtuple('StatRecord', ['nprocs', 'avg', 'std'])

def _usage(exitcode):
    sys.stderr.write('%s\n' % _USAGE)
    sys.exit(exitcode)

def _debug(fmt, *args):
    if not verbose:
        return
    _log('debug', fmt, *args)

def _log(tag, fmt, *args):
    fmt = '[%s] %s' % (tag, fmt)
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)

def _die(fmt, *args):
    _log('die', fmt, *args)
    sys.exit(1)


# nsm_engine and nsm_server must be specified together
def _do_test(nsm_engine=None, nsm_server=None, multi=None):
    if nsm_engine:
        if multi:
            cmd = _NSM_OPENSSL_MULTI_CMD % (nsm_server, nsm_engine, multi)
        else:
            cmd = _NSM_OPENSSL_CMD % (nsm_server, nsm_engine)
    else:
        cmd = 'openssl speed -elapsed'
        if multi:
            cmd += ' -multi %d' % multi
        cmd += ' rsa2048'

    _debug('running cmd: "%s"' % cmd)

    try:
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as err:
        _die("cmd '%s' returned %d: %s", cmd, err.returncode, str(err))

    lines = output.splitlines() 
    for line in lines:
        m = _REGEX.match(line)
        if m:
            signs_per_sec = float(m.group('signs_per_sec'))
            print '********** signs per sec: "%f"' % signs_per_sec
            break
    else:
        _die('could not find regex in output')
    return  signs_per_sec


#
# mean/ss/stddev from
# https://stackoverflow.com/questions/15389768/standard-deviation-of-a-list
#

def _mean(l):
    n = len(l)
    if n < 1:
        raise ValueError('mean request at least one data point')
    return float(sum(l)) / n 

def _ss(l):
    """Return sum of square devications of sequence data."""
    c = _mean(l)
    ss = sum((x-c)**2 for x in l)
    return ss
    
def _stddev(l, ddof=0):
    """Calculates the population standard devication by default; ddof=1 compute
    the sample standard deviation."""
    n = len(l)
    if n < 2:
        raise ValueError('variance needs at least two data points')
    ss = _ss(l)
    pvar = ss/(n - ddof)
    return pvar ** 0.5

def _stats(l, trimmed=False):
    trimmed = l
    if trimmed:
        # remove the low 30% and the high %30; compute the mean of the
        # middle %40.
        a = sorted(l)
        n = len(l)
        x = int(n * 0.3)

        # if the list isn't long enough to trim, then take the middle element
        if (x * 2) >= n:
            trimmed = a[n/2]
        else:
            trimmed = a[x:n-x]

    avg = _mean(trimmed)
    if len(trimmed) > 1:
        std = _stddev(trimmed)
    else:
        std = 0
    return (avg, std)

def main(argv):
    shortopts = 'hi:m:n:o:tv'
    longopts = ['help', 'iterations=', 'multi=', 'nsm=', 'output-file=',
            'trimmed-mean', 'verbose']
    #
    global verbose
    iterations = 1
    multi_low = None
    multi_high = None
    nsm_engine = None
    nsm_server = None
    output_file = None
    trimmed_mean = False

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write(str(err) + '\n')
        _usage(1)

    for o, a in opts:
        if o in ('-h', '--help'):
            _usage(0)
        elif o in ('-i', '--iterations'):
            iterations = int(a)
        elif o in ('-m', '--multi'):
            low, high = a.split(':')
            multi_low = int(low)
            multi_high = int(high)
        elif o in ('-n', '--nsm'):
            nsm_engine, nsm_server = a.split(',')
        elif o in ('-o', '--output-file'):
            output_file = a
        elif o in ('-t', '--trimmed-mean'):
            trimmed_mean = True
        elif o in ('-v', '--verbose'):
            verbose = True
        else:
            assert False, 'unhandled option "%s"' % o

    #
    # Do the tests
    #
    records = []
    if multi_low:
        for multi in xrange(multi_low, multi_high+1):
            runs = []
            for i in xrange(1, iterations+1):
                sps = _do_test(nsm_engine, nsm_server, multi)
                runs.append(sps)
            avg, std = _stats(runs, trimmed_mean)
            records.append(StatRecord(multi, avg, std))
    else:
        runs = []
        for i in xrange(1, iterations+1):
            sps = _do_test(nsm_engine, nsm_server)
            runs.append(sps)
        avg, std = _stats(runs, trimmed_mean)
        records.append(StatRecord(1, avg, std))


    #
    # Write output to file or stdout
    #
    f = sys.stdout
    if output_file:
        f = open(output_file, 'w')

    for rec in records:
        f.write('%d %f %f\n' % rec)

    f.close()

    
if __name__ == '__main__':
    main(sys.argv)
