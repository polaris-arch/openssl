#!/usr/bin/env python3
"""CI-only driver, deliberately absent from the proposed upstream change."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path.cwd()
OUT = ROOT.parent / 'evidence'
OUT.mkdir(exist_ok=True)
BASE = 'dffc5e3a5e65fe3fe9e8a610fbb4b8aff9332fdc'
PROFILE = sys.argv[1]
assert PROFILE in ('normal', 'debug', 'sanitizer')
assert re.fullmatch('[0-9a-f]{40}', os.environ['CANDIDATE'])
os.environ.pop('OPENSSL_TEST_RAND_ORDER', None)
os.environ.update(OPENSSL_TEST_TIMEOUT='600',
                 OSSL_RUN_CI_TESTS='1', ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                 UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')


def run(name, args, timeout=2400, expected=0, marker=None):
    path = OUT / (name + '.log')
    begin = time.monotonic()
    with path.open('wb') as out:
        p = subprocess.run(args, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
    text = path.read_text(errors='replace')
    row = {'name': name, 'argv': args, 'returncode': p.returncode,
           'elapsed': time.monotonic() - begin,
           'log_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    history.append(row)
    (OUT / 'commands.json').write_text(json.dumps(history, indent=2) + '\n')
    print(json.dumps(row), flush=True)
    if p.returncode != expected:
        print(text[-16000:], flush=True)
        raise RuntimeError(name + ' unexpected return code')
    if expected:
        assert marker is not None and marker in text, (name, marker, text[-4000:])
        assert re.search(r'^\s*not ok ', text, re.M), text
        assert not re.search(r'Sanitizer|runtime error:|Segmentation fault|watchdog|Timed out', text)
    else:
        assert not re.search(r'^\s*not ok ', text, re.M), name
    return text


def test_args(program, name, iteration=None):
    args = ['util/wrap.pl', 'test/' + program, '-test', name]
    if iteration is not None:
        args += ['-iter', str(iteration)]
    if program == 'quicapitest':
        args += ['default', 'test/default-recordpadding.cnf', 'test/certs',
                 'test/recipes/75-test_quicapi_data']
    return args


def check_iteration(text, iteration, failed=False):
    if iteration is not None:
        verdict = 'not ok' if failed else 'ok'
        assert re.search(r'^\s*' + verdict + r'\s+\d+\s+-\s+(?:[^\n]*?\s+-\s+)?iteration '
                         + str(iteration) + r'\s*$', text, re.M), text[-4000:]


history = []
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert head == os.environ['CANDIDATE']
assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
assert os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize >= 10 * 1024**3
run('identity', ['git', 'show', '--no-patch', '--format=fuller', 'HEAD'])
run('compiler', ['gcc', '--version'])
options = ['./config', '--strict-warnings', 'enable-quic', 'no-fips']
if PROFILE != 'normal':
    options += ['--debug']
if PROFILE == 'sanitizer':
    options += ['enable-asan', 'enable-ubsan']
run('configure', options)
run('configuration', ['perl', 'configdata.pm', '--dump'])
run('build', ['make', '-s', '-j4'], timeout=3000)
run('library-identity', ['sha256sum', 'libssl.a', 'libcrypto.a', 'libssl.so', 'libcrypto.so', 'test/quic_stream_test',
                         'test/quic_txp_test', 'test/quic_fifd_test', 'test/quicapitest'])
run('runtime-dependencies', ['ldd', 'libssl.so'])
run('test-runtime-dependencies', ['ldd', 'test/quic_stream_test'])

cases = [
    ('quic_stream_test', 'test_stream_map_gc_states'),
    ('quic_stream_test', 'test_stream_map_gc_multiple'),
    ('quic_stream_test', 'test_stream_map_gc_retire_error'),
    ('quic_stream_test', 'test_stream_gc_receive_progress'),
    ('quic_stream_test', 'test_stream_gc_receive_guards'),
    ('quic_stream_test', 'test_stream_gc_stream_credit'),
    ('quic_fifd_test', 'test_fifd'),
    ('quic_txp_test', 'test_control_frame_loss'),
    ('quic_txp_test', 'test_reset_ack_loss_order'),
    ('quicapitest', 'test_stream_gc_connection_credit'),
    ('quicapitest', 'test_reject_stream_gc'),
]
expected_iterations = {'test_stream_map_gc_states': 15,
                       'test_stream_map_gc_retire_error': 2,
                       'test_stream_gc_receive_progress': 4,
                       'test_stream_gc_receive_guards': 2,
                       'test_stream_gc_stream_credit': 4,
                       'test_fifd': 7, 'test_reset_ack_loss_order': 3}
for program, name in cases:
    text = run('positive-' + name, test_args(program, name), timeout=180)
    assert name in text and not re.search(r'#\s*(?:skip|skipped)', text, re.I), name
    if name in expected_iterations:
        actual = [int(n) for n in re.findall(r'^\s*ok \d+ - iteration (\d+)\s*$', text, re.M)]
        assert actual == list(range(1, expected_iterations[name] + 1)), (name, actual)
run('quic-suite', ['make', 'test', 'HARNESS_JOBS=4', 'V=1', 'TESTS=test_quic*'], timeout=3600)

sources = {p: (ROOT / p).read_text() for p in (
    'ssl/quic/quic_stream_map.c', 'ssl/quic/quic_channel.c',
    'ssl/quic/quic_rx_depack.c', 'ssl/quic/quic_fifd.c', 'ssl/quic/quic_txp.c')}
(OUT / 'candidate-diff.patch').write_bytes(subprocess.check_output(['git', 'diff', BASE, 'HEAD']))
candidate_library_sha = hashlib.sha256((ROOT / 'libssl.so').read_bytes()).hexdigest()
candidate_archive_sha = hashlib.sha256((ROOT / 'libssl.a').read_bytes()).hexdigest()
candidate_binaries = {program: hashlib.sha256((ROOT / 'test' / program).read_bytes()).hexdigest()
                      for program in {p for p, _ in cases}}
if PROFILE == 'normal':
    variants = [
        ('gc-admission', 'quic_stream_test', 'test_stream_map_gc_states', 1,
         'ossl_quic_stream_map_get_by_id'),
        ('unread-byte-credit', 'quic_stream_test', 'test_stream_map_gc_states', 5,
         'ossl_quic_rxfc_get_rwm(&f.connection)'),
        ('gc-before-tx', 'quicapitest', 'test_stream_gc_connection_credit', None,
         'ossl_quic_txfc_get_credit(&server_ch->conn_txfc'),
        ('receive-progress', 'quic_stream_test', 'test_stream_gc_receive_progress', 1,
         's->ready_for_gc'),
        ('null-send-controls', 'quic_fifd_test', 'test_fifd', 4,
         'regen_count'),
        ('credit-only-txpim', 'quic_txp_test', 'test_control_frame_loss', None,
         'credit->want_max_stream_data'),
        ('reset-late-loss', 'quic_txp_test', 'test_reset_ack_loss_order', 1,
         's->want_reset_stream'),
        ('reset-queued-ack', 'quic_txp_test', 'test_reset_ack_loss_order', 2,
         's->want_reset_stream'),
        ('accept-stream-credit', 'quic_stream_test', 'test_stream_gc_stream_credit', 1,
         'ossl_quic_rxfc_get_rwm(count)'),
        ('reject-stream-credit', 'quic_stream_test', 'test_stream_gc_stream_credit', 3,
         'ossl_quic_rxfc_get_rwm(count)'),
    ]
    controls = []
    try:
        for label, program, name, iteration, marker in variants:
            for p, text in sources.items():
                (ROOT / p).write_text(text)
            if label == 'gc-admission':
                p = 'ssl/quic/quic_stream_map.c'
                old = subprocess.check_output(['git', 'show', BASE + ':' + p], text=True)
                pattern = r'static int qsm_ready_for_gc\([^\n]*\n\{.*?\n\}'
                body = re.search(pattern, old, re.S).group()
                text, count = re.subn(pattern, lambda m: body, sources[p], count=1, flags=re.S)
                assert count == 1
                # The upstream predicate leaves its send helper unused.
                text = text.replace('static int qsm_send_part_permits_gc(',
                                    'static ossl_unused int qsm_send_part_permits_gc(', 1)
                (ROOT / p).write_text(text)
            elif label == 'unread-byte-credit':
                p = 'ssl/quic/quic_stream_map.c'
                text = sources[p].replace('    uint64_t swm, rwm;\n', '', 1)
                pattern = r'        if \(ossl_quic_stream_has_recv\(qs\)\) \{\n.*?\n        \}\n'
                text, count = re.subn(pattern, '', text, count=1, flags=re.S)
                assert count == 1
                (ROOT / p).write_text(text)
            elif label == 'gc-before-tx':
                p = 'ssl/quic/quic_channel.c'
                begin = sources[p].index('        ossl_statm_get_rtt_info(ossl_quic_channel_get_statm(ch), &rtt_info);\n')
                end = sources[p].index('        /* Queue any data', begin)
                block = sources[p][begin:end]
                text = sources[p][:begin] + sources[p][end:]
                anchor = '        ch_tx(ch, &notify_other_threads);\n'
                assert text.count(anchor) == 1
                (ROOT / p).write_text(text.replace(anchor, anchor + '\n' + block, 1))
            elif label in ('receive-progress', 'null-send-controls'):
                p = 'ssl/quic/quic_rx_depack.c' if label == 'receive-progress' else 'ssl/quic/quic_fifd.c'
                (ROOT / p).write_bytes(subprocess.check_output(['git', 'show', BASE + ':' + p]))
            elif label == 'credit-only-txpim':
                p = 'ssl/quic/quic_txp.c'
                needle = 'if (stream->txp_sent_fc || stream->txp_sent_stop_sending'
                assert sources[p].count(needle) == 1
                (ROOT / p).write_text(sources[p].replace(needle, 'if (stream->txp_sent_stop_sending', 1))
            elif label == 'reset-late-loss':
                p = 'ssl/quic/quic_txp.c'
                needle = 's == NULL || s->send_state != QUIC_SSTREAM_STATE_RESET_SENT'
                assert sources[p].count(needle) == 1
                (ROOT / p).write_text(sources[p].replace(needle, 's == NULL', 1))
            elif label == 'reset-queued-ack':
                p = 'ssl/quic/quic_stream_map.c'
                needle = '        qs->want_reset_stream = 0;\n'
                assert sources[p].count(needle) == 1
                (ROOT / p).write_text(sources[p].replace(needle, '', 1))
            elif label == 'accept-stream-credit':
                p = 'ssl/quic/quic_stream_map.c'
                needle = '        --qsm->num_accept_uni;\n'
                assert sources[p].count(needle) == 1
                (ROOT / p).write_text(sources[p].replace(needle, needle +
                    '    (void)ossl_quic_rxfc_on_retire(qsm_get_max_streams_rxfc(qsm, s), 1, ossl_time_zero());\n', 1))
            else:
                assert label == 'reject-stream-credit'
                p = 'ssl/quic/quic_channel.c'
                needle = '    qs->deleted = 1;\n'
                assert sources[p].count(needle) == 1
                (ROOT / p).write_text(sources[p].replace(needle, needle +
                    '    (void)ossl_quic_rxfc_on_retire(ossl_quic_stream_is_bidi(qs) ? &ch->max_streams_bidi_rxfc : &ch->max_streams_uni_rxfc, 1, ossl_time_zero());\n', 1))
            delta = subprocess.check_output(['git', 'diff'])
            assert delta
            (OUT / ('negative-' + label + '.patch')).write_bytes(delta)
            # These upstream test programs link libssl.a, even in a shared
            # library configuration. Rebuilding only libssl.so is insufficient.
            run('rebuild-' + label, ['make', '-s', '-j4', 'build_libs'], timeout=900)
            run('relink-' + label, ['make', '-s', 'test/' + program], timeout=900)
            library_sha = hashlib.sha256((ROOT / 'libssl.so').read_bytes()).hexdigest()
            assert library_sha != candidate_library_sha
            archive_sha = hashlib.sha256((ROOT / 'libssl.a').read_bytes()).hexdigest()
            binary_sha = hashlib.sha256((ROOT / 'test' / program).read_bytes()).hexdigest()
            assert archive_sha != candidate_archive_sha
            assert binary_sha != candidate_binaries[program]
            text = run('negative-' + label, test_args(program, name, iteration),
                       timeout=180, expected=1, marker=marker)
            check_iteration(text, iteration, failed=True)
            controls.append({'variant': label, 'library_sha256': library_sha,
                             'candidate_library_sha256': candidate_library_sha,
                             'archive_sha256': archive_sha,
                             'candidate_archive_sha256': candidate_archive_sha,
                             'executed_test_sha256': binary_sha,
                             'candidate_test_sha256': candidate_binaries[program],
                             'delta_sha256': hashlib.sha256(delta).hexdigest(),
                             'test': name, 'iteration': iteration, 'specified_failure': marker})
    finally:
        for p, text in sources.items():
            (ROOT / p).write_text(text)
    (OUT / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
    run('restore-candidate-build', ['make', '-s', '-j4', 'build_libs'], timeout=900)
    run('restore-candidate-tests', ['make', '-s',
                                  *['test/' + p for p in sorted(candidate_binaries)]], timeout=900)
    assert hashlib.sha256((ROOT / 'libssl.so').read_bytes()).hexdigest() == candidate_library_sha
    assert hashlib.sha256((ROOT / 'libssl.a').read_bytes()).hexdigest() == candidate_archive_sha
    for program, expected_sha in candidate_binaries.items():
        assert hashlib.sha256((ROOT / 'test' / program).read_bytes()).hexdigest() == expected_sha
    for program, name in cases:
        run('restored-' + name, test_args(program, name), timeout=180)
assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
(OUT / 'verified.json').write_text(json.dumps({'accepted': True, 'profile': PROFILE,
    'source': head, 'baseline': BASE, 'candidate_libssl_sha256': candidate_library_sha,
    'candidate_static_archive_sha256': candidate_archive_sha,
    'executed_test_binaries_sha256': candidate_binaries,
    'mandatory_positive_groups': len(cases), 'negative_variants': 8 if PROFILE == 'normal' else 0,
    'full_quic_recipes': True, 'options': options, 'commands': len(history)}, indent=2) + '\n')
