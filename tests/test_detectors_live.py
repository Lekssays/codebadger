"""Live-Joern accuracy tests for the memory-safety detectors.

These build real CPGs from small labeled C fixtures and run the ACTUAL detector
.scala queries through a Joern server (the same /query-sync path the MCP uses),
then assert which functions are flagged. They encode the true-positive /
false-positive matrix the detectors must satisfy, so a regression in the CPGQL
logic fails here rather than silently in production.

Opt-in: requires Docker + the `codebadger-joern-server` image, and the
CODEBADGER_LIVE_JOERN env var (the build is heavy). Skipped otherwise.

  CODEBADGER_LIVE_JOERN=1 python -m pytest tests/test_detectors_live.py -v
"""

import json
import os
import shutil
import subprocess
import time
import uuid

import pytest

from src.tools.queries import QueryLoader

CONTAINER = os.getenv("CODEBADGER_JOERN_CONTAINER", "codebadger-joern-server")
PORT = int(os.getenv("CODEBADGER_LIVE_JOERN_PORT", "18091"))


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                       capture_output=True, text=True)
    return r.returncode == 0 and CONTAINER in r.stdout


pytestmark = pytest.mark.skipif(
    not (os.getenv("CODEBADGER_LIVE_JOERN") and _docker_ok()),
    reason="set CODEBADGER_LIVE_JOERN=1 and run the codebadger-joern-server container",
)


def _dexec(cmd: str, data: str = None):
    base = ["docker", "exec"] + (["-i"] if data is not None else []) + [CONTAINER, "bash", "-lc", cmd]
    return subprocess.run(base, input=data, capture_output=True, text=True)


def _q(scala: str, timeout: int = 180) -> dict:
    payload = json.dumps({"query": scala})
    r = _dexec(
        f"curl -s -m {timeout} -X POST http://127.0.0.1:{PORT}/query-sync "
        f"-H 'Content-Type: application/json' --data-binary @-", payload)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"success": False, "stdout": "", "stderr": r.stdout + r.stderr}


@pytest.fixture(scope="module")
def server():
    chk = _dexec(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{PORT} || true")
    if chk.stdout.strip() not in ("200", "404"):
        _dexec(f"mkdir -p /tmp/qh_test && nohup /opt/joern/joern-cli/joern --server "
               f"--server-host 127.0.0.1 --server-port {PORT} > /tmp/qh_test/server.log 2>&1 &")
        for _ in range(90):
            time.sleep(1)
            chk = _dexec(f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{PORT} || true")
            if chk.stdout.strip() in ("200", "404"):
                break
        else:
            pytest.skip("joern server did not start")
    return True


def _run_detector(server, fixture_src: str, detector: str) -> str:
    """Build a CPG from fixture_src, run `detector`, return the result text."""
    proj = "t_" + uuid.uuid4().hex[:10]
    _dexec(f"rm -rf /tmp/qh_test/{proj} && mkdir -p /tmp/qh_test/{proj}")
    _dexec(f"cat > /tmp/qh_test/{proj}/f.c", fixture_src)
    imp = _q(f'importCode(inputPath="/tmp/qh_test/{proj}", projectName="{proj}")', timeout=300)
    assert imp.get("success"), f"importCode failed: {imp.get('stderr','')[:500]}"
    QueryLoader.clear_cache()
    block = QueryLoader.load(detector, filename="", limit=100)
    res = _q(block)
    assert res.get("success"), f"detector failed: {res.get('stderr','')[:800]}"
    out = res.get("stdout", "")
    if "<codebadger_result>" in out:
        return out.split("<codebadger_result>", 1)[1].split("</codebadger_result>", 1)[0] \
                  .encode().decode("unicode_escape")
    return out


# --- use_after_free -------------------------------------------------------

UAF_FIXTURE = r"""
#include <stdlib.h>
void sink(char *p);
void uaf_direct(char *p) { free(p); sink(p); }
void safe_mutex(char *p, int c) { if (c) { free(p); } else { sink(p); } }
void safe_realloc(char *p) { free(p); p = (char *)malloc(8); sink(p); }
void safe_return(char *p) { free(p); return; sink(p); }
void uaf_guarded_use(char *p, int c) { free(p); if (c) { sink(p); } }
void uaf_same_line(char *p) { free(p); sink(p); }
void uaf_loop(char *p) { for (int i=0;i<2;i++){ sink(p); free(p); } }
void safe_before(char *p) { sink(p); free(p); }
"""


def test_use_after_free_matrix(server):
    out = _run_detector(server, UAF_FIXTURE, "use_after_free")
    fire = lambda fn: f"in {fn}()" in out
    # True positives — must fire (incl. same-line and loop-carried, previously missed)
    assert fire("uaf_direct")
    assert fire("uaf_guarded_use")
    assert fire("uaf_same_line"), "same-line free(p); sink(p) must be detected"
    assert fire("uaf_loop"), "loop-carried use-after-free must be detected"
    # False positives — must NOT fire
    assert not fire("safe_mutex"), "mutually-exclusive branches are not a UAF"
    assert not fire("safe_realloc"), "reassigned pointer is not a UAF"
    assert not fire("safe_return"), "dead code after return is not a UAF"
    assert not fire("safe_before"), "use strictly before free is not a UAF"


# --- double_free ----------------------------------------------------------

DF_FIXTURE = r"""
#include <stdlib.h>
void df_true(char *p){ free(p); free(p); }
void df_realloc(char *p){ free(p); p=(char*)malloc(8); free(p); }
void df_mutex(char *p,int c){ if(c){free(p);} else {free(p);} }
void df_distinct(char *a, char *b){ free(a); free(b); }
void df_alias_ml(char *p){
    char *q = p;
    free(p);
    free(q);
}
void df_true_ml(char *p){
    free(p);
    p[0]=0;
    free(p);
}
"""


def test_double_free_matrix(server):
    out = _run_detector(server, DF_FIXTURE, "double_free")
    fire = lambda fn: f"in {fn}()" in out
    assert fire("df_true"), "straight-line double free must fire"
    assert fire("df_true_ml"), "multi-line same-pointer double free must fire"
    assert fire("df_alias_ml"), "multi-line alias double free must fire"
    assert not fire("df_realloc"), "realloc between frees is not a double free"
    assert not fire("df_mutex"), "mutually-exclusive frees are not a double free"
    assert not fire("df_distinct"), "freeing two different pointers is not a double free"


# --- null_pointer_deref ---------------------------------------------------

NPD_FIXTURE = r"""
#include <stdlib.h>
void npd_true(void){
    char *p = malloc(8);
    p[0] = 0;
}
void npd_eq(void){
    char *p = malloc(8);
    if (p == NULL) return;
    p[0] = 0;
}
void npd_bang(void){
    char *p = malloc(8);
    if (!p) return;
    p[0] = 0;
}
void npd_ifp(void){
    char *p = malloc(8);
    if (p) { p[0] = 0; }
}
void npd_reassigned(char *o){
    char *p = malloc(8);
    p = o;
    p[0] = 0;
}
"""


TOCTOU_FIXTURE = r"""
#include <sys/stat.h>
#include <fcntl.h>
void tc_samevar(const char *path){
    struct stat st;
    stat(path, &st);
    open(path, 0);
}
void tc_literal(void){
    struct stat st;
    stat("/tmp/x", &st);
    open("/tmp/x", 0);
}
void fp_diffvar(const char *file, const char *file2){
    struct stat st;
    stat(file, &st);
    open(file2, 0);
}
void fp_diffliteral(void){
    struct stat st;
    stat("file", &st);
    open("file2", 0);
}
"""


def test_toctou_matrix(server):
    out = _run_detector(server, TOCTOU_FIXTURE, "toctou")
    fire = lambda fn: f"{fn}()" in out
    assert fire("tc_samevar"), "check+use on the same variable is a TOCTOU"
    assert fire("tc_literal"), "check+use on the same path literal is a TOCTOU"
    # The substring `startsWith` match flagged these distinct paths before.
    assert not fire("fp_diffvar"), "stat(file)/open(file2) are different variables"
    assert not fire("fp_diffliteral"), "stat(\"file\")/open(\"file2\") are different paths"


HEAP_OVERFLOW_FIXTURE = r"""
#include <stdlib.h>
#include <string.h>
void ho_const_overflow(const char *src){
    char *p = malloc(16);
    memcpy(p, src, 32);
}
void ho_safe_const(const char *src){
    char *p = malloc(64);
    memcpy(p, src, 16);
}
void ho_strcpy(const char *src){
    char *p = malloc(8);
    strcpy(p, src);
}
void ho_same_var(const char *src, int n){
    char *p = malloc(n);
    memcpy(p, src, n);
}
void ho_bounded(const char *src, int n, int m){
    char *p = malloc(n);
    if (m <= n) {
        memcpy(p, src, m);
    }
}
"""


def test_heap_overflow_matrix(server):
    out = _run_detector(server, HEAP_OVERFLOW_FIXTURE, "heap_overflow")
    fire = lambda fn: f"in {fn}()" in out
    assert fire("ho_const_overflow"), "memcpy 32 into malloc(16) overflows"
    assert fire("ho_strcpy"), "strcpy into a heap buffer is unbounded"
    # Numeric size comparison: 16 < 64 is safe (string compare reported it before).
    assert not fire("ho_safe_const"), "memcpy 16 into malloc(64) is safe"
    assert not fire("ho_same_var"), "write size == allocation size is safe"
    assert not fire("ho_bounded"), "a real m<=n bounds check guards the write"


STACK_OVERFLOW_FIXTURE = r"""
#include <string.h>
void so_overflow(const char *src){
    char buf[16];
    memcpy(buf, src, 32);
}
void so_safe(const char *src){
    char buf[64];
    memcpy(buf, src, 16);
}
void so_strcpy(const char *src){
    char buf[8];
    strcpy(buf, src);
}
void so_sizeof(const char *src){
    char buf[16];
    memcpy(buf, src, sizeof(buf));
}
"""


def test_stack_overflow_matrix(server):
    out = _run_detector(server, STACK_OVERFLOW_FIXTURE, "stack_overflow")
    fire = lambda fn: f"in {fn}()" in out
    assert fire("so_overflow"), "memcpy 32 into char[16] overflows"
    assert fire("so_strcpy"), "strcpy into a fixed-size stack buffer is unbounded"
    assert not fire("so_safe"), "memcpy 16 into char[64] is safe"
    assert not fire("so_sizeof"), "memcpy sizeof(buf) into buf is safe"


def test_null_pointer_deref_matrix(server):
    out = _run_detector(server, NPD_FIXTURE, "null_pointer_deref")
    fire = lambda fn: f"in {fn}()" in out
    assert fire("npd_true"), "unchecked malloc deref must fire"
    # The two most common correct guards must SUPPRESS the finding. These were
    # false positives before the condAst iterator-reuse + NULL-operand fixes.
    assert not fire("npd_eq"), "if (p == NULL) return; must suppress the deref"
    assert not fire("npd_bang"), "if (!p) return; must suppress the deref"
    assert not fire("npd_ifp"), "if (p) { ... } must suppress the deref"
    assert not fire("npd_reassigned"), "reassigned pointer is not a null deref"
