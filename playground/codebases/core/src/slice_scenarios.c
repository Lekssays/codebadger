/*
 * slice_scenarios.c — Synthetic crash sites for program-slice unit tests.
 *
 * Each function mirrors a concrete crash from the program_slice.scala
 * improvement list.  Unit tests reference the exact line numbers below.
 * Compile with: gcc -Wall -Wextra -g -I../include -c slice_scenarios.c
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------
 * Scenario 1a: compound-assignment anchor (cp[0] &= ~...)
 * Old CALL-only anchor logic missed this — no named function call here.
 * Mirror of: CVE-2016-10271  tif_fax3.c:413
 * ------------------------------------------------------------------ */
void fill_runs(unsigned char *cp, const int *fillmasks, int run, int bx)
{
    cp[0] &= ~(fillmasks[run] >> bx);   /* line 20 — <operator>.assignmentAnd anchor */
}

/* ------------------------------------------------------------------
 * Scenario 1b: pointer-write in loop body (*op++ = value)
 * Loop body has only dereference + postincrement operators — no CALL.
 * Mirror of: CVE-2016-10272  tif_next.c:64
 * ------------------------------------------------------------------ */
void fill_buffer(void *buf, size_t occ)
{
    unsigned char *op;
    size_t cc;
    for (op = (unsigned char *)buf, cc = occ; cc > 0; cc--)
        *op++ = 0xff;   /* line 33 — pointer-write anchor */
}

/* ------------------------------------------------------------------
 * Scenario 1c: pure arithmetic anchor (shift expression, no CALL)
 * Only <operator>.shiftLeft on this line — no function call at all.
 * Mirror of: CVE-2017-7601  tif_jpeg.c:1646
 * ------------------------------------------------------------------ */
void compute_top(int bitspersample)
{
    long top = 1L << bitspersample;   /* line 43 — shift anchor; UB if >= 64 */
    (void)top;
}

/* ------------------------------------------------------------------
 * Scenario 6a: struct-field assignment; backward seed is field name.
 * Tracing "lyrno" must also match target "pi->lyrno" (endsWith variant).
 * Mirror of: CVE-2016-10251  jpc_t2cod.c:479+482
 * ------------------------------------------------------------------ */
typedef struct { int lyrno; } ProgIter;

void iter_loop(ProgIter *pi, int maxlyrno)
{
    for (pi->lyrno = 0; pi->lyrno < maxlyrno; pi->lyrno++)   /* line 56 — struct field assign */
        if (pi->lyrno >= maxlyrno)   /* line 57 — crash condition */
            break;
}

/* ------------------------------------------------------------------
 * Scenario 6b: typed declaration initializer.
 * "OJPEGState *sp = expr" may not emit <operator>.assignment in c2cpg;
 * the slice falls back to method.local to detect the initializer.
 * Mirror of: CVE-2016-10267  tif_ojpeg.c:806+816
 * ------------------------------------------------------------------ */
typedef struct { int bytes_per_line; } OJPEGState;

void ojpeg_decode(void *tif_data, size_t cc)
{
    OJPEGState *sp = (OJPEGState *)tif_data;   /* line 71 — typed-decl initializer */
    if (cc % (size_t)sp->bytes_per_line != 0)   /* line 72 — crash condition */
        return;
}

/* ------------------------------------------------------------------
 * Scenario 7: macro-expansion anchor requiring ±3-line fallback.
 * SLICE_GET32 expands to only indirection/cast operator nodes.
 * The fallback scans lines ±3 and finds the surrounding assignment.
 * Mirror of: CVE-2017-5974  memdisk.c:224
 * ------------------------------------------------------------------ */
#define SLICE_GET32(p) (*(const uint32_t *)(p))

void process_block(const unsigned char *block, size_t off)
{
    uint32_t diskstart = SLICE_GET32(block + off);   /* line 86 — macro expansion anchor */
    (void)diskstart;
}

/* ------------------------------------------------------------------
 * Scenario 9: forward slice for patch differentiation.
 * Backward from crash site; forward from the patch site shows the
 * corrected bytes_per_line propagating safely to the same condition.
 * Mirror of: CVE-2016-10267  tif_ojpeg.c  (bytes_per_line fix)
 * ------------------------------------------------------------------ */
typedef struct {
    int bytes_per_line;
    int subsampling_hor;
    int subsampling_ver;
} OJPEGFull;

void vulnerable_init(OJPEGFull *sp, int w)
{
    sp->bytes_per_line = w;                          /* line 104 — patch site (forward anchor) */
    if (w % sp->bytes_per_line != 0) return;         /* line 105 — crash site (backward anchor) */
}

void patched_init(OJPEGFull *sp, int w, int hor, int ver)
{
    sp->bytes_per_line = w;
    sp->bytes_per_line *= hor * ver;                 /* line 111 — fix: subsampling correction */
    if (w % sp->bytes_per_line != 0) return;         /* line 112 — same crash site, now safe */
}
