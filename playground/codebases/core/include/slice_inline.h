/*
 * slice_inline.h — Static inline functions defined entirely in a header.
 *
 * Exercises the <global> fallback in program_slice.scala: c2cpg assigns
 * "static inline" header functions to <global> instead of a named method,
 * so the old filterNot(_.name == "<global>") guard would silently drop them.
 *
 * Mirror of: CVE-2016-9556  pixel-accessor.h:507  (ImageMagick)
 *            CVE-2017-14638  Ap4Atom.h:247         (Bento4)
 */
#ifndef SLICE_INLINE_H
#define SLICE_INLINE_H

#include <stdint.h>

typedef unsigned char Quantum;

/* ------------------------------------------------------------------
 * Mirrors ImageMagick pixel-accessor.h:507.
 * "static inline" in a .h file => c2cpg may place this in <global>.
 * ------------------------------------------------------------------ */
static inline int is_pixel_gray(const Quantum *pixel, int channels)
{
    (void)channels;
    int red_green = (int)pixel[0] - (int)pixel[1];   /* line 25 — crash site: arithmetic on pixel */
    int green_blue = (int)pixel[1] - (int)pixel[2];  /* line 26 */
    return (red_green == 0) && (green_blue == 0);
}

/* ------------------------------------------------------------------
 * Mirrors Bento4 Ap4Atom.h:247 — one-liner inline in a header.
 * Single assignment in header scope; no .cpp TU sees this line.
 * ------------------------------------------------------------------ */
typedef struct { uint32_t m_Type; } Ap4Atom;

static inline void ap4_atom_set_type(Ap4Atom *atom, uint32_t type)
{
    atom->m_Type = type;   /* line 38 — struct-field write in header inline */
}

#endif /* SLICE_INLINE_H */
