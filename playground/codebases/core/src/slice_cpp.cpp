/*
 * slice_cpp.cpp — C++ virtual dispatch patterns for program-slice tests.
 *
 * Exercises the DYNAMIC_DISPATCH backward-trace path added to
 * program_slice.scala.  c2cpg handles C++ but virtual dispatch means
 * method.callIn finds no callers — only a DYNAMIC_DISPATCH scan resolves them.
 *
 * Mirror of: CVE-2017-14640  Ap4AtomSampleTable.cpp:143  (Bento4)
 *            CVE-2017-14642  Ap4HdlrAtom.cpp:85           (Bento4)
 */
#include <cstddef>
#include <cstring>
#include <cstdlib>

/* ------------------------------------------------------------------
 * Base class with a pure-virtual method.
 * method.callIn on GetDts() finds zero static callers because c2cpg
 * cannot resolve vtable dispatch; DYNAMIC_DISPATCH scan is required.
 * ------------------------------------------------------------------ */
struct AtomBase {
    virtual int GetDts(int index, long *dts, long *duration) = 0;
    virtual ~AtomBase() {}
};

struct SttsAtom : public AtomBase {
    int data[16];
    int GetDts(int index, long *dts, long *duration) override {
        if (index >= 16) return -1;
        *dts      = data[index];
        *duration = data[index];
        return 0;
    }
};

/* ------------------------------------------------------------------
 * Simulates Ap4AtomSampleTable.cpp:143 — virtual call via base ptr.
 * Anchor: DYNAMIC_DISPATCH call to GetDts.
 * ------------------------------------------------------------------ */
int sample_table_get_dts(AtomBase *m_SttsAtom, int index,
                         long *dts, long *duration)
{
    int result = m_SttsAtom->GetDts(index, dts, duration);   /* line 42 — virtual call anchor */
    return result;
}

/* ------------------------------------------------------------------
 * Simulates Ap4HdlrAtom.cpp:85 — new[] with user-controlled size.
 * When name_size wraps at UINT_MAX, name_size+1 == 0 and new[] returns
 * a tiny (or zero-size) allocation; the subsequent memset overflows it.
 * ------------------------------------------------------------------ */
char *hdlr_atom_alloc_name(unsigned int name_size)
{
    char *name = new char[name_size + 1];   /* line 53 — integer-wrap heap alloc */
    if (!name) return nullptr;
    std::memset(name, 0, name_size + 1);
    return name;
}
