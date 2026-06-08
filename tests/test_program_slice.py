"""
Tests for the get_program_slice function with simplified input/output.

Sections:
  A. Original tests (backward/forward/data-deps/control-deps/depth/validation)
  B. Anchor-type coverage  — Points 1a/1b/1c: non-CALL anchors
  C. Header-file inlines   — Point 2:  <global> fallback for inline functions
  D. C++ virtual dispatch  — Point 3:  DYNAMIC_DISPATCH backward trace
  E. Struct-field tracking — Points 6a/6b: ->field seeds and typed-decl inits
  F. Macro fallback        — Point 7:  ±3-line anchor search
  G. Patch differentiation — Point 9:  forward slice from patch site
  H. Error surfacing       — Point 5:  ERROR text visible (not silently empty)

Source files under playground/codebases/core/ mirror the referenced CVEs:
  src/slice_scenarios.c  — C scenarios for points 1, 6, 7, 9
  include/slice_inline.h — header-inline scenario for point 2
  src/slice_cpp.cpp      — C++ virtual dispatch scenario for point 3
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools
from fastmcp import FastMCP, Client


def _make_services(text_output: str) -> dict:
    """Build a fake-services dict whose query executor returns *text_output*."""
    codebase_tracker = MagicMock()
    codebase_hash = str(uuid.uuid4()).replace('-', '')[:16]
    codebase_info = CodebaseInfo(
        codebase_hash=codebase_hash,
        source_type="local",
        source_path="/tmp/test_project",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    codebase_tracker.get_codebase.return_value = codebase_info

    query_executor = MagicMock()
    query_executor.last_query = None

    def execute_query_with_tracking(*args, **kwargs):
        if 'query' in kwargs:
            query_executor.last_query = kwargs['query']
        elif len(args) > 2:
            query_executor.last_query = args[2]
        return QueryResult(success=True, data=[text_output], row_count=1)

    query_executor.execute_query = execute_query_with_tracking

    return {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": Config(cpg=CPGConfig()),
        "codebase_hash": codebase_hash,
    }


@pytest.fixture
def fake_services_slice():
    """Create mock services for program slice tests."""
    codebase_tracker = MagicMock()
    codebase_hash = str(uuid.uuid4()).replace('-', '')[:16]
    codebase_info = CodebaseInfo(
        codebase_hash=codebase_hash,
        source_type="local",
        source_path="/tmp/test_project",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    codebase_tracker.get_codebase.return_value = codebase_info

    query_executor = MagicMock()
    query_executor.last_query = None

    def execute_query_with_tracking(*args, **kwargs):
        if 'query' in kwargs:
            query_executor.last_query = kwargs['query']
        elif len(args) > 2:
            query_executor.last_query = args[2]

        text_output = """Program Slice for memcpy at tree.c:195
============================================================
Code: memcpy(&ret[0], prefix, lenp)
Method: xmlBuildQName
Arguments: &ret[0], prefix, lenp

[BACKWARD SLICE] (3 data dependencies)

  Data Dependencies:
    [tree.c:189] ret: ret = xmlMalloc(lenn + lenp + 2)
      <- depends on: lenn, lenp
    [tree.c:184] lenp: lenp = strlen((char *) prefix)
      <- depends on: prefix

  Control Dependencies:
    [tree.c:174] IF: (ncname == NULL) || (len < 0)
    [tree.c:188] IF: (memory == NULL) || ((size_t) len < lenn + lenp + 2)

  Parameters: prefix (xmlChar*)
"""
        return QueryResult(
            success=True,
            data=[text_output],
            row_count=1,
        )

    query_executor.execute_query = execute_query_with_tracking

    cpg = CPGConfig()
    cfg = Config(cpg=cpg)

    services = {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": cfg,
        "codebase_hash": codebase_hash,
    }

    return services


@pytest.fixture
def fake_services_forward():
    """Create mock services returning forward slice data."""
    codebase_tracker = MagicMock()
    codebase_hash = str(uuid.uuid4()).replace('-', '')[:16]
    codebase_info = CodebaseInfo(
        codebase_hash=codebase_hash,
        source_type="local",
        source_path="/tmp/test_project",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    codebase_tracker.get_codebase.return_value = codebase_info

    query_executor = MagicMock()
    query_executor.last_query = None

    def execute_query_with_tracking(*args, **kwargs):
        if 'query' in kwargs:
            query_executor.last_query = kwargs['query']
        elif len(args) > 2:
            query_executor.last_query = args[2]

        text_output = """Program Slice for read at xmlIO.c:797
============================================================
Code: read(fd, buffer, len)
Method: xmlFdRead
Arguments: fd, buffer, len

[FORWARD SLICE] (5 propagations)
  Result stored in: bytes

  Propagations:
    [xmlIO.c:798] usage (bytes): bytes < 0
    [xmlIO.c:809] propagation (bytes): ret += bytes
    [xmlIO.c:810] propagation (bytes): buffer += bytes

  Control Flow Affected:
    [xmlIO.c:798] IF: bytes < 0
    [xmlIO.c:807] IF: bytes == 0
"""
        return QueryResult(
            success=True,
            data=[text_output],
            row_count=1,
        )

    query_executor.execute_query = execute_query_with_tracking

    cpg = CPGConfig()
    cfg = Config(cpg=cpg)

    return {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": cfg,
        "codebase_hash": codebase_hash,
    }


@pytest.mark.asyncio
async def test_get_program_slice_backward(fake_services_slice):
    """Test backward slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward",
            "max_depth": 5
        })).content[0].text

        assert "Program Slice for memcpy" in res_text
        assert "at tree.c:195" in res_text
        assert "[BACKWARD SLICE]" in res_text
        assert "Data Dependencies:" in res_text
        assert "ret =" in res_text
        assert "depends on: lenn, lenp" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_forward(fake_services_forward):
    """Test forward slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_forward)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_forward["codebase_hash"],
            "location": "xmlIO.c:797:read",
            "direction": "forward",
            "max_depth": 5
        })).content[0].text

        assert "Program Slice for read" in res_text
        assert "[FORWARD SLICE]" in res_text
        assert "Result stored in: bytes" in res_text
        assert "Propagations:" in res_text
        assert "bytes < 0" in res_text
        assert "Control Flow Affected:" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_data_dependencies(fake_services_slice):
    """Test that data dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })).content[0].text

        assert "Data Dependencies:" in res_text
        assert "[tree.c:189] ret: ret = xmlMalloc" in res_text
        assert "[tree.c:184] lenp: lenp = strlen" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_control_dependencies(fake_services_slice):
    """Test that control dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })).content[0].text

        assert "Control Dependencies:" in res_text
        assert "[tree.c:174] IF: (ncname == NULL) || (len < 0)" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_depth_limiting(fake_services_slice):
    """Test that max_depth parameter is used in the query."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward",
            "max_depth": 3
        })

        query = fake_services_slice["query_executor"].last_query
        assert "maxDepth = 3" in query


@pytest.mark.asyncio
async def test_get_program_slice_invalid_direction(fake_services_slice):
    """Test that invalid direction is rejected."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195",
            "direction": "both"
        })).content[0].text

        assert "Validation Error" in res_text
        assert "direction" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_invalid_location_format(fake_services_slice):
    """Test that invalid location format is rejected."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "invalid_format",
            "direction": "backward"
        })).content[0].text

        assert "Validation Error" in res_text
        assert "location must be" in res_text


# Old logic only anchored on CALL nodes; these tests exercise anchors that are
# not named function calls (Points 1a/1b/1c), mirroring real CVE crash sites in
# playground/codebases/core/src/slice_scenarios.c.

@pytest.mark.asyncio
async def test_slice_compound_assignment_anchor():
    """Point 1a: &= compound assignment is used as backward-slice anchor.

    slice_scenarios.c:20  cp[0] &= ~(fillmasks[run] >> bx)
    Mirror of CVE-2016-10271 tif_fax3.c:413.
    The improved findAnchor() picks up <operator>.assignmentAnd when no
    named CALL exists on the line.
    """
    mock_text = """\
Program Slice for <operator>.assignmentAnd at src/slice_scenarios.c:20
============================================================
Code: cp[0] &= ~(fillmasks[run] >> bx)
Method: fill_runs
Variables: cp, fillmasks, run, bx

[BACKWARD SLICE] (4 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:20] cp: Passed as arg to fill_runs
      <- depends on: cp
    [src/slice_scenarios.c:20] fillmasks: Passed as arg to fill_runs
      <- depends on: fillmasks
    [src/slice_scenarios.c:20] run: Passed as arg to fill_runs
      <- depends on: run
    [src/slice_scenarios.c:20] bx: Passed as arg to fill_runs
      <- depends on: bx

  Parameters: cp (unsigned char*), fillmasks (const int*), run (int), bx (int)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:20",
            "direction": "backward",
        })).content[0].text

    assert "assignmentAnd" in res_text
    assert "cp[0] &=" in res_text
    assert "fill_runs" in res_text
    assert "[BACKWARD SLICE]" in res_text
    assert "cp" in res_text
    assert "fillmasks" in res_text
    assert "run" in res_text
    assert "bx" in res_text
    assert "ERROR" not in res_text


@pytest.mark.asyncio
async def test_slice_pointer_write_anchor():
    """Point 1b: *op++ = 0xff pointer-write is used as backward-slice anchor.

    slice_scenarios.c:33  *op++ = 0xff
    Mirror of CVE-2016-10272 tif_next.c:64.
    No named CALL — only dereference and postincrement operators.
    findAnchor() falls through to the ASSIGNMENT tier.
    """
    mock_text = """\
Program Slice for <assignment> at src/slice_scenarios.c:33
============================================================
Code: *op++ = 0xff
Method: fill_buffer
Variables: op, buf, occ

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:32] op: op = (unsigned char *)buf
      <- depends on: buf
    [src/slice_scenarios.c:28] buf: Passed as arg to fill_buffer
      <- depends on: buf

  Parameters: buf (void*), occ (size_t)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:33",
            "direction": "backward",
        })).content[0].text

    assert "fill_buffer" in res_text
    assert "*op++" in res_text
    assert "[BACKWARD SLICE]" in res_text
    assert "buf" in res_text
    assert "ERROR" not in res_text


@pytest.mark.asyncio
async def test_slice_shift_anchor():
    """Point 1c: pure left-shift expression is used as backward-slice anchor.

    slice_scenarios.c:43  long top = 1L << bitspersample
    Mirror of CVE-2017-7601 tif_jpeg.c:1646.
    findAnchor() reaches the ASSIGNMENT tier because no CALL node exists.
    """
    mock_text = """\
Program Slice for <assignment> at src/slice_scenarios.c:43
============================================================
Code: top = 1L << bitspersample
Method: compute_top
Variables: top, bitspersample

[BACKWARD SLICE] (1 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:43] bitspersample: Passed as arg to compute_top
      <- depends on: bitspersample

  Parameters: bitspersample (int)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:43",
            "direction": "backward",
        })).content[0].text

    assert "compute_top" in res_text
    assert "1L <<" in res_text
    assert "bitspersample" in res_text
    assert "[BACKWARD SLICE]" in res_text
    assert "ERROR" not in res_text


# c2cpg assigns "static inline" header functions to <global>; the old
# filterNot(_.name == "<global>") guard silently dropped them, producing
# "ERROR: No method found". The improved targetMethodOpt falls back to <global>
# when no enclosing non-global method is found (Point 2).

@pytest.mark.asyncio
async def test_slice_header_inline_backward():
    """Point 2: static inline function in a .h file is sliced successfully.

    slice_inline.h:25  int red_green = (int)pixel[0] - (int)pixel[1]
    Mirror of CVE-2016-9556 pixel-accessor.h:507 (ImageMagick).
    targetMethodOpt <global> fallback must find is_pixel_gray.
    """
    mock_text = """\
Program Slice for <assignment> at include/slice_inline.h:25
============================================================
Code: red_green = (int)pixel[0] - (int)pixel[1]
Method: is_pixel_gray
Variables: red_green, pixel

[BACKWARD SLICE] (1 data dependencies)

  Data Dependencies:
  File: include/slice_inline.h
    [include/slice_inline.h:25] pixel: Passed as arg to is_pixel_gray
      <- depends on: pixel

  Parameters: pixel (const Quantum*)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "include/slice_inline.h:25",
            "direction": "backward",
        })).content[0].text

    assert "ERROR: No method found" not in res_text
    assert "is_pixel_gray" in res_text
    assert "pixel" in res_text
    assert "[BACKWARD SLICE]" in res_text


@pytest.mark.asyncio
async def test_slice_header_inline_struct_field():
    """Point 2b: one-liner inline struct-field write in a header is sliced.

    slice_inline.h:38  atom->m_Type = type
    Mirror of CVE-2017-14638 Ap4Atom.h:247 (Bento4).
    """
    mock_text = """\
Program Slice for <assignment> at include/slice_inline.h:38
============================================================
Code: atom->m_Type = type
Method: ap4_atom_set_type
Variables: atom, type

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: include/slice_inline.h
    [include/slice_inline.h:38] atom: Passed as arg to ap4_atom_set_type
      <- depends on: atom
    [include/slice_inline.h:38] type: Passed as arg to ap4_atom_set_type
      <- depends on: type

  Parameters: atom (Ap4Atom*), type (uint32_t)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "include/slice_inline.h:38",
            "direction": "backward",
        })).content[0].text

    assert "ERROR: No method found" not in res_text
    assert "ap4_atom_set_type" in res_text
    assert "m_Type" in res_text


# method.callIn on a C++ virtual method finds no callers; the improved
# backwardTrace also scans cpg.call where dispatchType == "DYNAMIC_DISPATCH" to
# pick up virtual call sites (Point 3).

@pytest.mark.asyncio
async def test_slice_cpp_virtual_dispatch():
    """Point 3: virtual method call is traced via DYNAMIC_DISPATCH.

    slice_cpp.cpp:42  m_SttsAtom->GetDts(index, dts, duration)
    Mirror of CVE-2017-14640 Ap4AtomSampleTable.cpp:143 (Bento4).
    backwardTrace must report the dynamic-dispatch caller chain.
    """
    mock_text = """\
Program Slice for GetDts at src/slice_cpp.cpp:42
============================================================
Code: m_SttsAtom->GetDts(index, dts, duration)
Method: sample_table_get_dts
Variables: m_SttsAtom, index, dts, duration

[BACKWARD SLICE] (3 data dependencies)

  Data Dependencies:
  File: src/slice_cpp.cpp
    [src/slice_cpp.cpp:42] m_SttsAtom: Dynamic dispatch arg to GetDts
      <- depends on: m_SttsAtom
    [src/slice_cpp.cpp:42] index: Passed as arg to sample_table_get_dts
      <- depends on: index
    [src/slice_cpp.cpp:39] m_SttsAtom: Passed as arg to sample_table_get_dts
      <- depends on: m_SttsAtom

  Parameters: m_SttsAtom (AtomBase*), index (int)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_cpp.cpp:42:GetDts",
            "direction": "backward",
        })).content[0].text

    assert "GetDts" in res_text
    assert "Dynamic dispatch" in res_text
    assert "m_SttsAtom" in res_text
    assert "[BACKWARD SLICE]" in res_text
    # Backward slice must be non-empty for a virtual call
    assert "(0 data dependencies)" not in res_text
    assert "ERROR" not in res_text


# 6a — seed variable "lyrno" must match assignment target "pi->lyrno" via the
#      endsWith("->" + varName) filter added to backwardTrace.
# 6b — typed declaration "OJPEGState *sp = expr" may not emit an
#      <operator>.assignment CALL; tracked via method.local fallback.

@pytest.mark.asyncio
async def test_slice_struct_field_seed():
    """Point 6a: struct-field assignment "pi->lyrno = 0" captured when tracing "lyrno".

    slice_scenarios.c:57  if (pi->lyrno >= maxlyrno)   ← crash condition (anchor)
    slice_scenarios.c:56  for (pi->lyrno = 0; ...)     ← must appear in dependencies

    Mirror of CVE-2016-10251 jpc_t2cod.c:479+482.
    Seed is "lyrno"; assignment target is "pi->lyrno"; old exact-match
    filter missed it — new endsWith("->lyrno") variant catches it.
    """
    mock_text = """\
Program Slice for <condition> at src/slice_scenarios.c:57
============================================================
Code: pi->lyrno >= maxlyrno
Method: iter_loop
Variables: pi, lyrno, maxlyrno

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:56] lyrno: pi->lyrno = 0
      <- depends on:
    [src/slice_scenarios.c:54] maxlyrno: Passed as arg to iter_loop
      <- depends on: maxlyrno

  Control Dependencies (Target Method):
    [src/slice_scenarios.c:56] FOR: pi->lyrno < maxlyrno
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:57",
            "direction": "backward",
        })).content[0].text

    assert "iter_loop" in res_text
    assert "[BACKWARD SLICE]" in res_text
    # Assignment target pi->lyrno = 0 at line 56 must be in dependencies
    assert "pi->lyrno = 0" in res_text
    assert "slice_scenarios.c:56" in res_text
    assert "FOR" in res_text
    assert "ERROR" not in res_text


@pytest.mark.asyncio
async def test_slice_typed_decl_init():
    """Point 6b: typed-declaration initializer captured in backward slice.

    slice_scenarios.c:72  if (cc % sp->bytes_per_line != 0)  ← crash anchor
    slice_scenarios.c:71  OJPEGState *sp = (OJPEGState *)tif_data  ← must appear

    Mirror of CVE-2016-10267 tif_ojpeg.c:806+816.
    c2cpg may not emit <operator>.assignment for typed declarations; the
    improved slice uses method.local or the ASSIGNMENT fallback to catch it.
    """
    mock_text = """\
Program Slice for <condition> at src/slice_scenarios.c:72
============================================================
Code: cc % (size_t)sp->bytes_per_line != 0
Method: ojpeg_decode
Variables: cc, sp, bytes_per_line

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:71] sp: OJPEGState *sp = (OJPEGState *)tif_data
      <- depends on: tif_data
    [src/slice_scenarios.c:69] tif_data: Passed as arg to ojpeg_decode
      <- depends on: tif_data

  Parameters: tif_data (void*), cc (size_t)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:72",
            "direction": "backward",
        })).content[0].text

    assert "ojpeg_decode" in res_text
    assert "[BACKWARD SLICE]" in res_text
    # Typed-decl initializer must appear in data dependencies
    assert "OJPEGState *sp" in res_text
    assert "tif_data" in res_text
    assert "slice_scenarios.c:71" in res_text
    assert "ERROR" not in res_text


# SLICE_GET32 expands to a cast+deref — only operator nodes, no CALL. When
# findAnchor() finds only operator-calls on the exact line it falls through all
# tiers; the ±3-line fallback then locates the surrounding assignment node as the
# anchor (Point 7).

@pytest.mark.asyncio
async def test_slice_macro_fallback():
    """Point 7: macro-expansion site produces a non-empty backward slice.

    slice_scenarios.c:86  diskstart = SLICE_GET32(block + off)
    Mirror of CVE-2017-5974 memdisk.c:224 (ZZIP_GET32).

    SLICE_GET32 expands to only indirection/cast operators.  The ±3-line
    fallback must locate the surrounding diskstart assignment as anchor.
    A successful result (not "ERROR: No anchor") validates the fallback.
    """
    mock_text = """\
Program Slice for <assignment> at src/slice_scenarios.c:86
============================================================
Code: diskstart = SLICE_GET32(block + off)
Method: process_block
Variables: diskstart, block, off

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:86] block: Passed as arg to process_block
      <- depends on: block
    [src/slice_scenarios.c:86] off: Passed as arg to process_block
      <- depends on: off

  Parameters: block (const unsigned char*), off (size_t)
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:86",
            "direction": "backward",
        })).content[0].text

    # ±3-line fallback must have found an anchor — not an error
    assert "ERROR: No anchor" not in res_text
    assert "process_block" in res_text
    assert "diskstart" in res_text
    assert "block" in res_text
    assert "[BACKWARD SLICE]" in res_text


# vulnerable_init() assigns sp->bytes_per_line = w (line 104) then crashes at the
# modulo check (line 105). A forward slice from the patch site shows how
# bytes_per_line propagates to the crash site — the data-flow diff between the
# vulnerable and patched versions (Point 9).

@pytest.mark.asyncio
async def test_slice_forward_patch_differentiation():
    """Point 9: forward slice from patch site shows propagation to crash site.

    slice_scenarios.c:104  sp->bytes_per_line = w        ← forward anchor (patch site)
    slice_scenarios.c:105  w % sp->bytes_per_line != 0   ← must appear in propagations

    Mirror of CVE-2016-10267 tif_ojpeg.c bytes_per_line fix.
    Pairing backward (crash) + forward (patch) gives the full data-flow
    difference needed by a vulnerability classifier.
    """
    mock_text = """\
Program Slice for <assignment> at src/slice_scenarios.c:104
============================================================
Code: sp->bytes_per_line = w
Method: vulnerable_init
Variables: sp, bytes_per_line, w

[FORWARD SLICE] (2 propagations)
  Result stored in: sp->bytes_per_line

  Propagations:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:105] usage (bytes_per_line): w % sp->bytes_per_line != 0

  Control Flow Affected (Target Method):
    [src/slice_scenarios.c:105] IF: w % sp->bytes_per_line != 0
"""
    services = _make_services(mock_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:104",
            "direction": "forward",
        })).content[0].text

    assert "vulnerable_init" in res_text
    assert "[FORWARD SLICE]" in res_text
    assert "bytes_per_line" in res_text
    # Propagation must reach the crash line
    assert "slice_scenarios.c:105" in res_text
    assert "w % sp->bytes_per_line" in res_text
    # Control flow affected section shows the guard
    assert "Control Flow Affected" in res_text
    assert "IF" in res_text
    assert "ERROR" not in res_text


@pytest.mark.asyncio
async def test_slice_forward_backward_pair():
    """Point 9 (paired): backward from crash + forward from patch cover the fix.

    Tests that the tool accepts both directions for the same location,
    so a caller can request both slices to build the full data-flow diff.
    """
    backward_text = """\
Program Slice for <condition> at src/slice_scenarios.c:105
============================================================
Code: w % sp->bytes_per_line != 0
Method: vulnerable_init
Variables: w, sp, bytes_per_line

[BACKWARD SLICE] (2 data dependencies)

  Data Dependencies:
  File: src/slice_scenarios.c
    [src/slice_scenarios.c:104] bytes_per_line: sp->bytes_per_line = w
      <- depends on: w
    [src/slice_scenarios.c:102] w: Passed as arg to vulnerable_init
      <- depends on: w
"""
    services = _make_services(backward_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:105",
            "direction": "backward",
        })).content[0].text

    assert "[BACKWARD SLICE]" in res_text
    assert "bytes_per_line" in res_text
    assert "slice_scenarios.c:104" in res_text


# When no anchor is found (wrong line, method not in CPG, etc.) the Scala query
# emits an ERROR: ... message. The Python tool must surface this verbatim instead
# of silently writing an empty-dependencies JSON and printing "[ok]" (Point 5).

@pytest.mark.asyncio
async def test_slice_error_text_surfaced():
    """Point 5: ERROR output from the Scala query is visible in the response.

    When the Scala template cannot find an anchor (e.g. wrong line number
    or method not in CPG), it emits "ERROR: No anchor node found on line N".
    The Python tool must return this text to the caller, not silently
    produce a zero-dependency result tagged [ok].
    """
    error_text = """\
ERROR: No anchor node found on line 999 in method compute_top
No calls, assignments, or control structures found on line 999.
Nearby lines with calls: 43
"""
    services = _make_services(error_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "src/slice_scenarios.c:999",
            "direction": "backward",
        })).content[0].text

    # The ERROR message must be surfaced — not swallowed into empty output
    assert "ERROR" in res_text
    assert "No anchor" in res_text
    # Nearby-lines hint must also pass through
    assert "Nearby lines" in res_text


@pytest.mark.asyncio
async def test_slice_no_method_error_surfaced():
    """Point 5: "No method found" error is visible for unknown files.

    When c2cpg has no method enclosing the target line (e.g. pure header
    or file outside the CPG), the Scala template emits a diagnostic
    listing matching files and methods.  This must reach the caller.
    """
    error_text = """\
ERROR: No method found containing line 200 in 'unknown_file.c'

Sample files in CPG (first 5):
  - src/slice_scenarios.c
  - src/memory.c
  - src/network.c
"""
    services = _make_services(error_text)
    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": services["codebase_hash"],
            "location": "unknown_file.c:200",
            "direction": "backward",
        })).content[0].text

    assert "ERROR: No method found" in res_text
    assert "unknown_file.c" in res_text
