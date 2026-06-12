{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }

  /** Parse a size expression as an integer constant (decimal or 0x hex, with an
    * optional u/l suffix), or None if it isn't a plain integer literal. Lets the
    * overflow check compare constant sizes by value instead of by text. */
  def parseIntLit(s: String): Option[Long] = {
    val t = s.trim.replaceAll("[uUlL]+$", "")
    try {
      if (t.startsWith("0x") || t.startsWith("0X")) Some(java.lang.Long.parseLong(t.substring(2), 16))
      else if (t.nonEmpty && t.forall(_.isDigit)) Some(t.toLong)
      else None
    } catch { case _: Throwable => None }
  }

  /** Check if two line numbers are in mutually exclusive branches of the same IF. */
  def areInMutuallyExclusiveBranches(method: Method, lineA: Int, lineB: Int): Boolean = {
    method.ast.isControlStructure.l.exists { cs =>
      cs.controlStructureType match {
        case "IF" =>
          val children = cs.astChildren.l
          if (children.size >= 3) {
            val thenLines = children(1).ast.lineNumber.l.toSet
            val elseLines = children(2).ast.lineNumber.l.toSet
            (thenLines.contains(lineA) && elseLines.contains(lineB)) ||
            (elseLines.contains(lineA) && thenLines.contains(lineB))
          } else false
        case "SWITCH" =>
          val switchLines = cs.ast.lineNumber.l.toSet
          if (switchLines.contains(lineA) && switchLines.contains(lineB)) {
            val caseLabels = cs.ast.filter(_.label == "JUMP_TARGET").lineNumber.l.sorted
            if (caseLabels.size >= 2) {
              def caseSegmentOf(line: Int): Int = caseLabels.lastIndexWhere(_ <= line)
              val segA = caseSegmentOf(lineA)
              val segB = caseSegmentOf(lineB)
              segA >= 0 && segB >= 0 && segA != segB
            } else false
          } else false
        case _ => false
      }
    }
  }

  output.append("Heap Overflow Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Allocation functions that return a heap pointer of a known size.
  // calloc is excluded: its size is count * element_size (handled differently).
  val allocPattern = "malloc|calloc|realloc|aligned_alloc|reallocarray|valloc|pvalloc|memalign|posix_memalign|strdup|strndup"

  // Write operations and their (dst_arg_order, size_arg_order) — size_arg_order=0 means unbounded
  val writeOps: Map[String, (Int, Int)] = Map(
    "memcpy"  -> (1, 3),  "memmove"  -> (1, 3),  "memset"   -> (1, 3),
    "strncpy" -> (1, 3),  "strncat"  -> (1, 3),  "strlcpy"  -> (1, 3),
    "strlcat" -> (1, 3),  "snprintf" -> (1, 2),  "vsnprintf"-> (1, 2),
    // Unbounded — always dangerous if dst is heap-allocated
    "strcpy"  -> (1, 0),  "strcat"   -> (1, 0),  "gets"     -> (1, 0),
    "sprintf" -> (1, 0),  "vsprintf" -> (1, 0),
    // read/recv: dst=2, size=3
    "read"    -> (2, 3),  "recv"     -> (2, 3),  "fread"    -> (2, 0),
    "recvfrom"-> (2, 3)
  )
  val writePattern = writeOps.keys.mkString("|")

  val sizeInSecondArg = Set("realloc", "reallocarray", "aligned_alloc", "memalign", "posix_memalign")

  val allocCalls = cpg.call.name(allocPattern).l
  val filteredAllocs = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    allocCalls.filter(_.file.name.headOption.exists(_.matches(pattern)))
  } else allocCalls

  if (filteredAllocs.isEmpty) {
    output.append("No heap allocation calls found in the codebase.\n")
  } else {
    output.append(s"Found ${filteredAllocs.size} allocation site(s). Analyzing for heap overflow...\n\n")

    // (file, allocLine, allocCode, bufVar, allocSizeExpr, methodName,
    //  List[(writeLine, writeCode, writeSizeExpr, writeOp, overflowReason)])
    val issues = mutable.ListBuffer[(String, Int, String, String, String, String, List[(Int, String, String, String, String)])]()

    filteredAllocs.foreach { allocCall =>
      val allocFile   = allocCall.file.name.headOption.getOrElse("unknown")
      val allocLine   = allocCall.lineNumber.getOrElse(-1)
      val method      = allocCall.method
      val methodName  = method.name

      // Find the variable receiving this allocation
      val assignOpt = method.assignment.l.find { a =>
        val al = a.lineNumber.getOrElse(-1)
        al == allocLine && a.source.ast.isCall.name(allocCall.name).nonEmpty
      }

      assignOpt.foreach { assign =>
        val bufVar      = assign.target.code.trim
        if (!bufVar.contains("(") && !bufVar.contains("[") && bufVar.length < 50 && bufVar.nonEmpty) {

          val sizeArgOrder = if (sizeInSecondArg.contains(allocCall.name)) 2 else 1
          val allocSizeExpr = allocCall.argument.argumentIndex(sizeArgOrder).l.headOption.map(_.code).getOrElse("?")

          // Track reassignments of the buffer after allocation
          val reassignLines = mutable.Set[Int]()
          method.assignment.l.foreach { a =>
            val al = a.lineNumber.getOrElse(-1)
            if (al > allocLine && a.target.code.trim == bufVar) reassignLines += al
          }

          val overflowUsages = mutable.ListBuffer[(Int, String, String, String, String)]()

          // Find write operations that use bufVar as destination
          method.call.name(writePattern).l.foreach { writeCall =>
            val writeLine = writeCall.lineNumber.getOrElse(-1)
            if (writeLine > allocLine) {
              val (dstOrder, sizeOrder) = writeOps.getOrElse(writeCall.name, (1, 0))
              val dstCode = writeCall.argument.argumentIndex(dstOrder).l.headOption.map(_.code.trim).getOrElse("")

              val bufIsArg = dstCode == bufVar ||
                dstCode.startsWith(bufVar + "[") ||
                dstCode.startsWith(bufVar + "+") ||
                dstCode.startsWith("&" + bufVar)

              if (bufIsArg) {
                // Skip if buffer was reassigned between alloc and write
                val reassigned = reassignLines.exists(rl => rl > allocLine && rl < writeLine)
                val inDiffBranch = areInMutuallyExclusiveBranches(method, allocLine, writeLine)

                if (!reassigned && !inDiffBranch) {
                  val writeSizeExpr = if (sizeOrder > 0)
                    writeCall.argument.argumentIndex(sizeOrder).l.headOption.map(_.code.trim).getOrElse("?")
                  else
                    "(unbounded)"

                  // Classify overflow risk:
                  val reason: Option[String] = if (sizeOrder == 0) {
                    // Unbounded write — always risky (strcpy, gets, sprintf, etc.)
                    Some(s"Unbounded write (${writeCall.name}) — no size limit enforced")
                  } else if (parseIntLit(writeSizeExpr).isDefined && parseIntLit(allocSizeExpr).isDefined) {
                    // Both sizes are integer constants — compare by VALUE, not text.
                    // The old string test reported `malloc(64); memcpy(.., 16)` as an
                    // overflow (16 != "64" and "64" doesn't contain "16") even though
                    // 16 < 64 is safe, and couldn't affirm `malloc(16); memcpy(.., 32)`
                    // as a definite overflow. A numeric compare does both precisely.
                    val w = parseIntLit(writeSizeExpr).get
                    val a = parseIntLit(allocSizeExpr).get
                    if (w > a) Some(s"Write size $w exceeds allocation size $a")
                    else None
                  } else {
                    // Size-bounded write: flag if write size expression is NOT the same
                    // as allocation size and there is no obvious bounds check in between.
                    val sizeMatch = writeSizeExpr == allocSizeExpr || allocSizeExpr.contains(writeSizeExpr)
                    if (!sizeMatch) {
                      // Check for a bounds check (comparison involving the write size var)
                      val writeSizeVar = writeSizeExpr.replaceAll("[^a-zA-Z0-9_].*", "").trim
                      val hasBoundsCheck = writeSizeVar.nonEmpty && method.controlStructure
                        .filter(_.controlStructureType == "IF").l.exists { ifStmt =>
                          val condLine = ifStmt.lineNumber.getOrElse(-1)
                          condLine > allocLine && condLine < writeLine && {
                            val condCode = ifStmt.condition.code.headOption.getOrElse("")
                            condCode.matches(s".*\\b${java.util.regex.Pattern.quote(writeSizeVar)}\\b.*") && (condCode.contains("<") || condCode.contains(">") || condCode.contains("<=") || condCode.contains(">="))
                          }
                        }
                      if (!hasBoundsCheck)
                        Some(s"Write size '$writeSizeExpr' not bounded by allocation size '$allocSizeExpr'")
                      else None
                    } else None
                  }

                  reason.foreach { r =>
                    overflowUsages += ((writeLine, writeCall.code, writeSizeExpr, writeCall.name, r))
                  }
                }
              }
            }
          }

          if (overflowUsages.nonEmpty) {
            issues += ((allocFile, allocLine, allocCall.code, bufVar, allocSizeExpr, methodName,
              overflowUsages.toList.distinct.sortBy(_._1)))
          }
        }
      }
    }

    if (issues.isEmpty) {
      output.append("No potential heap overflow issues detected.\n")
      output.append("\nNote: This analysis looks for:\n")
      output.append("  - Unbounded writes (strcpy, gets, sprintf) to heap-allocated buffers\n")
      output.append("  - Sized writes (memcpy, read, recv) where the write size is not\n")
      output.append("    bounded by or equal to the allocation size\n")
      output.append("\nFiltered out:\n")
      output.append("  - Writes guarded by a bounds check before the write\n")
      output.append("  - Writes where the size expression matches the allocation size\n")
      output.append("  - Buffer reassignments between allocation and write\n")
      output.append("  - Writes in mutually exclusive branches from the allocation\n")
    } else {
      output.append(s"Found ${issues.size} potential heap overflow issue(s):\n\n")

      issues.take(maxResults).zipWithIndex.foreach { case ((file, allocLine, allocCode, buf, allocSize, meth, writes), idx) =>
        val confidence = if (writes.exists(_._4 == "strcpy") || writes.exists(_._4 == "gets") || writes.exists(_._4 == "sprintf"))
          "HIGH" else "MEDIUM"

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence:      $confidence\n")
        output.append(s"Allocation Site: $allocCode\n")
        output.append(s"  Location:      $file:$allocLine in $meth()\n")
        output.append(s"  Buffer:        $buf (size: $allocSize)\n")
        output.append(s"\nDangerous Write(s):\n")

        writes.take(10).foreach { case (wLine, wCode, wSize, wOp, reason) =>
          val snippet = if (wCode.length > 70) wCode.take(67) + "..." else wCode
          output.append(s"  [$file:$wLine] $snippet\n")
          output.append(s"    Write size: $wSize  |  Reason: $reason\n")
        }

        if (writes.size > 10)
          output.append(s"  ... and ${writes.size - 10} more write(s)\n")

        output.append("\n")
      }

      if (issues.size > maxResults)
        output.append(s"(Showing $maxResults of ${issues.size} issues. Use limit parameter to see more.)\n\n")

      output.append(s"Total: ${issues.size} potential heap overflow issue(s) found\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
