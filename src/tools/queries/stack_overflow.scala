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

  /** Check if two line numbers are in mutually exclusive branches of the same IF or SWITCH. */
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

  /** Extract numeric array dimension from a C type like "char [64]" or "int[10]". */
  def parseArraySize(typeName: String): Option[Int] = {
    val m = java.util.regex.Pattern.compile("\\[(\\d+)\\]").matcher(typeName)
    if (m.find()) scala.util.Try(m.group(1).toInt).toOption else None
  }

  output.append("Stack Buffer Overflow Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Write operations: (dst_arg_order, size_arg_order) — size_arg_order=0 means unbounded
  val writeOps: Map[String, (Int, Int)] = Map(
    "memcpy"   -> (1, 3), "memmove"  -> (1, 3), "memset"   -> (1, 3),
    "strncpy"  -> (1, 3), "strncat"  -> (1, 3), "strlcpy"  -> (1, 3),
    "strlcat"  -> (1, 3), "snprintf" -> (1, 2), "vsnprintf"-> (1, 2),
    "read"     -> (2, 3), "recv"     -> (2, 3),
    // Unbounded — always dangerous on a fixed-size stack buffer
    "strcpy"   -> (1, 0), "strcat"   -> (1, 0), "gets"     -> (1, 0),
    "sprintf"  -> (1, 0), "vsprintf" -> (1, 0)
  )
  val writePattern = writeOps.keys.mkString("|")

  // Find all local variables whose type encodes a fixed-size array dimension, e.g. "char [64]"
  val stackArrayLocals = cpg.local.filter(l => l.typeFullName.matches(".*\\[\\d+\\].*")).l
  val filteredLocals = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    stackArrayLocals.filter(l => l.file.name.headOption.exists(_.matches(pattern)))
  } else stackArrayLocals

  if (filteredLocals.isEmpty) {
    output.append("No fixed-size stack array declarations found in the codebase.\n")
  } else {
    output.append(s"Found ${filteredLocals.size} fixed-size stack array(s). Analyzing for overflow...\n\n")

    // (file, declLine, bufName, bufType, arraySize, methodName,
    //  List[(writeLine, writeCode, writeSizeExpr, writeOp, overflowReason)])
    val issues = mutable.ListBuffer[(String, Int, String, String, Int, String, List[(Int, String, String, String, String)])]()

    filteredLocals.foreach { local =>
      val localName = local.name
      val localType = local.typeFullName
      parseArraySize(localType).foreach { arraySize =>
        val mOpt = local.method.l.headOption
        if (mOpt.isDefined) {
          val m        = mOpt.get
          val methName = m.name
          val declFile = local.file.name.headOption.getOrElse("unknown")
          val declLine = local.lineNumber.getOrElse(-1)

          val overflowUsages = mutable.ListBuffer[(Int, String, String, String, String)]()

          m.call.name(writePattern).l.foreach { writeCall =>
            val writeLine = writeCall.lineNumber.getOrElse(-1)
            val (dstOrder, sizeOrder) = writeOps.getOrElse(writeCall.name, (1, 0))
            val dstCode = writeCall.argument.argumentIndex(dstOrder).l.headOption.map(_.code.trim).getOrElse("")

            val bufIsArg = dstCode == localName ||
              dstCode.startsWith(localName + "[") ||
              dstCode.startsWith(localName + "+") ||
              dstCode.startsWith("&" + localName)

            if (bufIsArg) {
              val inDiffBranch = declLine > 0 && areInMutuallyExclusiveBranches(m, declLine, writeLine)

              if (!inDiffBranch) {
                val writeSizeExpr = if (sizeOrder > 0)
                  writeCall.argument.argumentIndex(sizeOrder).l.headOption.map(_.code.trim).getOrElse("?")
                else
                  "(unbounded)"

                val reason: Option[String] = if (sizeOrder == 0) {
                  Some(s"Unbounded write (${writeCall.name}) to fixed-size stack buffer [$arraySize]")
                } else {
                  scala.util.Try(writeSizeExpr.trim.toLong).toOption match {
                    case Some(wSize) if wSize > arraySize =>
                      Some(s"Write size $wSize exceeds stack buffer size $arraySize")
                    case Some(_) =>
                      None
                    case None =>
                      val arraySizeStr = arraySize.toString
                      val sizeMatch = writeSizeExpr == arraySizeStr ||
                        writeSizeExpr.matches(s".*\\b${java.util.regex.Pattern.quote(arraySizeStr)}\\b.*") ||
                        writeSizeExpr.contains("sizeof")
                      if (!sizeMatch) {
                        val writeSizeVar = writeSizeExpr.replaceAll("[^a-zA-Z0-9_].*", "").trim
                        val hasBoundsCheck = writeSizeVar.nonEmpty && m.controlStructure
                          .filter(_.controlStructureType == "IF").l.exists { ifStmt =>
                            val condLine = ifStmt.lineNumber.getOrElse(-1)
                            condLine >= declLine && condLine < writeLine && {
                              val condCode = ifStmt.condition.code.headOption.getOrElse("")
                              condCode.matches(s".*\\b${java.util.regex.Pattern.quote(writeSizeVar)}\\b.*") &&
                              (condCode.contains("<") || condCode.contains(">") ||
                               condCode.contains("<=") || condCode.contains(">="))
                            }
                          }
                        if (!hasBoundsCheck)
                          Some(s"Write size '$writeSizeExpr' not statically bounded by stack buffer size $arraySize")
                        else None
                      } else None
                  }
                }

                reason.foreach { r =>
                  overflowUsages += ((writeLine, writeCall.code, writeSizeExpr, writeCall.name, r))
                }
              }
            }
          }

          if (overflowUsages.nonEmpty) {
            issues += ((declFile, declLine, localName, localType, arraySize, methName,
              overflowUsages.toList.distinct.sortBy(_._1)))
          }
        }
      }
    }

    if (issues.isEmpty) {
      output.append("No potential stack buffer overflow issues detected.\n")
      output.append("\nNote: This analysis looks for:\n")
      output.append("  - Unbounded writes (strcpy, gets, sprintf) to fixed-size stack arrays\n")
      output.append("  - Bounded writes (memcpy, strncpy, snprintf) where the size argument\n")
      output.append("    exceeds or is not statically bounded by the declared array dimension\n")
      output.append("\nFiltered out:\n")
      output.append("  - Bounded writes with a literal size <= array dimension\n")
      output.append("  - Write sizes containing sizeof or matching the array dimension constant\n")
      output.append("  - Writes guarded by a preceding bounds-check (if comparison)\n")
      output.append("  - Writes in mutually exclusive branches from the declaration\n")
    } else {
      output.append(s"Found ${issues.size} potential stack buffer overflow issue(s):\n\n")

      issues.take(maxResults).zipWithIndex.foreach { case ((file, declLine, buf, bufType, arraySize, meth, writes), idx) =>
        val confidence = if (writes.exists(w => Set("strcpy", "gets", "sprintf", "vsprintf", "strcat").contains(w._4)))
          "HIGH" else "MEDIUM"

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence:    $confidence\n")
        output.append(s"Stack Buffer:  $buf ($bufType)\n")
        output.append(s"  Location:    $file:$declLine in $meth()\n")
        output.append(s"  Array Size:  $arraySize\n")
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

      output.append(s"Total: ${issues.size} potential stack buffer overflow issue(s) found\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
