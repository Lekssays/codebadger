{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter  = "{{filename}}"
  val maxResults  = {{limit}}

  val output = new StringBuilder()

  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }

  // Format-string functions and the argument order of their format string.
  // E.g. printf(fmt, ...) → order 1; fprintf(fp, fmt, ...) → order 2.
  val formatFunctions: Map[String, Int] = Map(
    "printf"    -> 1, "vprintf"   -> 1, "wprintf"    -> 1,
    "fprintf"   -> 2, "vfprintf"  -> 2, "dprintf"    -> 2,
    "sprintf"   -> 2, "vsprintf"  -> 2,
    "snprintf"  -> 3, "vsnprintf" -> 3,
    "syslog"    -> 2, "vsyslog"   -> 2,
    "err"       -> 2, "errx"      -> 2,
    "warn"      -> 2, "warnx"     -> 2,
    "asprintf"  -> 2, "vasprintf" -> 2
  )

  val formatPattern = formatFunctions.keys.mkString("|")

  // Known external-input functions for taint confidence boost
  val taintSources = Set(
    "getenv", "fgets", "scanf", "read", "recv", "fread", "gets", "getchar",
    "fscanf", "recvfrom", "recvmsg", "getopt", "getline", "getpass"
  )

  output.append("Format String Vulnerability Analysis\n")
  output.append("=" * 60 + "\n\n")

  val formatCalls = cpg.call.name(formatPattern).l

  val filteredCalls = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    formatCalls.filter(_.file.name.headOption.exists(_.matches(pattern)))
  } else {
    formatCalls
  }

  if (filteredCalls.isEmpty) {
    output.append("No format-string function calls found in the codebase.\n")
  } else {
    output.append(s"Found ${filteredCalls.size} format-string call(s). Analyzing...\n\n")

    // (file, line, code, fmtArgCode, methodName, confidence)
    val issues = mutable.ListBuffer[(String, Int, String, String, String, String)]()

    filteredCalls.foreach { call =>
      val fmtArgOrder = formatFunctions.getOrElse(call.name, 1)
      call.argument.argumentIndex(fmtArgOrder).l.headOption.foreach { fmtArg =>
        // A string literal is safe.  Anything else is suspicious.
        val isLiteral = fmtArg.isInstanceOf[Literal] || {
          val c = fmtArg.code.trim
          c.startsWith("\"") || c.startsWith("L\"") || c.startsWith("u\"") ||
          c.startsWith("U\"") || c.startsWith("u8\"")
        }

        if (!isLiteral) {
          val callFile   = call.file.name.headOption.getOrElse("unknown")
          val callLine   = call.lineNumber.getOrElse(-1)
          val methodName = call.method.name
          val fmtCode    = fmtArg.code.trim
          val method     = call.method

          // Determine confidence:
          // HIGH  — format arg is an identifier that was assigned from a taint source
          //         in the same function before this call.
          // MEDIUM — format arg is a non-literal (variable, call result, parameter).
          val confidence: String = fmtArg match {
            case id: Identifier =>
              val varName = id.name
              // Check if varName was assigned from a taint source before this call
              val assignedFromInput = method.assignment.l.exists { a =>
                val aLine = a.lineNumber.getOrElse(-1)
                aLine > 0 && aLine < callLine && a.target.code.trim == varName &&
                a.source.ast.isCall.l.exists(c => taintSources.contains(c.name))
              }
              // Also check if it is a parameter (passed in from caller — could be tainted)
              val isParam = method.parameter.nameExact(varName).l.nonEmpty
              if (assignedFromInput) "HIGH" else if (isParam) "MEDIUM" else "MEDIUM"
            case _ => "MEDIUM"
          }

          issues += ((callFile, callLine, call.code, fmtCode, methodName, confidence))
        }
      }
    }

    if (issues.isEmpty) {
      output.append("No format string vulnerabilities detected.\n")
      output.append("All format-string calls use string literal format arguments.\n")
    } else {
      val highCount = issues.count(_._6 == "HIGH")
      val medCount  = issues.count(_._6 == "MEDIUM")
      output.append(s"Found ${issues.size} potential format string vulnerability(ies):\n")
      if (highCount > 0) output.append(s"  HIGH confidence:   $highCount\n")
      if (medCount  > 0) output.append(s"  MEDIUM confidence: $medCount\n")
      output.append("\n")

      // Sort HIGH before MEDIUM, then by file:line
      val sorted = issues.toList
        .sortBy(i => (if (i._6 == "HIGH") 0 else 1, i._1, i._2))

      sorted.take(maxResults).zipWithIndex.foreach { case ((file, line, code, fmt, meth, conf), idx) =>
        val snippet = if (code.length > 80) code.take(77) + "..." else code
        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence: $conf\n")
        output.append(s"Location:   $file:$line in $meth()\n")
        output.append(s"Code:       $snippet\n")
        output.append(s"Format Arg: $fmt\n")
        val note = conf match {
          case "HIGH"   => "Format argument is assigned from an external input function."
          case _        => "Format argument is not a string literal — verify it cannot contain user-controlled % directives."
        }
        output.append(s"Note:       $note\n\n")
      }

      if (issues.size > maxResults) {
        output.append(s"(Showing $maxResults of ${issues.size} issues. Use limit parameter to see more.)\n\n")
      }

      output.append(s"Total: ${issues.size} potential format string vulnerability(ies)\n")
      output.append("\nConfidence levels:\n")
      output.append("  HIGH   — format arg assigned directly from a known taint source (getenv, fgets, etc.)\n")
      output.append("  MEDIUM — format arg is a variable or call result; manual review required\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
