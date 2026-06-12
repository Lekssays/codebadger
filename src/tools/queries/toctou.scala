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

  output.append("TOCTOU (Time-of-Check-Time-of-Use) Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Check functions (CWE-367): functions that inspect a path without opening it
  val checkFuncs = Set("access", "stat", "lstat", "fstat", "faccessat", "euidaccess",
    "eaccess", "statx", "access64", "stat64", "lstat64")

  // Use functions: functions that act on a path after a prior check
  val useFuncs = Set("open", "fopen", "freopen", "creat", "openat", "open64", "fopen64",
    "rename", "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "chmod", "chown",
    "lchown", "fchmodat", "fchownat", "execve", "execvp", "execvpe", "execl", "execlp",
    "link", "linkat", "symlink", "symlinkat", "truncate", "truncate64")

  val checkPattern = checkFuncs.mkString("|")
  val usePattern   = useFuncs.mkString("|")

  // Collect all methods that contain at least one check call
  val methodsWithChecks = cpg.call.name(checkPattern).method.dedup.l

  val filteredMethods = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    methodsWithChecks.filter(m => m.file.name.headOption.exists(_.matches(pattern)))
  } else methodsWithChecks

  if (filteredMethods.isEmpty) {
    output.append("No calls to file-check functions (access, stat, lstat, …) found.\n")
  } else {
    output.append(s"Found ${filteredMethods.size} method(s) containing file-check calls. Analyzing for TOCTOU...\n\n")

    // (file, method, checkLine, checkCode, checkPathArg, useLine, useCode, usePathArg)
    val issues = mutable.ListBuffer[(String, String, Int, String, String, Int, String, String)]()

    filteredMethods.foreach { method =>
      val methName = method.name
      val methFile = method.file.name.headOption.getOrElse("unknown")

      // The first argument of a check/use is the path. Carry the argument NODE
      // (not just its code) so we can compare targets by identity, not text.
      val checkCalls = method.call.name(checkPattern).l.flatMap { chk =>
        chk.argument.argumentIndex(1).l.headOption.flatMap { a =>
          val code = a.code.trim
          if (code.nonEmpty) Some((chk, code, a)) else None
        }
      }

      val useCalls = method.call.name(usePattern).l.flatMap { use =>
        use.argument.argumentIndex(1).l.headOption.flatMap { a =>
          val code = a.code.trim
          if (code.nonEmpty) Some((use, code, a)) else None
        }
      }

      // Do two path arguments refer to the SAME target? For two identifiers,
      // require the SAME variable via the REF edge (refsTo) — a textual
      // `usePath.startsWith(chkPath)` flagged `stat(file); open(file2)` (a false
      // positive) and would also conflate same-named variables in different
      // scopes. For string literals / expressions, fall back to exact code match.
      def sameTarget(chkArg: Expression, chkCode: String,
                     useArg: Expression, useCode: String): Boolean = {
        if (chkArg.isInstanceOf[Identifier] && useArg.isInstanceOf[Identifier]) {
          val cr = chkArg.start.collectAll[Identifier].refsTo.id.l.headOption
          val ur = useArg.start.collectAll[Identifier].refsTo.id.l.headOption
          cr.isDefined && cr == ur
        } else {
          chkCode == useCode
        }
      }

      checkCalls.foreach { case (chkCall, chkPath, chkArg) =>
        val chkLine = chkCall.lineNumber.getOrElse(-1)

        useCalls.foreach { case (useCall, usePath, useArg) =>
          val useLine = useCall.lineNumber.getOrElse(-1)

          // Must be: check appears before use on a feasible path (line order heuristic)
          if (chkLine > 0 && useLine > 0 && chkLine < useLine) {
            if (sameTarget(chkArg, chkPath, useArg, usePath)) {
              issues += ((methFile, methName, chkLine, chkCall.code, chkPath,
                          useLine, useCall.code, usePath))
            }
          }
        }
      }
    }

    val dedupIssues = issues.toList.distinct

    if (dedupIssues.isEmpty) {
      output.append("No TOCTOU patterns detected.\n")
      output.append("\nNote: This analysis looks for:\n")
      output.append("  - A call to access()/stat()/lstat() (or similar) followed by open()/fopen()\n")
      output.append("    (or another file-operation call) on the same path argument\n")
      output.append("  - Both calls must appear in the same function\n")
      output.append("  - The check must textually precede the use (line-number order)\n")
    } else {
      output.append(s"Found ${dedupIssues.size} potential TOCTOU issue(s):\n\n")

      dedupIssues.take(maxResults).zipWithIndex.foreach { case ((file, meth, chkLine, chkCode, chkPath, useLine, useCode, usePath), idx) =>
        val chkSnippet = if (chkCode.length > 70) chkCode.take(67) + "..." else chkCode
        val useSnippet = if (useCode.length > 70) useCode.take(67) + "..." else useCode

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence:   HIGH\n")
        output.append(s"CWE:          CWE-367 (Use of Device File in Sensitive Operation)\n")
        output.append(s"Function:     $meth()  [$file]\n")
        output.append(s"Path arg:     $chkPath\n")
        output.append(s"\n  CHECK  [$file:$chkLine]  $chkSnippet\n")
        output.append(s"  USE    [$file:$useLine]  $useSnippet\n")
        output.append(s"\n  Window: ${useLine - chkLine} line(s) between check and use\n")
        output.append(s"  Risk:   An attacker may replace/symlink the file between the check and\n")
        output.append(s"          the subsequent operation, bypassing the access control decision.\n")
        output.append("\n")
      }

      if (dedupIssues.size > maxResults)
        output.append(s"(Showing $maxResults of ${dedupIssues.size} issues. Use limit parameter to see more.)\n\n")

      output.append(s"Total: ${dedupIssues.size} potential TOCTOU issue(s) found\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
