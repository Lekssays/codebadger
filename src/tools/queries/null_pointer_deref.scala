{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  output.append("Null Pointer Dereference Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Allocation functions that can return NULL
  val allocFunctions = "malloc|calloc|realloc|strdup|strndup|aligned_alloc|reallocarray|fopen|fdopen|freopen|tmpfile|popen|dlopen|mmap|xmlMalloc|xmlMallocAtomic|xmlRealloc|xmlStrdup|xmlStrndup|xmlCharStrdup|xmlCharStrndup"

  // Safe wrapper allocators that guarantee non-NULL (abort on failure)
  val safeWrappers = Set(
    "xmalloc", "xcalloc", "xrealloc", "xstrdup", "xstrndup",
    "g_malloc", "g_malloc0", "g_new", "g_new0", "g_strdup", "g_strndup",
    "emalloc", "ecalloc", "erealloc", "estrdup"
  )

  // Find all allocation calls
  val allocCalls = cpg.call.name(allocFunctions).l

  val allocCallsFiltered = if (fileFilter.nonEmpty) {
    allocCalls.filter(_.file.name.headOption.exists(f => f.contains(fileFilter) || f.endsWith(fileFilter)))
  } else {
    allocCalls
  }

  if (allocCallsFiltered.isEmpty) {
    output.append("No allocation calls found in the codebase.\n")
  } else {
    output.append(s"Found ${allocCallsFiltered.size} allocation site(s). Analyzing for unchecked null dereferences...\n\n")

    // Store null pointer dereference issues
    // (file, allocLine, allocCode, assignedPtr, methodName, List[(derefLine, derefCode, derefType)])
    val npIssues = mutable.ListBuffer[(String, Int, String, String, String, List[(Int, String, String)])]()

    allocCallsFiltered.foreach { allocCall =>
      val allocFile = allocCall.file.name.headOption.getOrElse("unknown")
      val allocLine = allocCall.lineNumber.getOrElse(-1)
      val allocCode = allocCall.code
      val method = allocCall.method
      val methodName = method.name

      // Skip safe wrapper allocators
      if (!safeWrappers.contains(allocCall.name)) {

        // === PHASE 1: Find the assigned pointer variable ===
        // Look for assignment: ptr = malloc(...) on the same line
        val assignmentOpt = method.assignment.l.find { assign =>
          val assignLine = assign.lineNumber.getOrElse(-1)
          assignLine == allocLine && assign.source.code.contains(allocCall.name)
        }

        assignmentOpt.foreach { assignment =>
          val assignedPtr = assignment.target.code.trim

          // Only track simple variable names (skip complex expressions)
          if (!assignedPtr.contains("(") && !assignedPtr.contains("[") && assignedPtr.length < 50 && assignedPtr.nonEmpty) {

            // === PHASE 2: Find dereferences of the pointer after allocation ===
            val dereferences = mutable.ListBuffer[(Int, String, String)]()

            // Find ptr->field (indirectMemberAccess)
            method.call.name("<operator>.indirectMemberAccess").l.foreach { deref =>
              val derefLine = deref.lineNumber.getOrElse(-1)
              if (derefLine > allocLine) {
                val baseObj = deref.argument.l.headOption.map(_.code.trim).getOrElse("")
                if (baseObj == assignedPtr) {
                  dereferences += ((derefLine, deref.code, "member_access"))
                }
              }
            }

            // Find *ptr (indirection)
            method.call.name("<operator>.indirection").l.foreach { deref =>
              val derefLine = deref.lineNumber.getOrElse(-1)
              if (derefLine > allocLine) {
                val argCode = deref.argument.l.headOption.map(_.code.trim).getOrElse("")
                if (argCode == assignedPtr) {
                  dereferences += ((derefLine, deref.code, "pointer_deref"))
                }
              }
            }

            // Find ptr[i] (indirectIndexAccess)
            method.call.name("<operator>.indirectIndexAccess").l.foreach { deref =>
              val derefLine = deref.lineNumber.getOrElse(-1)
              if (derefLine > allocLine) {
                val baseObj = deref.argument.l.headOption.map(_.code.trim).getOrElse("")
                if (baseObj == assignedPtr) {
                  dereferences += ((derefLine, deref.code, "index_access"))
                }
              }
            }

            // Find calls where pointer is passed as argument
            method.call.l.foreach { call =>
              val callLine = call.lineNumber.getOrElse(-1)
              if (callLine > allocLine &&
                  !call.name.startsWith("<operator>") &&
                  !call.name.matches("free|cfree|g_free|sizeof|typeof|__builtin_.*|assert|__assert_fail|exit|abort|_exit")) {
                val argsContainPtr = call.argument.code.l.exists { argCode =>
                  argCode == assignedPtr ||
                  argCode.startsWith(assignedPtr + "->") ||
                  argCode.startsWith(assignedPtr + "[") ||
                  argCode.startsWith("*" + assignedPtr)
                }
                if (argsContainPtr) {
                  dereferences += ((callLine, call.code, "passed_to_func"))
                }
              }
            }

            if (dereferences.nonEmpty) {
              // === PHASE 3: False positive filtering ===

              // Track reassignments of the pointer after allocation
              val reassignmentLines = mutable.Set[Int]()
              method.assignment.l.foreach { assign =>
                val assignLine = assign.lineNumber.getOrElse(-1)
                if (assignLine > allocLine && assign.target.code.trim == assignedPtr) {
                  reassignmentLines += assignLine
                }
              }

              // Find null checks on the pointer via IF control structures
              val nullCheckLines = mutable.Set[Int]()
              val quotedPtr = java.util.regex.Pattern.quote(assignedPtr)

              method.controlStructure.filter(_.controlStructureType == "IF").l.foreach { ifStmt =>
                val condLine = ifStmt.lineNumber.getOrElse(-1)
                if (condLine > allocLine) {
                  // Check condition code for null-testing patterns
                  val condCalls = ifStmt.condition.isCall.l
                  condCalls.foreach { cond =>
                    val condCode = cond.code
                    val checksPtr = condCode.contains(assignedPtr) && (
                      condCode.contains("NULL") ||
                      condCode.contains("null") ||
                      condCode.matches(s".*\\b${quotedPtr}\\s*==\\s*0\\b.*") ||
                      condCode.matches(s".*\\b0\\s*==\\s*${quotedPtr}\\b.*") ||
                      condCode.matches(s".*\\b${quotedPtr}\\s*!=\\s*NULL\\b.*") ||
                      condCode.matches(s".*\\bNULL\\s*!=\\s*${quotedPtr}\\b.*") ||
                      condCode.matches(s".*\\b${quotedPtr}\\s*==\\s*NULL\\b.*") ||
                      condCode.matches(s".*\\bNULL\\s*==\\s*${quotedPtr}\\b.*") ||
                      condCode.matches(s".*!\\s*${quotedPtr}\\b.*") ||
                      condCode == assignedPtr ||
                      condCode == s"!$assignedPtr"
                    )
                    if (checksPtr) {
                      nullCheckLines += condLine
                    }
                  }
                  // Also check the condition AST for identifiers matching the pointer
                  // This catches cases like: if(ptr) or if(!ptr)
                  val condIds = ifStmt.condition.ast.isIdentifier.name(assignedPtr).l
                  if (condIds.nonEmpty) {
                    nullCheckLines += condLine
                  }
                }
              }

              // Find early exits (return/exit/abort) after allocation
              val earlyExitLines = mutable.Set[Int]()
              method.call.name("return").l.foreach { ret =>
                val retLine = ret.lineNumber.getOrElse(-1)
                if (retLine > allocLine) earlyExitLines += retLine
              }
              method.call.name("exit|abort|_exit|__assert_fail").l.foreach { exitCall =>
                val exitLine = exitCall.lineNumber.getOrElse(-1)
                if (exitLine > allocLine) earlyExitLines += exitLine
              }

              // Filter dereferences: keep only truly unguarded ones
              val unguardedDerefs = dereferences.toList.filter { case (derefLine, _, _) =>
                // Skip if pointer was reassigned between alloc and deref
                val reassignedBefore = reassignmentLines.exists(rl => rl > allocLine && rl < derefLine)

                // Skip if there's a null check between alloc and deref
                val hasNullCheckBefore = nullCheckLines.exists(ncLine => ncLine > allocLine && ncLine <= derefLine)

                // Skip if there's an early exit between alloc and deref
                // (suggests an error-handling path like: if(!ptr) return;)
                val hasEarlyExit = earlyExitLines.exists(el => el > allocLine && el < derefLine)

                !reassignedBefore && !hasNullCheckBefore && !hasEarlyExit
              }.distinct.sortBy(_._1)

              if (unguardedDerefs.nonEmpty) {
                npIssues += ((allocFile, allocLine, allocCode, assignedPtr, methodName, unguardedDerefs))
              }
            }
          }
        }
      }
    }

    if (npIssues.isEmpty) {
      output.append("No potential Null Pointer Dereference issues detected.\n")
      output.append("\nNote: This analysis checks for:\n")
      output.append("  - Unchecked malloc/calloc/realloc return values\n")
      output.append("  - Unchecked fopen/strdup/mmap return values\n")
      output.append("  - Dereferences without prior NULL checks\n")
      output.append("\nFiltered out:\n")
      output.append("  - Dereferences guarded by if(ptr != NULL) checks\n")
      output.append("  - Dereferences after early return/exit on NULL\n")
      output.append("  - Pointer reassignments between allocation and use\n")
      output.append("  - Safe wrapper allocators (xmalloc, g_malloc, etc.)\n")
    } else {
      output.append(s"Found ${npIssues.size} potential null pointer dereference issue(s):\n\n")

      npIssues.take(maxResults).zipWithIndex.foreach { case ((file, line, code, ptr, methodName, derefs), idx) =>
        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Allocation Site: $code\n")
        output.append(s"  Location: $file:$line in $methodName()\n")
        output.append(s"  Assigned To: $ptr\n")
        output.append("\nUnchecked Dereference(s):\n")

        derefs.take(10).foreach { case (derefLine, derefCode, derefType) =>
          val codeSnippet = if (derefCode.length > 60) derefCode.take(57) + "..." else derefCode
          val typeTag = derefType match {
            case "member_access" => ""
            case "pointer_deref" => " [DEREF]"
            case "index_access" => " [INDEX]"
            case "passed_to_func" => " [FUNC-ARG]"
            case _ => ""
          }
          output.append(s"  [$file:$derefLine] $codeSnippet$typeTag\n")
        }

        if (derefs.size > 10) {
          output.append(s"  ... and ${derefs.size - 10} more dereference(s)\n")
        }

        output.append("\n")
      }

      if (npIssues.size > maxResults) {
        output.append(s"(Showing $maxResults of ${npIssues.size} issues. Increase limit to see more.)\n\n")
      }

      output.append(s"Total: ${npIssues.size} potential null pointer dereference issue(s) found\n")
      output.append("\nDereference Types:\n")
      output.append("  - (no tag): Member access via ->\n")
      output.append("  - [DEREF]: Explicit pointer dereference via *\n")
      output.append("  - [INDEX]: Array-style access via []\n")
      output.append("  - [FUNC-ARG]: Pointer passed to function (potential dereference inside)\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
