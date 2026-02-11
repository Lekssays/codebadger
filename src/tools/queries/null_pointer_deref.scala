{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  /** Check if two line numbers are in mutually exclusive branches of the same IF.
    * Returns true if lineA is inside the THEN block and lineB inside ELSE (or vice versa),
    * meaning they cannot both execute in the same control flow path.
    */
  def areInMutuallyExclusiveBranches(method: Method, lineA: Int, lineB: Int): Boolean = {
    method.controlStructure.filter(_.controlStructureType == "IF").l.exists { ifStmt =>
      val children = ifStmt.astChildren.l
      if (children.size >= 3) {
        val thenLines = children(1).ast.lineNumber.l
        val elseLines = children(2).ast.lineNumber.l
        (thenLines.contains(lineA) && elseLines.contains(lineB)) ||
        (elseLines.contains(lineA) && thenLines.contains(lineB))
      } else false
    }
  }

  // Known external input functions for reachability analysis
  val externalInputFunctions = Set(
    "getenv", "fgets", "scanf", "read", "recv", "fread", "gets", "getchar",
    "fscanf", "recvfrom", "recvmsg", "getopt", "fopen", "getline",
    "getaddrinfo", "gethostbyname", "accept", "socket", "getpass",
    "realpath", "popen", "fdopen", "tmpfile", "dlopen"
  )

  /** Check if a method is transitively reachable from external input.
    * BFS-walks callers up to maxDepth levels.
    */
  def findEntryPoint(methodName: String, maxDepth: Int = 10): Option[String] = {
    var visited = Set[String]()
    var frontier = List(methodName)
    var depth = 0

    while (depth < maxDepth && frontier.nonEmpty) {
      val nextFrontier = mutable.ListBuffer[String]()
      frontier.foreach { current =>
        if (!visited.contains(current)) {
          visited += current
          val hasExtInput = cpg.method.name(current).l.exists { m =>
            m.call.l.exists(c => externalInputFunctions.contains(c.name))
          }
          if (hasExtInput) return Some(current)
          val callers = cpg.method.name(current).l
            .flatMap(_.callIn.l)
            .map(_.method.name)
            .distinct
            .filterNot(visited.contains)
          nextFrontier ++= callers
        }
      }
      frontier = nextFrontier.toList
      depth += 1
    }
    None
  }

  output.append("Null Pointer Dereference Analysis (Deep Interprocedural)\n")
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
    output.append(s"Found ${allocCallsFiltered.size} allocation site(s). Analyzing with deep interprocedural flow...\n\n")

    // Store null pointer dereference issues
    // (file, allocLine, allocCode, assignedPtr, methodName, List[(derefLine, derefCode, derefType, derefFile, derefMethod)])
    val npIssues = mutable.ListBuffer[(String, Int, String, String, String, List[(Int, String, String, String, String)])]()

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

          // Only track simple variable names (skip complex expressions and dereferences)
          if (!assignedPtr.contains("(") && !assignedPtr.contains("[") && !assignedPtr.startsWith("*") && !assignedPtr.startsWith("&") && assignedPtr.length < 50 && assignedPtr.nonEmpty) {

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

            // Dedup dereferences: one per line, prefer direct deref over func-arg
            val derefPriority = Map("member_access" -> 0, "pointer_deref" -> 1, "index_access" -> 2, "passed_to_func" -> 3)
            val dedupedDereferences = dereferences.toList
              .sortBy(d => derefPriority.getOrElse(d._3, 3))
              .groupBy(_._1)  // group by line
              .values.map(_.head).toList  // keep first (highest priority) per line

            // === PHASE 3: False positive filtering ===

            // Track reassignments of the pointer after allocation
            val reassignmentLines = mutable.Set[Int]()
            method.assignment.l.foreach { assign =>
              val assignLine = assign.lineNumber.getOrElse(-1)
              if (assignLine > allocLine && assign.target.code.trim == assignedPtr) {
                reassignmentLines += assignLine
              }
            }

            // Find null checks on the pointer via semantic AST analysis of IF conditions
            val nullCheckLines = mutable.Set[Int]()
            val quotedPtr = java.util.regex.Pattern.quote(assignedPtr)

            method.controlStructure.filter(_.controlStructureType == "IF").l.foreach { ifStmt =>
              val condLine = ifStmt.lineNumber.getOrElse(-1)
              if (condLine > allocLine) {
                val condAst = ifStmt.condition.ast

                // Semantic check 1: ptr == NULL / ptr != NULL / ptr == 0 / 0 == ptr / ptr == nullptr
                val hasEqualityNullCheck = condAst.isCall
                  .name("<operator>.equals|<operator>.notEquals").l.exists { cmp =>
                    val argCodes = cmp.argument.code.l.map(_.trim)
                    val hasPtr = argCodes.contains(assignedPtr)
                    val hasNull = argCodes.exists(c =>
                      c == "NULL" || c == "0" || c == "nullptr" || c == "((void *)0)" || c == "((void*)0)"
                    )
                    hasPtr && hasNull
                  }

                // Semantic check 2: !ptr (logicalNot applied to the pointer)
                val hasLogicalNotCheck = condAst.isCall
                  .name("<operator>.logicalNot").l.exists { notOp =>
                    notOp.argument.isIdentifier.name(quotedPtr).l.nonEmpty
                  }

                // Semantic check 3: if(ptr) — pointer used directly as boolean condition
                val hasImplicitBoolCheck = ifStmt.condition.isIdentifier.name(quotedPtr).l.nonEmpty

                // Semantic check 4: ptr as operand of && or || (implicit truthiness check in compound condition)
                // e.g., if (ptr && ptr->field > 0) or if (!ptr || error)
                val hasCompoundBoolCheck = condAst.isCall
                  .name("<operator>.logicalAnd|<operator>.logicalOr").l.exists { logOp =>
                    logOp.argument.isIdentifier.name(quotedPtr).l.nonEmpty
                  }

                if (hasEqualityNullCheck || hasLogicalNotCheck || hasImplicitBoolCheck || hasCompoundBoolCheck) {
                  nullCheckLines += condLine
                }
              }
            }

            // Find early exits (return/exit/abort) after allocation
            // Note: return statements are Return nodes in Joern's CPG, not Call nodes
            val earlyExitLines = mutable.Set[Int]()
            method.ast.isReturn.l.foreach { ret =>
              val retLine = ret.lineNumber.getOrElse(-1)
              if (retLine > allocLine) earlyExitLines += retLine
            }
            method.call.name("exit|abort|_exit|__assert_fail").l.foreach { exitCall =>
              val exitLine = exitCall.lineNumber.getOrElse(-1)
              if (exitLine > allocLine) earlyExitLines += exitLine
            }

            // Filter intraprocedural dereferences: keep only truly unguarded ones
            val unguardedDerefs = if (dedupedDereferences.nonEmpty) {
              dedupedDereferences.filter { case (derefLine, _, _) =>
                // Skip if pointer was reassigned between alloc and deref
                val reassignedBefore = reassignmentLines.exists(rl => rl > allocLine && rl < derefLine)

                // Skip if there's a null check between alloc and deref
                val hasNullCheckBefore = nullCheckLines.exists(ncLine => ncLine > allocLine && ncLine <= derefLine)

                // Skip if there's an early exit between alloc and deref
                // (suggests an error-handling path like: if(!ptr) return;)
                val hasEarlyExit = earlyExitLines.exists(el => el > allocLine && el < derefLine)

                // Also check if alloc and deref are in mutually exclusive branches
                val inDifferentBranches = areInMutuallyExclusiveBranches(method, allocLine, derefLine)

                !reassignedBefore && !hasNullCheckBefore && !hasEarlyExit && !inDifferentBranches
              }.distinct.sortBy(_._1)
                .map { case (line, code, dtype) => (line, code, dtype, "", "") }
            } else {
              List.empty[(Int, String, String, String, String)]
            }

            // === PHASE 4: Deep Interprocedural Flow using reachableByFlows ===
            // Track the allocated pointer across function call boundaries.
            // Detects: ptr = malloc(...); process(ptr); where process() dereferences without NULL check.
            val interprocDerefs = mutable.ListBuffer[(Int, String, String, String, String)]()

            // Get the pointer identifier nodes after allocation as sources for interprocedural flow.
            // Include all occurrences (not just first N) so we don't miss flows through later call sites.
            val ptrNodes = method.ast.isIdentifier.name(quotedPtr).l
              .filter(_.lineNumber.getOrElse(-1) >= allocLine)
              .collect { case cfgNode: CfgNode => cfgNode }

            if (ptrNodes.nonEmpty) {
              // Find dereference operations in OTHER methods as potential sinks
              val derefOpPattern = "<operator>.indirectMemberAccess|<operator>.indirection|<operator>.indirectIndexAccess"
              val crossFuncDerefSinks = cpg.call.name(derefOpPattern).l
                .filter { deref =>
                  val dm = deref.method.name
                  val df = deref.file.name.headOption.getOrElse("")
                  dm != methodName || df != allocFile
                }
                .take(200)
                .collect { case cfgNode: CfgNode => cfgNode }

              if (crossFuncDerefSinks.nonEmpty) {
                try {
                  val flows = crossFuncDerefSinks.reachableByFlows(ptrNodes).l.take(10)

                  flows.foreach { flow =>
                    val elements = flow.elements.l
                    if (elements.size > 1) {
                      val sink = elements.last
                      val sinkLine = sink.lineNumber.getOrElse(-1)
                      val sinkFile = sink.file.name.headOption.getOrElse("?")
                      val sinkMethod = sink match {
                        case c: Call => c.method.name
                        case i: Identifier => i.method.name
                        case _ => "?"
                      }

                      // Only process cross-function flows
                      if (sinkMethod != methodName || sinkFile != allocFile) {
                        // Check if the current method has a null guard before the flow exits
                        val flowElemsInSource = elements.filter { elem =>
                          val em = elem match {
                            case c: Call => c.method.name
                            case i: Identifier => i.method.name
                            case _ => "?"
                          }
                          em == methodName
                        }
                        val exitLine = flowElemsInSource.lastOption.flatMap(_.lineNumber).getOrElse(allocLine)
                        val hasLocalNullGuard = nullCheckLines.exists(ncLine => ncLine > allocLine && ncLine <= exitLine)
                        val hasLocalEarlyExit = earlyExitLines.exists(el => el > allocLine && el < exitLine)

                        if (!hasLocalNullGuard && !hasLocalEarlyExit) {
                          // Check if callee has a semantic null check on the parameter before dereference
                          val sinkMethodNode = cpg.method.name(sinkMethod).l.headOption
                          val hasNullCheckInCallee = sinkMethodNode.exists { m =>
                            val mStartLine = m.lineNumber.getOrElse(0)
                            // Collect candidate identifiers to check: sink's base object + callee parameters
                            val sinkBaseId = sink match {
                              case c: Call => c.argument.l.headOption.map(_.code.trim).getOrElse("")
                              case _ => ""
                            }
                            val params = m.parameter.name.l
                            val candidates = (if (sinkBaseId.nonEmpty) List(sinkBaseId) else Nil) ++ params

                            m.controlStructure.filter(_.controlStructureType == "IF").l.exists { ifStmt =>
                              val condLine = ifStmt.lineNumber.getOrElse(-1)
                              condLine >= mStartLine && condLine <= sinkLine && {
                                val condAst = ifStmt.condition.ast

                                candidates.exists { candidate =>
                                  val qCand = java.util.regex.Pattern.quote(candidate)

                                  // Semantic: candidate == NULL / != NULL / == 0 / == nullptr
                                  val hasEqCheck = condAst.isCall
                                    .name("<operator>.equals|<operator>.notEquals").l.exists { cmp =>
                                      val argCodes = cmp.argument.code.l.map(_.trim)
                                      argCodes.contains(candidate) &&
                                        argCodes.exists(c => c == "NULL" || c == "0" || c == "nullptr" || c == "((void *)0)" || c == "((void*)0)")
                                    }

                                  // Semantic: !candidate
                                  val hasNotCheck = condAst.isCall
                                    .name("<operator>.logicalNot").l.exists { notOp =>
                                      notOp.argument.isIdentifier.name(qCand).l.nonEmpty
                                    }

                                  // Semantic: if(candidate) — direct bool or compound &&/||
                                  val hasBoolCheck = ifStmt.condition.isIdentifier.name(qCand).l.nonEmpty ||
                                    condAst.isCall.name("<operator>.logicalAnd|<operator>.logicalOr").l.exists { logOp =>
                                      logOp.argument.isIdentifier.name(qCand).l.nonEmpty
                                    }

                                  hasEqCheck || hasNotCheck || hasBoolCheck
                                }
                              }
                            }
                          }

                          if (!hasNullCheckInCallee) {
                            val pathMethods = elements.flatMap { elem =>
                              elem match {
                                case c: Call => Some(c.method.name)
                                case i: Identifier => Some(i.method.name)
                                case _ => None
                              }
                            }.distinct.take(4)

                            val flowType = if (pathMethods.size > 2) "deep-interproc" else "interproc"
                            val pathStr = pathMethods.mkString(" -> ")

                            // Deduplicate against intraprocedural results and already-found interproc results
                            if (!interprocDerefs.exists(d => d._1 == sinkLine && d._5 == sinkMethod) &&
                                !unguardedDerefs.exists(d => d._1 == sinkLine)) {
                              interprocDerefs += ((sinkLine, sink.code + s" [via: $pathStr]", flowType, sinkFile, sinkMethod))
                            }
                          }
                        }
                      }
                    }
                  }
                } catch {
                  case _: Exception => // Ignore dataflow errors gracefully
                }
              }
            }

            // Combine intraprocedural and interprocedural results
            val allDerefs = (unguardedDerefs ++ interprocDerefs.toList).distinct.sortBy(_._1)

            if (allDerefs.nonEmpty) {
              npIssues += ((allocFile, allocLine, allocCode, assignedPtr, methodName, allDerefs))
            }
          }
        }
      }
    }

    if (npIssues.isEmpty) {
      output.append("No potential Null Pointer Dereference issues detected.\n")
      output.append("\nNote: This analysis includes:\n")
      output.append("  - Intraprocedural unchecked allocation return values\n")
      output.append("  - Unchecked fopen/strdup/mmap return values\n")
      output.append("  - Dereferences without prior NULL checks\n")
      output.append("  - Deep interprocedural flow (multi-level call chains)\n")
      output.append("\nFiltered out:\n")
      output.append("  - Dereferences guarded by if(ptr != NULL) checks\n")
      output.append("  - Dereferences after early return/exit on NULL\n")
      output.append("  - Pointer reassignments between allocation and use\n")
      output.append("  - Safe wrapper allocators (xmalloc, g_malloc, etc.)\n")
      output.append("  - Cross-function dereferences with NULL checks in callee\n")
    } else {
      output.append(s"Found ${npIssues.size} potential null pointer dereference issue(s):\n\n")

      npIssues.take(maxResults).zipWithIndex.foreach { case ((file, line, code, ptr, methodName, derefs), idx) =>
        // Compute confidence based on dereference types
        val hasDirectDeref = derefs.exists(d => d._3 == "member_access" || d._3 == "pointer_deref" || d._3 == "index_access")
        val hasConfirmedInterproc = derefs.exists(d => d._3 == "interproc" || d._3 == "deep-interproc")
        val hasFuncArgOnly = derefs.forall(d => d._3 == "passed_to_func")
        val baseConfidence = if (hasDirectDeref || hasConfirmedInterproc) "HIGH"
                             else if (hasFuncArgOnly) "MEDIUM"
                             else "MEDIUM"

        // Check reachability from external input
        val entryPoint = findEntryPoint(methodName)
        val reachable = entryPoint.isDefined
        val confidence = if (reachable && baseConfidence == "MEDIUM") "HIGH" else baseConfidence

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence: $confidence\n")
        output.append(s"Allocation Site: $code\n")
        output.append(s"  Location: $file:$line in $methodName()\n")
        output.append(s"  Assigned To: $ptr\n")
        output.append("\nUnchecked Dereference(s):\n")

        derefs.take(10).foreach { case (derefLine, derefCode, derefType, derefFile, derefMethod) =>
          val codeSnippet = if (derefCode.length > 60) derefCode.take(57) + "..." else derefCode
          val typeTag = derefType match {
            case "member_access" => ""
            case "pointer_deref" => " [DEREF]"
            case "index_access" => " [INDEX]"
            case "passed_to_func" => " [FUNC-ARG]"
            case "interproc" => " [CROSS-FUNC]"
            case "deep-interproc" => " [DEEP]"
            case _ => ""
          }
          val fileToShow = if (derefFile.nonEmpty) derefFile else file
          output.append(s"  [$fileToShow:$derefLine] $codeSnippet$typeTag\n")
          if (derefMethod.nonEmpty && derefMethod != methodName) {
            output.append(s"           in $derefMethod()\n")
          }
        }

        if (derefs.size > 10) {
          output.append(s"  ... and ${derefs.size - 10} more dereference(s)\n")
        }

        // Validation context
        output.append("\nContext:\n")
        val method = cpg.method.name(methodName).l.headOption
        method.foreach { m =>
          val params = m.parameter.l.map(p => s"${p.typeFullName} ${p.name}").mkString(", ")
          val returnType = m.methodReturn.typeFullName
          output.append(s"  Function: $returnType $methodName($params)\n")
        }
        output.append(s"  File: $file\n")
        val callers = cpg.method.name(methodName).l.flatMap(_.callIn.l).map(_.method.name).distinct.take(5)
        if (callers.nonEmpty) {
          output.append(s"  Called By: ${callers.mkString(", ")}\n")
        }
        entryPoint match {
          case Some(entry) => output.append(s"  Reachable From: $entry() (external input)\n")
          case None => output.append(s"  Reachable From: Not directly reachable from external input (depth 10)\n")
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
      output.append("  - [CROSS-FUNC]: Dereference in directly called function\n")
      output.append("  - [DEEP]: Dereference across multiple function call levels\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
