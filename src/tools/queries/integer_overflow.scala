{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  output.append("Integer Overflow/Underflow Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Allocation functions vulnerable to integer overflow in size argument.
  // calloc and reallocarray are EXCLUDED: they handle multiplication overflow internally.
  val allocPattern = "malloc|realloc|aligned_alloc|valloc|pvalloc|memalign|kmalloc|kzalloc|krealloc|vmalloc|kvmalloc|xmlMalloc|xmlMallocAtomic|xmlRealloc|g_malloc|g_malloc0|g_realloc|xmalloc|xrealloc|emalloc|erealloc"

  // Functions where size is the SECOND argument (ptr/alignment, size)
  val sizeInSecondArg = Set("realloc", "krealloc", "xmlRealloc", "g_realloc", "xrealloc", "erealloc", "aligned_alloc")

  // High-risk: multiplication and left-shift can cause dramatic overflow
  val highRiskOps = Set("<operator>.multiplication", "<operator>.shiftLeft")

  // Medium-risk: addition/subtraction of two variable operands
  val mediumRiskOps = Set("<operator>.addition", "<operator>.subtraction")

  // Keywords indicating an overflow check in a condition
  val guardKeywords = List(
    "SIZE_MAX", "UINT_MAX", "ULONG_MAX", "INT_MAX", "LONG_MAX",
    "UINT32_MAX", "UINT64_MAX", "SSIZE_MAX", "RSIZE_MAX",
    "__builtin_mul_overflow", "__builtin_add_overflow", "__builtin_sub_overflow",
    "__builtin_umul_overflow", "__builtin_uadd_overflow",
    "safe_mul", "safe_add", "checked_mul", "checked_add",
    "ckd_mul", "ckd_add", "ckd_sub"
  )

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

  // --- Helper functions ---

  def isConstantExpr(code: String): Boolean = {
    val c = code.trim
    c.matches("-?\\d+[UuLl]*") ||
    c.matches("0[xX][0-9a-fA-F]+[UuLl]*") ||
    c.matches("0[0-7]+[UuLl]*") ||
    c.startsWith("sizeof") ||
    c.matches("'.'")
  }

  def hasOverflowGuard(method: Method, fromLine: Int, toLine: Int, operandNames: List[String]): Boolean = {
    if (operandNames.isEmpty) return false
    method.controlStructure.filter(_.controlStructureType == "IF").l.exists { ifStmt =>
      val condLine = ifStmt.lineNumber.getOrElse(-1)
      condLine >= fromLine && condLine <= toLine && {
        val condCode = ifStmt.condition.code.headOption.getOrElse("")
        // Check 1: Condition contains overflow-check keywords (SIZE_MAX, __builtin_*_overflow, etc.)
        val hasKeyword = guardKeywords.exists(kw => condCode.contains(kw))
        // Check 2: Condition contains division with an operand name (pattern: a > MAX / b)
        val hasDivCheck = condCode.contains("/") && operandNames.exists(n => n.length > 1 && condCode.contains(n))
        // Check 3: Uses GCC/Clang builtin overflow checking
        val hasBuiltin = condCode.contains("__builtin_") && condCode.contains("overflow")
        hasKeyword || hasDivCheck || hasBuiltin
      }
    }
  }

  // --- Analysis ---

  val allAllocCalls = cpg.call.name(allocPattern).l
  val allocCalls = if (fileFilter.nonEmpty) {
    allAllocCalls.filter(_.file.name.headOption.exists(f => f.contains(fileFilter) || f.endsWith(fileFilter)))
  } else {
    allAllocCalls
  }

  if (allocCalls.isEmpty) {
    output.append("No allocation calls found in the codebase.\n")
  } else {
    output.append(s"Found ${allocCalls.size} allocation site(s). Analyzing for integer overflow risks...\n\n")

    // Issues: (file, line, accessCode, arithCode, opType, methodName, risk, issueType)
    val issues = mutable.ListBuffer[(String, Int, String, String, String, String, String, String)]()
    val seen = mutable.Set[String]()

    allocCalls.foreach { allocCall =>
      val allocFile = allocCall.file.name.headOption.getOrElse("unknown")
      val allocLine = allocCall.lineNumber.getOrElse(-1)
      val method = allocCall.method
      val methodName = method.name

      // Determine which argument is the size
      val sizeArgIdx = if (sizeInSecondArg.contains(allocCall.name)) 2 else 1

      // === PHASE 1: Direct arithmetic in size argument ===
      allocCall.argument.order(sizeArgIdx).l.foreach { sizeArg =>

        // Check high-risk operators (multiplication, left-shift)
        sizeArg.ast.isCall.filter(c => highRiskOps.contains(c.name)).l.foreach { arithOp =>
          val operandCodes = arithOp.argument.l.map(_.code.trim)
          if (!operandCodes.forall(isConstantExpr) && operandCodes.size >= 2) {
            val arithLine = arithOp.lineNumber.getOrElse(allocLine)
            val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
            val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
            if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
              val key = s"$allocFile:$allocLine:h:${arithOp.code.hashCode}"
              if (!seen.contains(key)) {
                seen += key
                val opStr = if (arithOp.name == "<operator>.multiplication") "multiplication" else "left-shift"
                issues += ((allocFile, allocLine, allocCall.code, arithOp.code, opStr, methodName, "HIGH", "alloc_arithmetic"))
              }
            }
          }
        }

        // Check medium-risk operators (addition/subtraction of two non-constant variables)
        sizeArg.ast.isCall.filter(c => mediumRiskOps.contains(c.name)).l.foreach { arithOp =>
          val operandCodes = arithOp.argument.l.map(_.code.trim)
          val nonConstCount = operandCodes.count(c => !isConstantExpr(c))
          // Only flag if BOTH operands are non-constant (avoids flagging "len + 1" noise)
          if (nonConstCount >= 2) {
            val arithLine = arithOp.lineNumber.getOrElse(allocLine)
            val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
            val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
            if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
              val key = s"$allocFile:$allocLine:m:${arithOp.code.hashCode}"
              if (!seen.contains(key)) {
                seen += key
                val opStr = if (arithOp.name == "<operator>.addition") "addition" else "subtraction"
                issues += ((allocFile, allocLine, allocCall.code, arithOp.code, opStr, methodName, "MEDIUM", "alloc_arithmetic"))
              }
            }
          }
        }
      }

      // === PHASE 2: Indirect — variable with arithmetic result used as alloc size ===
      // Pattern: size = a * b; ... malloc(size);
      allocCall.argument.order(sizeArgIdx).l.foreach { sizeArg =>
        val sizeVarNames = sizeArg.ast.isIdentifier.name.l.distinct

        sizeVarNames.foreach { sizeVarName =>
          // Find the most recent assignment to this variable before the allocation
          val assignments = method.assignment.l.filter { assign =>
            val aLine = assign.lineNumber.getOrElse(-1)
            aLine > 0 && aLine < allocLine && assign.target.code.trim == sizeVarName
          }.sortBy(_.lineNumber.getOrElse(-1))

          assignments.lastOption.foreach { assign =>
            val assignLine = assign.lineNumber.getOrElse(-1)

            // Check if RHS contains high-risk arithmetic
            assign.source.ast.isCall.filter(c => highRiskOps.contains(c.name)).l.foreach { arithOp =>
              val operandCodes = arithOp.argument.l.map(_.code.trim)
              if (!operandCodes.forall(isConstantExpr) && operandCodes.size >= 2) {
                // Check no reassignment of the variable between assignment and alloc
                val hasReassignment = method.assignment.l.exists { a =>
                  val aLine2 = a.lineNumber.getOrElse(-1)
                  aLine2 > assignLine && aLine2 < allocLine && a.target.code.trim == sizeVarName
                }

                if (!hasReassignment) {
                  val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
                  val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
                  if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
                    val key = s"$allocFile:$allocLine:i:${arithOp.code.hashCode}"
                    if (!seen.contains(key)) {
                      seen += key
                      val opStr = if (arithOp.name == "<operator>.multiplication") "multiplication" else "left-shift"
                      issues += ((allocFile, allocLine, allocCall.code, arithOp.code, opStr, methodName, "HIGH", "alloc_indirect_arithmetic"))
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    // === PHASE 3: Multiplication/left-shift in array index (conservative) ===
    // Only flag high-risk arithmetic in array indices, with no bounds check nearby.
    val allIndexCalls = cpg.call.name("<operator>.indirectIndexAccess|<operator>.indexAccess").l
    val indexCalls = if (fileFilter.nonEmpty) {
      allIndexCalls.filter(_.file.name.headOption.exists(f => f.contains(fileFilter) || f.endsWith(fileFilter)))
    } else {
      allIndexCalls
    }

    indexCalls.foreach { indexCall =>
      val indexFile = indexCall.file.name.headOption.getOrElse("unknown")
      val indexLine = indexCall.lineNumber.getOrElse(-1)
      val method = indexCall.method
      val methodName = method.name

      // Index is the second argument (first is the array/pointer)
      indexCall.argument.order(2).l.foreach { indexArg =>
        indexArg.ast.isCall.filter(c => highRiskOps.contains(c.name)).l.foreach { arithOp =>
          val operandCodes = arithOp.argument.l.map(_.code.trim)
          if (!operandCodes.forall(isConstantExpr) && operandCodes.size >= 2) {
            val arithLine = arithOp.lineNumber.getOrElse(indexLine)
            val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct

            // Check for bounds check: any IF before the index access that
            // references an operand AND contains a comparison operator
            val hasBoundsCheck = method.controlStructure.filter(_.controlStructureType == "IF").l.exists { ifStmt =>
              val condLine = ifStmt.lineNumber.getOrElse(-1)
              condLine > 0 && condLine <= indexLine && {
                val condCode = ifStmt.condition.code.headOption.getOrElse("")
                operandNames.exists(n => n.length > 1 && condCode.contains(n)) && (
                  condCode.contains("<") || condCode.contains(">") ||
                  guardKeywords.exists(kw => condCode.contains(kw))
                )
              }
            }

            if (!hasBoundsCheck) {
              val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
              if (!hasOverflowGuard(method, guardFrom, indexLine, operandNames)) {
                val key = s"$indexFile:$indexLine:x:${arithOp.code.hashCode}"
                if (!seen.contains(key)) {
                  seen += key
                  val opStr = if (arithOp.name == "<operator>.multiplication") "multiplication" else "left-shift"
                  issues += ((indexFile, indexLine, indexCall.code, arithOp.code, opStr, methodName, "MEDIUM", "index_arithmetic"))
                }
              }
            }
          }
        }
      }
    }

    // === PHASE 4: Deep Interprocedural — arithmetic result flows cross-function to allocation ===
    // Pattern: size_t compute_size(w, h) { return w * h; }  ...  malloc(compute_size(w, h));
    // Uses Joern's reachableByFlows() for multi-level call chain tracking.
    try {
      // Sources: multiplication/left-shift results with non-constant operands
      val arithSourceCalls = cpg.call.filter(c => highRiskOps.contains(c.name)).l
        .filter { arithOp =>
          val operandCodes = arithOp.argument.l.map(_.code.trim)
          !operandCodes.forall(isConstantExpr) && operandCodes.size >= 2
        }

      val arithSourcesFiltered = if (fileFilter.nonEmpty) {
        arithSourceCalls.filter(_.file.name.headOption.exists(f => f.contains(fileFilter) || f.endsWith(fileFilter)))
      } else {
        arithSourceCalls
      }

      val arithSourceNodes = arithSourcesFiltered.take(200).collect { case cfgNode: CfgNode => cfgNode }

      // Sinks: size arguments of allocation calls
      val allocSinkNodes = allocCalls.flatMap { allocCall =>
        val sizeArgIdx = if (sizeInSecondArg.contains(allocCall.name)) 2 else 1
        allocCall.argument.order(sizeArgIdx).l
      }.take(200).collect { case cfgNode: CfgNode => cfgNode }

      if (arithSourceNodes.nonEmpty && allocSinkNodes.nonEmpty) {
        val flows = allocSinkNodes.reachableByFlows(arithSourceNodes).l.take(20)

        flows.foreach { flow =>
          val elements = flow.elements.l
          if (elements.size > 1) {
            val source = elements.head
            val sink = elements.last

            val sourceMethod = source match {
              case c: Call => c.method.name
              case i: Identifier => i.method.name
              case _ => "?"
            }
            val sinkMethod = sink match {
              case c: Call => c.method.name
              case i: Identifier => i.method.name
              case _ => "?"
            }

            // Only report cross-function flows (intraprocedural already handled by Phases 1-2)
            if (sourceMethod != sinkMethod) {
              val sinkFile = sink.file.name.headOption.getOrElse("unknown")
              val sinkLine = sink.lineNumber.getOrElse(-1)
              val sourceFile = source.file.name.headOption.getOrElse("unknown")
              val sourceLine = source.lineNumber.getOrElse(-1)

              // Check overflow guard in the sink's method
              val sinkMethodNode = cpg.method.name(sinkMethod).l.headOption
              val operandNames = source match {
                case c: Call => c.argument.ast.isIdentifier.name.l.distinct
                case _ => List.empty[String]
              }
              val hasGuard = sinkMethodNode.exists { m =>
                val guardFrom = math.max(m.lineNumber.getOrElse(1), 1)
                hasOverflowGuard(m, guardFrom, sinkLine, operandNames)
              }

              if (!hasGuard) {
                val key = s"$sinkFile:$sinkLine:p:${source.code.hashCode}"
                if (!seen.contains(key)) {
                  seen += key
                  // Also skip if we already reported this allocation site from Phase 1/2
                  val alreadyReported = issues.exists(i => i._1 == sinkFile && i._2 == sinkLine)
                  if (!alreadyReported) {
                    val pathMethods = elements.flatMap { elem =>
                      elem match {
                        case c: Call => Some(c.method.name)
                        case i: Identifier => Some(i.method.name)
                        case _ => None
                      }
                    }.distinct.take(4)

                    val opStr = source match {
                      case c: Call if c.name == "<operator>.multiplication" => "multiplication"
                      case _ => "left-shift"
                    }
                    val pathStr = pathMethods.mkString(" -> ")
                    val arithCode = source.code + s" (at $sourceFile:$sourceLine) [via: $pathStr]"
                    val sinkCode = sink.code
                    issues += ((sinkFile, sinkLine, sinkCode, arithCode, opStr, sinkMethod, "HIGH", "interproc_arithmetic"))
                  }
                }
              }
            }
          }
        }
      }
    } catch {
      case _: Exception => // Ignore dataflow engine errors gracefully
    }

    // === Output results ===

    if (issues.isEmpty) {
      output.append("No potential integer overflow/underflow issues detected.\n")
      output.append("\nNote: This analysis checks for:\n")
      output.append("  - Unchecked multiplication/left-shift in allocation sizes\n")
      output.append("  - Unchecked addition/subtraction of two variables in allocation sizes\n")
      output.append("  - Unchecked multiplication/left-shift in array indices\n")
      output.append("  - Cross-function arithmetic flowing to allocation sizes (interprocedural)\n")
      output.append("\nFiltered out:\n")
      output.append("  - Constant expressions (sizeof * literal, etc.)\n")
      output.append("  - Arithmetic guarded by overflow checks (SIZE_MAX, __builtin_*_overflow, etc.)\n")
      output.append("  - calloc/reallocarray (handle overflow internally)\n")
      output.append("  - Single-variable + constant additions (e.g., len + 1)\n")
      output.append("  - Array indices with preceding bounds checks\n")
    } else {
      // Sort HIGH before MEDIUM
      val sortedIssues = issues.toList.sortBy(i => if (i._7 == "HIGH") 0 else 1)

      output.append(s"Found ${issues.size} potential integer overflow/underflow issue(s):\n\n")

      sortedIssues.take(maxResults).zipWithIndex.foreach { case ((file, line, accessCode, arithCode, opStr, methodName, risk, issueType), idx) =>
        // Confidence mirrors risk level, boosted by reachability
        val entryPoint = findEntryPoint(methodName)
        val reachable = entryPoint.isDefined
        val confidence = if (risk == "HIGH") "HIGH"
                         else if (reachable) "HIGH"
                         else "MEDIUM"

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence: $confidence\n")

        val truncAccessCode = if (accessCode.length > 80) accessCode.take(77) + "..." else accessCode
        val truncArithCode = if (arithCode.length > 60) arithCode.take(57) + "..." else arithCode

        val issueTypeStr = issueType match {
          case "alloc_arithmetic" => "Arithmetic in Allocation Size"
          case "alloc_indirect_arithmetic" => "Arithmetic in Allocation Size (via variable)"
          case "index_arithmetic" => "Arithmetic in Array Index"
          case "interproc_arithmetic" => "Cross-Function Arithmetic to Allocation"
          case _ => "Arithmetic Overflow Risk"
        }

        val crossFuncTag = if (issueType == "interproc_arithmetic") " [CROSS-FUNC]" else ""
        output.append(s"Type: $issueTypeStr [$risk]$crossFuncTag\n")
        output.append(s"  Location: $file:$line in $methodName()\n")
        output.append(s"  Code: $truncAccessCode\n")
        output.append(s"  Arithmetic: $truncArithCode ($opStr)\n")
        output.append(s"  Risk: Unchecked $opStr may wrap around, causing ")
        if (issueType == "index_arithmetic") {
          output.append("out-of-bounds array access\n")
        } else {
          output.append("undersized buffer allocation\n")
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

      if (issues.size > maxResults) {
        output.append(s"(Showing $maxResults of ${issues.size} issues. Increase limit to see more.)\n\n")
      }

      output.append(s"Total: ${issues.size} potential integer overflow/underflow issue(s) found\n")
      output.append("\nRisk Levels:\n")
      output.append("  - [HIGH]: Multiplication or left-shift in allocation size without overflow check\n")
      output.append("  - [HIGH] [CROSS-FUNC]: Cross-function arithmetic result used in allocation size\n")
      output.append("  - [MEDIUM]: Addition/subtraction of variables in allocation size, or arithmetic in array index\n")
      output.append("\nCWE: CWE-190 (Integer Overflow or Wraparound)\n")
      output.append("Recommendation: Use overflow-safe functions (calloc, reallocarray) or add explicit\n")
      output.append("overflow checks before using arithmetic results for allocation sizes or array indices.\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
