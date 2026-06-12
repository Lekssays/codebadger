{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  // Helper: build path-boundary anchored regex from a filename
  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }

  output.append("Integer Overflow/Underflow Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Allocation functions vulnerable to integer overflow in size argument.
  // calloc and reallocarray are EXCLUDED: they handle multiplication overflow internally.
  val allocPattern = "malloc|calloc|realloc|aligned_alloc|reallocarray|valloc|pvalloc|memalign|posix_memalign"

  // Functions where size is the SECOND argument (ptr/alignment, size)
  val sizeInSecondArg = Set("realloc", "aligned_alloc", "memalign", "posix_memalign")

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

  // Memoize findEntryPoint results — called once per finding, expensive without cache
  val entryPointCache = mutable.Map[String, Option[String]]()

  /** Check if a method is transitively reachable from external input.
    * BFS-walks callers up to maxDepth levels. Results are memoized.
    */
  def findEntryPoint(methodName: String, maxDepth: Int = 10): Option[String] = {
    entryPointCache.getOrElseUpdate(methodName, {
      var visited = Set[String]()
      var frontier = List(methodName)
      var depth = 0
      var result: Option[String] = None

      while (depth < maxDepth && frontier.nonEmpty && result.isEmpty) {
        val nextFrontier = mutable.ListBuffer[String]()
        frontier.foreach { current =>
          if (!visited.contains(current) && result.isEmpty) {
            visited += current
            val hasExtInput = cpg.method.name(current).l.exists { m =>
              m.call.l.exists(c => externalInputFunctions.contains(c.name))
            }
            if (hasExtInput) result = Some(current)
            else {
              val callers = cpg.method.name(current).l
                .flatMap(_.callIn.l)
                .map(_.method.name)
                .distinct
                .filterNot(visited.contains)
              nextFrontier ++= callers
            }
          }
        }
        frontier = nextFrontier.toList
        depth += 1
      }
      result
    })
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

  /** Check if a constant expression is "small" (<=4096).
    * Small constants in addition (e.g., len + 1, size + sizeof(int)) are
    * extremely common and virtually never cause overflow in practice.
    * Large constants (e.g., MAX_SIZE expanded to 65536) combined with a
    * variable ARE worth flagging since overflow is more plausible.
    */
  def isSmallConstant(code: String): Boolean = {
    val c = code.trim.replaceAll("[UuLl]+$", "")
    try {
      if (c.startsWith("sizeof") || c.matches("'.'")) {
        true
      } else if (c.startsWith("0x") || c.startsWith("0X")) {
        java.lang.Long.parseLong(c.substring(2), 16) <= 4096L
      } else if (c.startsWith("0") && c.length > 1 && c.matches("0[0-7]+")) {
        java.lang.Long.parseLong(c.substring(1), 8) <= 4096L
      } else {
        java.lang.Long.parseLong(c) <= 4096L
      }
    } catch {
      case _: NumberFormatException => false
    }
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
        val hasDivCheck = condCode.contains("/") && operandNames.exists(n => condCode.matches(s".*\\b${java.util.regex.Pattern.quote(n)}\\b.*"))
        // Check 3: Uses GCC/Clang builtin overflow checking
        val hasBuiltin = condCode.contains("__builtin_") && condCode.contains("overflow")
        hasKeyword || hasDivCheck || hasBuiltin
      }
    }
  }

  // --- Analysis ---

  val allAllocCalls = cpg.call.name(allocPattern).l
  val filePattern = if (fileFilter.nonEmpty) pathBoundaryRegex(fileFilter) else ""

  val allocCalls = if (fileFilter.nonEmpty) {
    allAllocCalls.filter(_.file.name.headOption.exists(_.matches(filePattern)))
  } else {
    allAllocCalls
  }

  if (allocCalls.isEmpty) {
    output.append("No allocation calls found in the codebase.\n")
  } else {
    output.append(s"Found ${allocCalls.size} allocation site(s). Analyzing for integer overflow risks...\n\n")

    // Issues: (file, line, accessCode, arithCode, opType, methodName, risk, issueType)
    val issues = mutable.ListBuffer[(String, Int, String, String, String, String, String, String)]()
    // One issue per allocation/index site — first (highest-risk) match wins
    val seenAllocSites = mutable.Set[String]()
    val seenIndexSites = mutable.Set[String]()

    allocCalls.foreach { allocCall =>
      val allocFile = allocCall.file.name.headOption.getOrElse("unknown")
      val allocLine = allocCall.lineNumber.getOrElse(-1)
      val method = allocCall.method
      val methodName = method.name

      // Determine which argument is the size
      val sizeArgIdx = if (sizeInSecondArg.contains(allocCall.name)) 2 else 1

      // === PHASE 1: Direct arithmetic in size argument ===
      allocCall.argument.argumentIndex(sizeArgIdx).l.foreach { sizeArg =>

        // Check high-risk operators (multiplication, left-shift)
        // Take only the first (outermost in AST) match per allocation site
        val allocSiteKey = s"$allocFile:$allocLine"
        if (!seenAllocSites.contains(allocSiteKey)) {
          sizeArg.ast.isCall.filter(c => highRiskOps.contains(c.name)).l
            .find { arithOp =>
              val operandCodes = arithOp.argument.l.map(_.code.trim)
              !operandCodes.forall(isConstantExpr) && operandCodes.size >= 2
            }
            .foreach { arithOp =>
              val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
              val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
              if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
                seenAllocSites += allocSiteKey
                val opStr = if (arithOp.name == "<operator>.multiplication") "multiplication" else "left-shift"
                issues += ((allocFile, allocLine, allocCall.code, arithOp.code, opStr, methodName, "HIGH", "alloc_arithmetic"))
              }
            }
        }

        // Check medium-risk operators (addition/subtraction) — only if no high-risk found for this site
        if (!seenAllocSites.contains(allocSiteKey)) {
          sizeArg.ast.isCall.filter(c => mediumRiskOps.contains(c.name)).l
            .find { arithOp =>
              val operandCodes = arithOp.argument.l.map(_.code.trim)
              val nonConstCount = operandCodes.count(c => !isConstantExpr(c))
              if (nonConstCount >= 2) true
              else if (nonConstCount == 1) {
                val constOperands = operandCodes.filter(isConstantExpr)
                !constOperands.forall(isSmallConstant)
              } else false
            }
            .foreach { arithOp =>
              val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
              val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
              if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
                seenAllocSites += allocSiteKey
                val opStr = if (arithOp.name == "<operator>.addition") "addition" else "subtraction"
                issues += ((allocFile, allocLine, allocCall.code, arithOp.code, opStr, methodName, "MEDIUM", "alloc_arithmetic"))
              }
            }
        }
      }

      // === PHASE 2: Indirect — variable with arithmetic result used as alloc size ===
      // Pattern: size = a * b; ... malloc(size);
      // Skip if Phase 1 already reported this allocation site
      if (!seenAllocSites.contains(s"$allocFile:$allocLine")) {
        allocCall.argument.argumentIndex(sizeArgIdx).l.foreach { sizeArg =>
          val sizeVarNames = sizeArg.ast.isIdentifier.name.l.distinct
          val siteKey = s"$allocFile:$allocLine"

          sizeVarNames.takeWhile(_ => !seenAllocSites.contains(siteKey)).foreach { sizeVarName =>
            val assignments = method.assignment.l.filter { assign =>
              val aLine = assign.lineNumber.getOrElse(-1)
              aLine > 0 && aLine < allocLine && assign.target.code.trim == sizeVarName
            }.sortBy(_.lineNumber.getOrElse(-1))

            assignments.lastOption.foreach { assign =>
              val assignLine = assign.lineNumber.getOrElse(-1)

              assign.source.ast.isCall.filter(c => highRiskOps.contains(c.name)).l
                .find { arithOp =>
                  val operandCodes = arithOp.argument.l.map(_.code.trim)
                  !operandCodes.forall(isConstantExpr) && operandCodes.size >= 2
                }
                .foreach { arithOp =>
                  val hasReassignment = method.assignment.l.exists { a =>
                    val aLine2 = a.lineNumber.getOrElse(-1)
                    aLine2 > assignLine && aLine2 < allocLine && a.target.code.trim == sizeVarName
                  }

                  if (!hasReassignment && !seenAllocSites.contains(siteKey)) {
                    val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct
                    val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
                    if (!hasOverflowGuard(method, guardFrom, allocLine, operandNames)) {
                      seenAllocSites += siteKey
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

    // === PHASE 3: Multiplication/left-shift in array index (conservative) ===
    // Only flag high-risk arithmetic in array indices, with no bounds check nearby.
    val allIndexCalls = cpg.call.name("<operator>.indirectIndexAccess|<operator>.indexAccess").l
    val indexCalls = if (fileFilter.nonEmpty) {
      allIndexCalls.filter(_.file.name.headOption.exists(_.matches(filePattern)))
    } else {
      allIndexCalls
    }

    indexCalls.foreach { indexCall =>
      val indexFile = indexCall.file.name.headOption.getOrElse("unknown")
      val indexLine = indexCall.lineNumber.getOrElse(-1)
      val method = indexCall.method
      val methodName = method.name
      val indexSiteKey = s"$indexFile:$indexLine"

      // One issue per index site; skip if already reported
      if (!seenIndexSites.contains(indexSiteKey)) {
        indexCall.argument.argumentIndex(2).l.foreach { indexArg =>
          indexArg.ast.isCall.filter(c => highRiskOps.contains(c.name)).l
            .find { arithOp =>
              val operandCodes = arithOp.argument.l.map(_.code.trim)
              !operandCodes.forall(isConstantExpr) && operandCodes.size >= 2
            }
            .foreach { arithOp =>
              val operandNames = arithOp.argument.ast.isIdentifier.name.l.distinct

              val hasBoundsCheck = method.controlStructure.filter(_.controlStructureType == "IF").l.exists { ifStmt =>
                val condLine = ifStmt.lineNumber.getOrElse(-1)
                condLine > 0 && condLine <= indexLine && {
                  val condCode = ifStmt.condition.code.headOption.getOrElse("")
                  operandNames.exists(n => condCode.matches(s".*\\b${java.util.regex.Pattern.quote(n)}\\b.*")) && (
                    condCode.contains("<") || condCode.contains(">") ||
                    guardKeywords.exists(kw => condCode.contains(kw))
                  )
                }
              }

              // Suppress array index arithmetic when the index access falls INSIDE a FOR
              // loop that names the operand in its header.  Previous code only checked
              // forLine <= indexLine, which is true even when the index access is AFTER
              // the loop ends.  Now we also verify indexLine <= forEnd.
              val isInBoundedLoop = method.controlStructure.filter(_.controlStructureType == "FOR").l.exists { forStmt =>
                val forStart = forStmt.lineNumber.getOrElse(-1)
                val forLines = forStmt.ast.lineNumber.l.filter(_ > 0)
                val forEnd   = if (forLines.nonEmpty) forLines.max else forStart
                forStart > 0 && forStart <= indexLine && forEnd >= indexLine && {
                  val forCode = forStmt.code
                  operandNames.exists(n => n.length > 1 && forCode.contains(n))
                }
              }

              if (!hasBoundsCheck && !isInBoundedLoop) {
                val guardFrom = math.max(method.lineNumber.getOrElse(1), 1)
                if (!hasOverflowGuard(method, guardFrom, indexLine, operandNames)) {
                  seenIndexSites += indexSiteKey
                  val opStr = if (arithOp.name == "<operator>.multiplication") "multiplication" else "left-shift"
                  issues += ((indexFile, indexLine, indexCall.code, arithOp.code, opStr, methodName, "MEDIUM", "index_arithmetic"))
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
        arithSourceCalls.filter(_.file.name.headOption.exists(_.matches(filePattern)))
      } else {
        arithSourceCalls
      }

      val arithSourceNodes = arithSourcesFiltered.take(200).collect { case cfgNode: CfgNode => cfgNode }

      // Sinks: size arguments of allocation calls
      val allocSinkNodes = allocCalls.flatMap { allocCall =>
        val sizeArgIdx = if (sizeInSecondArg.contains(allocCall.name)) 2 else 1
        allocCall.argument.argumentIndex(sizeArgIdx).l
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
                val crossSiteKey = s"$sinkFile:$sinkLine"
                // Skip if already reported this allocation site from Phase 1/2/earlier Phase 4
                if (!seenAllocSites.contains(crossSiteKey)) {
                  seenAllocSites += crossSiteKey
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
    } catch {
      case e: Exception =>
        output.append(s"  Note: Interprocedural arithmetic flow analysis encountered an error (${e.getClass.getSimpleName})\n")
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
      output.append("  - Single-variable + small constant additions (e.g., len + 1, size + 16)\n")
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

    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
