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

  /** Check if two line numbers are in mutually exclusive branches of the same IF.
    * Returns true if lineA is inside the THEN block and lineB inside ELSE (or vice versa),
    * meaning they cannot both execute in the same control flow path.
    */
  def areInMutuallyExclusiveBranches(method: Method, lineA: Int, lineB: Int): Boolean = {
    csCache.getOrElseUpdate(method.fullName, method.ast.isControlStructure.l).exists { cs =>
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
  
  // Known external input functions for reachability analysis
  val externalInputFunctions = Set(
    "getenv", "fgets", "scanf", "read", "recv", "fread", "gets", "getchar",
    "fscanf", "recvfrom", "recvmsg", "getopt", "fopen", "getline",
    "getaddrinfo", "gethostbyname", "accept", "socket", "getpass",
    "realpath", "popen", "fdopen", "tmpfile", "dlopen"
  )

  val csCache    = mutable.Map[String, List[ControlStructure]]()
  val retCache   = mutable.Map[String, List[Return]]()
  val entryPointCache = mutable.Map[String, Option[String]]()

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

  output.append("Use-After-Free Analysis (Deep Interprocedural)\n")
  output.append("=" * 60 + "\n\n")
  
  // Find all free() calls (and common variants)
  val freeCalls = cpg.call.name("free|cfree").l

  val freeCallsFiltered = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    freeCalls.filter(_.file.name.headOption.exists(_.matches(pattern)))
  } else {
    freeCalls
  }
  
  if (freeCallsFiltered.isEmpty) {
    output.append("No free() calls found in the codebase.\n")
  } else {
    output.append(s"Found ${freeCallsFiltered.size} free() call site(s). Analyzing with deep interprocedural flow...\n\n")
    
    // Store UAF issues
    val uafIssues = mutable.ListBuffer[(String, Int, String, String, String, List[(Int, String, String, String, String)])]()

    // Track (freedPtr, methodFullName) to only keep the earliest free per pointer per method
    val seenPtrMethod = mutable.Set[String]()

    // Process free calls sorted by line number so earliest free wins
    val sortedFreeCallsFiltered = freeCallsFiltered.sortBy(_.lineNumber.getOrElse(0))

    sortedFreeCallsFiltered.foreach { freeCall =>
      val freeFile = freeCall.file.name.headOption.getOrElse("unknown")
      val freeLine = freeCall.lineNumber.getOrElse(-1)
      val freeCode = freeCall.code
      val methodName = freeCall.method.name
      
      // The freed expression is the first ARGUMENT, not the first descendant
      // identifier: for free(obj->ptr) / free(*pp) the direct child is a
      // field-access / indirection call, so astChildren.isIdentifier returned the
      // base ("obj") or nothing — silently dropping those frees. Use argument(1)
      // so freedPtr is the actual freed expression ("obj->ptr", "*pp", "p").
      val freedPtrOpt = freeCall.argument.argumentIndex(1).l.headOption

      freedPtrOpt.foreach { freedPtrNode =>
        val freedPtr = freedPtrNode.code.trim
        
        if (!freedPtr.contains("(") && !freedPtr.contains("[") && freedPtr.length < 50) {
          // Skip if we already reported a (earlier) free for this pointer in this method
          val ptrMethodKey = s"$freedPtr:${freeCall.method.fullName}"
          if (!seenPtrMethod.contains(ptrMethodKey)) {
          seenPtrMethod += ptrMethodKey

          val method = freeCall.method
          val postFreeUsages = mutable.ListBuffer[(Int, String, String, String, String)]()

          // === PHASE 1: Intraprocedural post-free use via DATA FLOW ===
          // A genuine post-free use is one the freed pointer's VALUE actually
          // reaches along a control-flow path. Gating on dataflow rather than a
          // `callLine > freeLine` line-number test (plus the old reassignment /
          // early-return / mutually-exclusive line heuristics) is strictly more
          // accurate: it catches same-line `free(p); use(p);` and loop-carried
          // uses those missed, while still excluding (a) a use after the pointer
          // is reassigned, (b) a use on a mutually-exclusive branch, and (c) dead
          // code after an unconditional return — in every case the freed value
          // simply does not flow there. Verified end-to-end against the fixture
          // matrix in tests/test_use_after_free_live.py.
          val freedArgNode = freeCall.argument(1)
          method.call.l.foreach { call =>
            val callLine = call.lineNumber.getOrElse(-1)
            if (!call.name.matches("free|cfree")) {
              val reachedByFreed =
                try { call.argument.reachableBy(freedArgNode).nonEmpty }
                catch { case _: Throwable => false }
              if (reachedByFreed) {
                // Keep only DIRECT references to the freed pointer at this site;
                // transitive aliases are Phase 2's job, and the assignment LHS
                // that merely stores the pointer is propagation, not a use.
                val relevantArgs = call.argument.l.filterNot { arg =>
                  call.name == "<operator>.assignment" && arg.argumentIndex == 1 && arg.code == freedPtr
                }
                val argsContainPtr = relevantArgs.exists { arg =>
                  val argCode = arg.code
                  argCode == freedPtr ||
                  argCode.startsWith(freedPtr + "->") ||
                  argCode.startsWith(freedPtr + "[") ||
                  argCode.startsWith("*" + freedPtr)
                }
                if (argsContainPtr) {
                  postFreeUsages += ((callLine, call.code, freeFile, methodName, "direct"))
                }
              }
            }
          }
          
          // === PHASE 2: Pointer Aliasing Detection ===
          val aliases = mutable.Set[String](freedPtr)
          method.assignment.l.foreach { assign =>
            val assignLine = assign.lineNumber.getOrElse(-1)
            if (assignLine < freeLine) {
              val srcCode = assign.source.code
              if (srcCode == freedPtr || srcCode == "&" + freedPtr) {
                val targetCode = assign.target.code.trim
                if (!targetCode.contains("(") && !targetCode.contains("[") && targetCode.length < 50) {
                  aliases += targetCode
                }
              }
            }
          }
          
          // === PHASE 2b: Post-Free Aliasing Detection ===
          // Catch: free(p); q = p; use(q) — alias created AFTER the free
          // `aliases` already contains freedPtr + all pre-free aliases, so checking
          // aliases.contains(srcCode) covers both direct and transitive post-free aliasing.
          val postFreeAliasAssignments = mutable.ListBuffer[(String, Int)]() // (aliasName, assignLine)
          method.assignment.l.foreach { assign =>
            val assignLine = assign.lineNumber.getOrElse(-1)
            if (assignLine > freeLine) {
              val srcCode = assign.source.code.trim
              if (aliases.contains(srcCode)) {
                val targetCode = assign.target.code.trim
                if (!targetCode.contains("(") && !targetCode.contains("[") && targetCode.length < 50) {
                  postFreeAliasAssignments += ((targetCode, assignLine))
                }
              }
            }
          }

          postFreeAliasAssignments.foreach { case (alias, aliasLine) =>
            val aliasReassignmentLines = mutable.Set[Int]()
            method.assignment.l.foreach { assign =>
              val assignLine = assign.lineNumber.getOrElse(-1)
              if (assignLine > aliasLine && assign.target.code.trim == alias) {
                aliasReassignmentLines += assignLine
              }
            }

            method.call.l.foreach { call =>
              val callLine = call.lineNumber.getOrElse(-1)
              if (callLine > aliasLine && !call.name.matches("free|cfree")) {
                val aliasReassignedBefore = aliasReassignmentLines.exists(rl => rl > aliasLine && rl < callLine)
                val methodCss2b = csCache.getOrElseUpdate(method.fullName, method.ast.isControlStructure.l)
                val hasEarlyReturn = retCache.getOrElseUpdate(method.fullName, method.ast.isReturn.l).exists { ret =>
                  val retLine = ret.lineNumber.getOrElse(-1)
                  retLine > freeLine && retLine < callLine && {
                    val nested = methodCss2b.exists { cs =>
                      val csStart = cs.lineNumber.getOrElse(-1)
                      val csLines = cs.ast.lineNumber.l.filter(_ > 0)
                      val csEnd   = if (csLines.nonEmpty) csLines.max else csStart
                      csStart > freeLine && csStart <= retLine && csEnd >= retLine
                    }
                    !nested
                  }
                }
                val inDifferentBranches = areInMutuallyExclusiveBranches(method, freeLine, callLine)

                if (!aliasReassignedBefore && !hasEarlyReturn && !inDifferentBranches) {
                  val argsContainAlias = call.argument.code.l.exists { argCode =>
                    argCode == alias ||
                    argCode.startsWith(alias + "->") ||
                    argCode.startsWith(alias + "[") ||
                    argCode.startsWith("*" + alias)
                  }
                  if (argsContainAlias) {
                    postFreeUsages += ((callLine, call.code, freeFile, methodName, s"post-free-alias($alias)"))
                  }
                }
              }
            }
          }

          if (aliases.size > 1) {
            val aliasesWithoutOriginal = aliases - freedPtr
            aliasesWithoutOriginal.foreach { alias =>
              // Collect reassignment lines for this alias (after free)
              val aliasReassignmentLines = mutable.Set[Int]()
              method.assignment.l.foreach { assign =>
                val assignLine = assign.lineNumber.getOrElse(-1)
                if (assignLine > freeLine && assign.target.code.trim == alias) {
                  aliasReassignmentLines += assignLine
                }
              }

              method.call.l.foreach { call =>
                val callLine = call.lineNumber.getOrElse(-1)
                if (callLine > freeLine && !call.name.matches("free|cfree")) {
                  // Check if alias was reassigned between free and this specific usage
                  val aliasReassignedBefore = aliasReassignmentLines.exists(rl => rl > freeLine && rl < callLine)

                  val methodCss2a = csCache.getOrElseUpdate(method.fullName, method.ast.isControlStructure.l)
                  val hasEarlyReturn = retCache.getOrElseUpdate(method.fullName, method.ast.isReturn.l).exists { ret =>
                    val retLine = ret.lineNumber.getOrElse(-1)
                    retLine > freeLine && retLine < callLine && {
                      val nested = methodCss2a.exists { cs =>
                        val csStart = cs.lineNumber.getOrElse(-1)
                        val csLines = cs.ast.lineNumber.l.filter(_ > 0)
                        val csEnd   = if (csLines.nonEmpty) csLines.max else csStart
                        csStart > freeLine && csStart <= retLine && csEnd >= retLine
                      }
                      !nested
                    }
                  }
                  val inDifferentBranches = areInMutuallyExclusiveBranches(method, freeLine, callLine)

                  if (!aliasReassignedBefore && !hasEarlyReturn && !inDifferentBranches) {
                    val argsContainAlias = call.argument.code.l.exists { argCode =>
                      argCode == alias || argCode.startsWith(alias + "->") || argCode.startsWith(alias + "[") || argCode.startsWith("*" + alias)
                    }
                    if (argsContainAlias) {
                      postFreeUsages += ((callLine, call.code, freeFile, methodName, s"alias($alias)"))
                    }
                  }
                }
              }
            }
          }
          
          // === PHASE 3: Deep Interprocedural Flow using reachableByFlows ===
          // Track the freed pointer across multiple function call levels
          val sources = List(freedPtrNode).collect { case cfgNode: CfgNode => cfgNode }
          
          if (sources.nonEmpty) {
            // Find usages of identifiers with the same name — scoped to the freeing
            // method and its direct callees only.  Scanning the whole codebase for a
            // common name like "ptr" produces thousands of unrelated nodes and makes
            // reachableByFlows() extremely slow with many false positives.
            val directCalleeNames = method.call.l
              .filterNot(_.name.startsWith("<operator>"))
              .map(_.name)
              .distinct
              .toSet

            val sameNameUsages = cpg.identifier.name(freedPtr).l
              .filter { id =>
                val idLine    = id.lineNumber.getOrElse(-1)
                val idFile    = id.file.name.headOption.getOrElse("")
                val idMethod  = id.method.name
                // Keep: in a direct callee, or in same method AFTER the free
                val inCallee  = directCalleeNames.contains(idMethod)
                val postFreeInSameMethod = idFile == freeFile && idMethod == methodName && idLine > freeLine
                (inCallee || postFreeInSameMethod) &&
                  // Exclude the free call itself
                  !(idFile == freeFile && idMethod == methodName && idLine <= freeLine)
              }
              .collect { case cfgNode: CfgNode => cfgNode }
            
            if (sameNameUsages.nonEmpty) {
              try {
                val flows = sameNameUsages.reachableByFlows(sources).l
                
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
                    
                    val pathMethods = elements.flatMap { elem =>
                        elem match {
                          case c: Call => Some(c.method.name)
                          case i: Identifier => Some(i.method.name)
                          case _ => None
                        }
                      }.distinct.take(4)

                    // Only add cross-function flows that don't enter the deallocator itself
                    val calledMethodName = freeCall.name
                    if ((sinkMethod != methodName || sinkFile != freeFile) && !pathMethods.contains(calledMethodName)) {
                      val flowType = if (pathMethods.size > 2) "deep-interproc" else "interproc"
                      val pathStr = pathMethods.mkString(" -> ")
                      
                      if (!postFreeUsages.exists(u => u._1 == sinkLine && u._4 == sinkMethod)) {
                        postFreeUsages += ((sinkLine, sink.code + s" [via: $pathStr]", sinkFile, sinkMethod, flowType))
                      }
                    }
                  }
                }
              } catch {
                case e: Exception =>
                  output.append(s"  Note: Interprocedural analysis skipped for $freedPtr in $methodName() (${e.getClass.getSimpleName})\n")
              }
            }
          }
          
          // Dedup usages: one per line, prefer direct > alias > interproc
          val flowPriority = Map("direct" -> 0, "alias" -> 1, "interproc" -> 2, "deep-interproc" -> 3)
          val uniqueUsages = postFreeUsages.toList.distinct
            .sortBy(u => flowPriority.getOrElse(u._5.takeWhile(_ != '('), 3))
            .groupBy(_._1)  // group by line
            .values.map(_.head).toList  // keep first (highest priority) per line
            .sortBy(_._1)
          if (uniqueUsages.nonEmpty) {
            uafIssues += ((freeFile, freeLine, freeCode, freedPtr, methodName, uniqueUsages))
          }
          } // end seenPtrMethod check
        }
      }
    }
    
    if (uafIssues.isEmpty) {
      output.append("No potential Use-After-Free issues detected.\n")
      output.append("\nNote: This analysis includes:\n")
      output.append("  - Intraprocedural usages (same function)\n")
      output.append("  - Pre-free aliasing (p2 = ptr; free(ptr); use(p2))\n")
      output.append("  - Post-free aliasing (free(ptr); p2 = ptr; use(p2))\n")
      output.append("  - Deep interprocedural flow (multi-level call chains)\n")
    } else {
      output.append(s"Found ${uafIssues.size} potential UAF issue(s):\n\n")
      
      uafIssues.take(maxResults).zipWithIndex.foreach { case ((freeFile, freeLine, freeCode, freedPtr, methodName, usages), idx) =>
        // Compute confidence based on flow types present
        val hasDirectDeref = usages.exists(u => u._5 == "direct")
        val hasConfirmedInterproc = usages.exists(u => u._5 == "interproc" || u._5 == "deep-interproc")
        val hasAliasOnly = usages.forall(u => u._5.startsWith("alias") || u._5.startsWith("post-free-alias"))
        val baseConfidence = if (hasDirectDeref || hasConfirmedInterproc) "HIGH"
                             else if (hasAliasOnly) "MEDIUM"
                             else "MEDIUM"

        // Check reachability from external input
        val entryPoint = findEntryPoint(methodName)
        val reachable = entryPoint.isDefined
        val confidence = if (reachable && baseConfidence == "MEDIUM") "HIGH" else baseConfidence

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence: $confidence\n")
        output.append(s"Free Site: $freeCode\n")
        output.append(s"  Location: $freeFile:$freeLine in $methodName()\n")
        output.append(s"  Freed Pointer: $freedPtr\n")
        output.append("\nPost-Free Usage(s):\n")

        usages.take(10).foreach { case (line, code, file, usageMethod, flowType) =>
          val codeSnippet = if (code.length > 60) code.take(57) + "..." else code
          val flowTag = flowType match {
            case "direct" => ""
            case "interproc" => " [CROSS-FUNC]"
            case "deep-interproc" => " [DEEP]"
            case other if other.startsWith("alias") || other.startsWith("post-free-alias") => s" [$other]"
            case _ => ""
          }
          output.append(s"  [$file:$line] $codeSnippet$flowTag\n")
          if (usageMethod != methodName) {
            output.append(s"           in $usageMethod()\n")
          }
        }

        if (usages.size > 10) {
          output.append(s"  ... and ${usages.size - 10} more usage(s)\n")
        }

        // Validation context
        output.append("\nContext:\n")
        val method = cpg.method.name(methodName).l.headOption
        method.foreach { m =>
          val params = m.parameter.l.map(p => s"${p.typeFullName} ${p.name}").mkString(", ")
          val returnType = m.methodReturn.typeFullName
          output.append(s"  Function: $returnType $methodName($params)\n")
        }
        output.append(s"  File: $freeFile\n")
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
      
      if (uafIssues.size > maxResults) {
        output.append(s"(Showing $maxResults of ${uafIssues.size} issues. Increase limit to see more.)\n\n")
      }
      
      output.append(s"Total: ${uafIssues.size} potential UAF issue(s) found\n")
      output.append("\nFlow Types:\n")
      output.append("  - direct: Same-function usage of freed pointer\n")
      output.append("  - alias(X): Usage of pre-free alias X (X = ptr before free)\n")
      output.append("  - post-free-alias(X): Usage of X after X = ptr was assigned post-free\n")
      output.append("  - [CROSS-FUNC]: Usage in directly called function\n")
      output.append("  - [DEEP]: Usage across multiple function call levels\n")
    }
  }
  
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
