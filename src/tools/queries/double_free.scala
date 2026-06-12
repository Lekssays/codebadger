{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable
  
  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  // Helper: build path-boundary anchored regex from a filename
  // e.g., "parser.c" -> "(^|.*/)parser\\.c$" so it matches "/path/to/parser.c"
  // but NOT "/path/to/myparser.c"
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

  val csCache = mutable.Map[String, List[ControlStructure]]()
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

  output.append("Double-Free Detection Analysis\n")
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
    output.append(s"Found ${freeCallsFiltered.size} free() call site(s). Analyzing for double-free...\n\n")
    
    // Group free calls by method to analyze within each function
    val freeCallsByMethod = freeCallsFiltered.groupBy(_.method.fullName)
    
    // Store double-free issues
    val doubleFreeIssues = mutable.ListBuffer[(String, String, String, Int, String, Int, String, String)]()
    // (file, method, ptr, firstFreeLine, firstFreeCode, secondFreeLine, secondFreeCode, flowType)
    
    freeCallsByMethod.foreach { case (methodFullName, methodFreeCalls) =>
      if (methodFreeCalls.size >= 2) {
        val method = methodFreeCalls.head.method
        val methodName = method.name
        val methodAssignments = method.assignment.l

        val sortedFreeCalls = methodFreeCalls.sortBy(_.lineNumber.getOrElse(0))
        // Track which free sites already have a pair to avoid redundant chains
        // e.g., free@10, free@20, free@30 → report (10,20) only, skip (10,30)
        val pairedFirstFrees = mutable.Set[String]()

        // For each free call, check if there's another free of the same pointer later
        sortedFreeCalls.zipWithIndex.foreach { case (firstFree, idx) =>
          val firstLine = firstFree.lineNumber.getOrElse(-1)
          val firstCode = firstFree.code
          val firstFile = firstFree.file.name.headOption.getOrElse("unknown")
          
          // Get the freed pointer
          val firstArgs = firstFree.astChildren.isIdentifier.l
          firstArgs.headOption.foreach { firstPtrNode =>
            val firstPtr = firstPtrNode.code.trim
            
            if (!firstPtr.contains("(") && !firstPtr.contains("[") && firstPtr.length < 50) {
              
              val aliases = mutable.Set[String](firstPtr)
              methodAssignments.foreach { assign =>
                val assignLine = assign.lineNumber.getOrElse(-1)
                if (assignLine < firstLine) {
                  val srcCode = assign.source.code.trim
                  val tgtCode = assign.target.code.trim
                  if (srcCode == firstPtr && !tgtCode.contains("(") && !tgtCode.contains("[") && tgtCode.length < 50) {
                    aliases += tgtCode
                  }
                  if (tgtCode == firstPtr && !srcCode.contains("(") && !srcCode.contains("[") && srcCode.length < 50) {
                    aliases += srcCode
                  }
                }
              }
              
              // Check for reallocation between first free and any subsequent free
              val reallocCalls = method.call.name("malloc|calloc|realloc|strdup|strndup|aligned_alloc|reallocarray").l
              
              // Check remaining free calls for double-free
              sortedFreeCalls.drop(idx + 1).foreach { secondFree =>
                val secondLine = secondFree.lineNumber.getOrElse(-1)
                val secondCode = secondFree.code
                
                val secondArgs = secondFree.astChildren.isIdentifier.l
                secondArgs.headOption.foreach { secondPtrNode =>
                  val secondPtr = secondPtrNode.code.trim
                  
                  // Check if second free is on the same pointer or an alias
                  if (aliases.contains(secondPtr)) {
                    val hasRealloc = reallocCalls.exists { realloc =>
                      val reallocLine = realloc.lineNumber.getOrElse(-1)
                      reallocLine > firstLine && reallocLine < secondLine &&
                      methodAssignments.exists { assign =>
                        assign.lineNumber.getOrElse(-1) == reallocLine &&
                        aliases.contains(assign.target.code.trim)
                      }
                    }

                    val hasReassignment = methodAssignments.exists { assign =>
                      val assignLine = assign.lineNumber.getOrElse(-1)
                      assignLine > firstLine && assignLine < secondLine &&
                      aliases.contains(assign.target.code.trim)
                    }

                    val methodCss = csCache.getOrElseUpdate(method.fullName, method.ast.isControlStructure.l)
                    val hasEarlyExit = method.ast.isReturn.l.exists { ret =>
                      val retLine = ret.lineNumber.getOrElse(-1)
                      retLine > firstLine && retLine < secondLine && {
                        val nested = methodCss.exists { cs =>
                          val csStart = cs.lineNumber.getOrElse(-1)
                          val csLines = cs.ast.lineNumber.l.filter(_ > 0)
                          val csEnd   = if (csLines.nonEmpty) csLines.max else csStart
                          csStart > firstLine && csStart <= retLine && csEnd >= retLine
                        }
                        !nested
                      }
                    }
                    
                    // Check if the two frees are in mutually exclusive if/else branches
                    val inDifferentBranches = areInMutuallyExclusiveBranches(method, firstLine, secondLine)

                    // Decide whether this pair is a genuine double-free.
                    //   Same pointer: DATA FLOW is authoritative. If the value freed
                    //   at the first site still reaches the second free's argument,
                    //   it is the same live allocation freed twice. Dataflow is
                    //   path-sensitive, so it already accounts for reallocation,
                    //   reassignment, early return and mutually-exclusive branches —
                    //   and, unlike the line-number checks above, it stays correct
                    //   when several statements share a line (e.g. macro expansions
                    //   or `free(p); p = malloc(); free(p);` on one line, which the
                    //   line tests mis-handled as both a false positive here and a
                    //   missed reassignment).
                    //   Alias (q = p; free(p); free(q)): the freed value does not
                    //   flow from the first arg to the second, so fall back to the
                    //   line-based safety checks for that rarer shape.
                    val isSamePtr = firstPtr == secondPtr
                    val dataflowReaches =
                      try { secondFree.argument(1).reachableBy(firstFree.argument(1)).nonEmpty }
                      catch { case _: Throwable => false }
                    val isDoubleFree =
                      if (isSamePtr) dataflowReaches
                      else (!hasRealloc && !hasReassignment && !hasEarlyExit && !inDifferentBranches)

                    // Only report if it's a genuine double-free and first-free not already paired
                    val pairKey = s"$firstPtr:$firstFile:$firstLine"
                    if (isDoubleFree && !pairedFirstFrees.contains(pairKey)) {
                      val flowType = if (firstPtr == secondPtr) "same-ptr" else s"alias($secondPtr=$firstPtr)"
                      doubleFreeIssues += ((firstFile, methodName, firstPtr, firstLine, firstCode, secondLine, secondCode, flowType))
                      pairedFirstFrees += pairKey
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    
    // === Interprocedural: Check for frees across function calls ===
    freeCallsFiltered.foreach { freeCall =>
      val freeFile = freeCall.file.name.headOption.getOrElse("unknown")
      val freeLine = freeCall.lineNumber.getOrElse(-1)
      val freeCode = freeCall.code
      val method = freeCall.method
      val methodName = method.name
      
      val args = freeCall.astChildren.isIdentifier.l
      args.headOption.foreach { ptrNode =>
        val freedPtr = ptrNode.code.trim
        
        if (!freedPtr.contains("(") && !freedPtr.contains("[") && freedPtr.length < 50) {
          val callsAfterFree = method.call.l.filter { call =>
            val callLine = call.lineNumber.getOrElse(-1)
            callLine > freeLine &&
            !call.name.matches("free|cfree") &&
            call.argument.code.l.exists(_ == freedPtr)
          }
          
          callsAfterFree.foreach { callerCall =>
            val calleeName = callerCall.name
            
            val calleeMethods = cpg.method.name(calleeName).l
            calleeMethods.foreach { calleeMethod =>
              val calleeFreeCalls = calleeMethod.call.name("free|cfree").l
              
              if (calleeFreeCalls.nonEmpty) {
                val argIndex = callerCall.argument.code.l.indexOf(freedPtr)
                if (argIndex >= 0) {
                  val params = calleeMethod.parameter.l
                  if (argIndex < params.size) {
                    val paramName = params(argIndex).name
                    
                    calleeFreeCalls.foreach { calleeFree =>
                      val calleeFreeArgs = calleeFree.astChildren.isIdentifier.l
                      calleeFreeArgs.headOption.foreach { cfArg =>
                        if (cfArg.code.trim == paramName) {
                          val calleeFreeLine = calleeFree.lineNumber.getOrElse(-1)
                          val calleeFreeFile = calleeFree.file.name.headOption.getOrElse("?")
                          doubleFreeIssues += ((
                            freeFile,
                            methodName,
                            freedPtr,
                            freeLine,
                            freeCode,
                            calleeFreeLine,
                            s"${calleeFree.code} [in $calleeName() at $calleeFreeFile:$calleeFreeLine]",
                            "interprocedural"
                          ))
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    
    // Deduplicate and output
    val uniqueIssues = doubleFreeIssues.toList.distinctBy(i => (i._3, i._4, i._6))
    
    if (uniqueIssues.isEmpty) {
      output.append("No potential Double-Free issues detected.\n")
      output.append("\nNote: This analysis checks for:\n")
      output.append("  - Multiple free() on the same pointer in the same function\n")
      output.append("  - Pointer aliasing (p2 = ptr; free(ptr); free(p2))\n")
      output.append("  - Interprocedural double-free via function calls\n")
      output.append("\nFiltered out:\n")
      output.append("  - Frees in different if/else branches\n")
      output.append("  - Frees with intervening reallocation or reassignment\n")
      output.append("  - Frees with early return between them\n")
    } else {
      output.append(s"Found ${uniqueIssues.size} potential Double-Free issue(s):\n\n")
      
      uniqueIssues.take(maxResults).zipWithIndex.foreach { case ((file, methodName, ptr, firstLine, firstCode, secondLine, secondCode, flowType), idx) =>
        // Compute confidence based on flow type
        val baseConfidence = flowType match {
          case "same-ptr" => "HIGH"
          case "interprocedural" => "HIGH"
          case other if other.startsWith("alias") => "MEDIUM"
          case _ => "MEDIUM"
        }

        // Check reachability from external input
        val entryPoint = findEntryPoint(methodName)
        val reachable = entryPoint.isDefined
        val confidence = if (reachable && baseConfidence == "MEDIUM") "HIGH" else baseConfidence

        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence: $confidence\n")
        output.append(s"Pointer: $ptr\n")
        output.append(s"Location: $file in $methodName()\n\n")
        output.append(s"First Free:  [$file:$firstLine] $firstCode\n")
        output.append(s"Second Free: [$file:$secondLine] $secondCode\n")

        val flowTag = flowType match {
          case "same-ptr" => ""
          case "interprocedural" => " [CROSS-FUNC]"
          case other if other.startsWith("alias") => s" [$other]"
          case _ => ""
        }
        if (flowTag.nonEmpty) {
          output.append(s"Flow Type:$flowTag\n")
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
      
      if (uniqueIssues.size > maxResults) {
        output.append(s"(Showing $maxResults of ${uniqueIssues.size} issues. Increase limit to see more.)\n\n")
      }
      
      output.append(s"Total: ${uniqueIssues.size} potential Double-Free issue(s) found\n")
    }
  }
  
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
