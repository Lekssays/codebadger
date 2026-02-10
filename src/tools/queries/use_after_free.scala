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
    * Returns Some(entry_function_name) if reachable, None otherwise.
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

  output.append("Use-After-Free Analysis (Deep Interprocedural)\n")
  output.append("=" * 60 + "\n\n")
  
  // Find all free() calls (and common variants)
  val freeCalls = cpg.call.name("free|cfree|g_free|xmlFree|xsltFree.*").l
  
  val freeCallsFiltered = if (fileFilter.nonEmpty) {
    freeCalls.filter(_.file.name.headOption.exists(f => f.contains(fileFilter) || f.endsWith(fileFilter)))
  } else {
    freeCalls
  }
  
  if (freeCallsFiltered.isEmpty) {
    output.append("No free() calls found in the codebase.\n")
  } else {
    output.append(s"Found ${freeCallsFiltered.size} free() call site(s). Analyzing with deep interprocedural flow...\n\n")
    
    // Store UAF issues
    val uafIssues = mutable.ListBuffer[(String, Int, String, String, String, List[(Int, String, String, String, String)])]()
    
    freeCallsFiltered.foreach { freeCall =>
      val freeFile = freeCall.file.name.headOption.getOrElse("unknown")
      val freeLine = freeCall.lineNumber.getOrElse(-1)
      val freeCode = freeCall.code
      val methodName = freeCall.method.name
      
      val args = freeCall.astChildren.isIdentifier.l
      val freedPtrOpt = args.headOption
      
      freedPtrOpt.foreach { freedPtrNode =>
        val freedPtr = freedPtrNode.code.trim
        
        if (!freedPtr.contains("(") && !freedPtr.contains("[") && freedPtr.length < 50) {
          val method = freeCall.method
          val postFreeUsages = mutable.ListBuffer[(Int, String, String, String, String)]()
          
          // Track reassignments
          val reassignmentLines = mutable.Set[Int]()
          method.assignment.l.foreach { assign =>
            val assignLine = assign.lineNumber.getOrElse(-1)
            if (assignLine > freeLine && assign.target.code == freedPtr) {
              reassignmentLines += assignLine
            }
          }
          
          // === PHASE 1: Intraprocedural usages (same method) ===
          method.call.l.foreach { call =>
            val callLine = call.lineNumber.getOrElse(-1)
            if (callLine > freeLine && !call.name.matches("free|cfree|g_free|xmlFree|xsltFree.*")) {
              val reassignedBefore = reassignmentLines.exists(rl => rl > freeLine && rl < callLine)
              
              // Check for early return between free and usage
              // Note: return statements are Return nodes in Joern's CPG, not Call nodes
              val hasEarlyReturn = method.ast.isReturn.l.exists { ret =>
                val retLine = ret.lineNumber.getOrElse(-1)
                retLine > freeLine && retLine < callLine
              }
              
              // Check if free and usage are in mutually exclusive if/else branches
              val inDifferentBranches = areInMutuallyExclusiveBranches(method, freeLine, callLine)

              if (!reassignedBefore && !hasEarlyReturn && !inDifferentBranches) {
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
          
          if (aliases.size > 1) {
            val aliasesWithoutOriginal = aliases - freedPtr
            aliasesWithoutOriginal.foreach { alias =>
              val aliasReassigned = method.assignment.l.exists { assign =>
                assign.lineNumber.getOrElse(-1) > freeLine && assign.target.code == alias
              }
              if (!aliasReassigned) {
                method.call.l.foreach { call =>
                  val callLine = call.lineNumber.getOrElse(-1)
                  if (callLine > freeLine && !call.name.matches("free|cfree|g_free|xmlFree|xsltFree.*")) {
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
            // Find usages of identifiers with the same name across the codebase
            // These could be parameters in callees that receive the freed pointer
            val sameNameUsages = cpg.identifier.name(freedPtr).l
              .filter { id =>
                val idLine = id.lineNumber.getOrElse(-1)
                val idFile = id.file.name.headOption.getOrElse("")
                // Skip usages in the same method at/before the free
                !(idFile == freeFile && id.method.name == methodName && idLine <= freeLine)
              }
              .take(100)
              .collect { case cfgNode: CfgNode => cfgNode }
            
            if (sameNameUsages.nonEmpty) {
              try {
                val flows = sameNameUsages.reachableByFlows(sources).l.take(5)
                
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
                case _: Exception => // Ignore dataflow errors
              }
            }
          }
          
          val uniqueUsages = postFreeUsages.toList.distinct.sortBy(_._1)
          if (uniqueUsages.nonEmpty) {
            uafIssues += ((freeFile, freeLine, freeCode, freedPtr, methodName, uniqueUsages))
          }
        }
      }
    }
    
    if (uafIssues.isEmpty) {
      output.append("No potential Use-After-Free issues detected.\n")
      output.append("\nNote: This analysis includes:\n")
      output.append("  - Intraprocedural usages (same function)\n")
      output.append("  - Pointer aliasing (p2 = ptr; free(ptr); use(p2))\n")
      output.append("  - Deep interprocedural flow (multi-level call chains)\n")
    } else {
      output.append(s"Found ${uafIssues.size} potential UAF issue(s):\n\n")
      
      uafIssues.take(maxResults).zipWithIndex.foreach { case ((freeFile, freeLine, freeCode, freedPtr, methodName, usages), idx) =>
        // Compute confidence based on flow types present
        val hasDirectDeref = usages.exists(u => u._5 == "direct")
        val hasConfirmedInterproc = usages.exists(u => u._5 == "interproc" || u._5 == "deep-interproc")
        val hasAliasOnly = usages.forall(u => u._5.startsWith("alias"))
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
            case other if other.startsWith("alias") => s" [$other]"
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
      output.append("  - alias(X): Usage of pointer alias X after original freed\n")
      output.append("  - [CROSS-FUNC]: Usage in directly called function\n")
      output.append("  - [DEEP]: Usage across multiple function call levels\n")
    }
  }
  
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
