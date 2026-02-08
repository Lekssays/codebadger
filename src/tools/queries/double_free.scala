{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable
  
  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}
  
  val output = new StringBuilder()
  
  output.append("Double-Free Detection Analysis\n")
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
        
        // Get all control structures to check for conditional branches
        val ifStatements = method.controlStructure.filter(_.controlStructureType == "IF").l
        
        // Sort by line number
        val sortedFreeCalls = methodFreeCalls.sortBy(_.lineNumber.getOrElse(0))
        
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
              
              // Track aliases of this pointer (assignments before the first free)
              val aliases = mutable.Set[String](firstPtr)
              method.assignment.l.foreach { assign =>
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
              val reallocCalls = method.call.name("malloc|calloc|realloc|strdup|xmlMalloc.*|g_malloc.*|xmlStrdup").l
              
              // Check remaining free calls for double-free
              sortedFreeCalls.drop(idx + 1).foreach { secondFree =>
                val secondLine = secondFree.lineNumber.getOrElse(-1)
                val secondCode = secondFree.code
                
                val secondArgs = secondFree.astChildren.isIdentifier.l
                secondArgs.headOption.foreach { secondPtrNode =>
                  val secondPtr = secondPtrNode.code.trim
                  
                  // Check if second free is on the same pointer or an alias
                  if (aliases.contains(secondPtr)) {
                    // Check if there's a reallocation between the two frees
                    val hasRealloc = reallocCalls.exists { realloc =>
                      val reallocLine = realloc.lineNumber.getOrElse(-1)
                      reallocLine > firstLine && reallocLine < secondLine &&
                      method.assignment.l.exists { assign =>
                        assign.lineNumber.getOrElse(-1) == reallocLine &&
                        aliases.contains(assign.target.code.trim)
                      }
                    }
                    
                    // Check if pointer is reassigned between the two frees
                    val hasReassignment = method.assignment.l.exists { assign =>
                      val assignLine = assign.lineNumber.getOrElse(-1)
                      assignLine > firstLine && assignLine < secondLine &&
                      aliases.contains(assign.target.code.trim)
                    }
                    
                    // Check if there's a return/goto between the two frees
                    val hasEarlyExit = method.call.name("return").l.exists { ret =>
                      val retLine = ret.lineNumber.getOrElse(-1)
                      retLine > firstLine && retLine < secondLine
                    }
                    
                    // Only report if not a safe pattern
                    if (!hasRealloc && !hasReassignment && !hasEarlyExit) {
                      val flowType = if (firstPtr == secondPtr) "same-ptr" else s"alias($secondPtr=$firstPtr)"
                      doubleFreeIssues += ((firstFile, methodName, firstPtr, firstLine, firstCode, secondLine, secondCode, flowType))
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
            !call.name.matches("free|cfree|g_free|xmlFree|xsltFree.*") &&
            call.argument.code.l.exists(_ == freedPtr)
          }
          
          callsAfterFree.foreach { callerCall =>
            val calleeName = callerCall.name
            
            val calleeMethods = cpg.method.name(calleeName).l
            calleeMethods.foreach { calleeMethod =>
              val calleeFreeCalls = calleeMethod.call.name("free|cfree|g_free|xmlFree|xsltFree.*").l
              
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
        output.append(s"--- Issue ${idx + 1} ---\n")
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
