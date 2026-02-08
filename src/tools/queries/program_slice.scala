{
  import scala.collection.mutable
  
  def normalizeFilename(path: String, target: String): Boolean = {
    def toPath(p: String) = p.replaceAll("\\\\", "/")
    val p = toPath(path)
    val t = toPath(target)
    p == t || p.endsWith("/" + t) || t.endsWith("/" + p)
  }

  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  val callName = "{{call_name}}"
  val maxDepth = {{max_depth}}
  val includeBackward = {{include_backward}}
  val includeForward = {{include_forward}}
  val includeControlFlow = {{include_control_flow}}
  val direction = "{{direction}}"
  
  val output = new StringBuilder()
  
  // Find target method
  val targetMethodOpt = cpg.method
    .filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename))
    .filterNot(_.name == "\u003cglobal\u003e")
    .filter(m => {
      val start = m.lineNumber.getOrElse(-1)
      val end = m.lineNumberEnd.getOrElse(-1)
      start <= lineNum && end >= lineNum
    })
    .headOption
  
  targetMethodOpt match {
    case Some(method) => {
      // Find target call
      val targetCallOpt = {
        val callsOnLine = method.call.filter(c => c.lineNumber.getOrElse(-1) == lineNum).l
        if (callName.nonEmpty && callsOnLine.nonEmpty) {
          callsOnLine.filter(_.name == callName).headOption
        } else if (callsOnLine.nonEmpty) {
          callsOnLine.filterNot(_.name.startsWith("<operator>")).headOption.orElse(callsOnLine.headOption)
        } else {
          None
        }
      }
      
      targetCallOpt match {
        case Some(targetCall) => {
          val targetLine = targetCall.lineNumber.getOrElse(lineNum)
          val argVars = targetCall.argument.ast.isIdentifier.name.l.distinct
          val targetFile = targetCall.file.name.headOption.getOrElse("unknown")
          
          // Header
          output.append(s"Program Slice for ${targetCall.name} at $targetFile:$targetLine\n")
          output.append("=" * 60 + "\n")
          output.append(s"Code: ${targetCall.code}\n")
          output.append(s"Method: ${method.fullName}\n")
          val args = targetCall.argument.code.l
          if (args.nonEmpty) output.append(s"Arguments: ${args.mkString(", ")}\n")
          
          // === BACKWARD SLICE ===
          if (includeBackward) {
            val visited = mutable.Set[String]()
            val dataDepsList = mutable.ListBuffer[(Int, String, String, String, List[String])]()
            
            // Define recursive function with explicit method context
            def backwardTrace(currMethod: io.shiftleft.codepropertygraph.generated.nodes.Method, 
                              varName: String, 
                              beforeLine: Int, 
                              depth: Int): Unit = {
                              
              val methodId = currMethod.fullName
              val uniqueId = s"$methodId:$varName:$beforeLine"
              
              if (depth <= 0 || visited.contains(uniqueId)) return
              visited.add(uniqueId)
              
              // 1. Local Assignments in current method
              currMethod.assignment
                .filter(a => a.lineNumber.getOrElse(0) > 0 && a.lineNumber.getOrElse(0) < beforeLine)
                .filter(a => a.target.code == varName || a.target.code.startsWith(varName + "[") || a.target.code.startsWith(varName + "->"))
                .l
                .foreach { assign =>
                  val rhsVars = assign.source.ast.isIdentifier.name.l.distinct.filter(_ != varName)
                  val assignFile = assign.file.name.headOption.getOrElse("unknown")
                  dataDepsList += ((assign.lineNumber.getOrElse(-1), assignFile, varName, assign.code, rhsVars))
                  rhsVars.foreach(v => backwardTrace(currMethod, v, assign.lineNumber.getOrElse(0), depth - 1))
                }
                
              // 2. Inter-procedural: If varName is a parameter, trace to Callers
              val params = currMethod.parameter.filter(_.name == varName).l
              if (params.nonEmpty) {
                params.foreach { param =>
                  // Check all calls to this method
                  currMethod.callIn.foreach { call =>
                     val callerMethod = call.method
                     // Find argument at the same index
                     call.argument.filter(_.argumentIndex == param.order).foreach { arg =>
                       val argVars = arg.ast.isIdentifier.name.l.distinct
                       if (argVars.nonEmpty) {
                         val callFile = call.file.name.headOption.getOrElse("unknown")
                         val callLine = call.lineNumber.getOrElse(-1)
                         dataDepsList += ((callLine, callFile, varName, s"Passed as arg to ${currMethod.name}", argVars))
                         // Recurse into caller
                         argVars.foreach(v => backwardTrace(callerMethod, v, callLine, depth - 1))
                       }
                     }
                  }
                }
              }
            }
            
            argVars.foreach(v => backwardTrace(method, v, targetLine, maxDepth))
            
            val sortedDeps = dataDepsList.toList.distinct.sortBy(_._1)
            val backwardCount = sortedDeps.size
            
            output.append(s"\n[BACKWARD SLICE] (${backwardCount} data dependencies)\n")
            
            if (sortedDeps.nonEmpty) {
              output.append("\n  Data Dependencies:\n")
              // Group by file for better readability
              sortedDeps.groupBy(_._2).foreach { case (file, deps) =>
                 output.append(s"  File: $file\n")
                 deps.sortBy(_._1).foreach { case (line, _, varName, code, deps) =>
                   val lineInfo = if (line != -1) s"[$line]" else "[Local]"
                   output.append(s"    $lineInfo $varName: $code\n")
                   if (deps.nonEmpty) output.append(s"      <- depends on: ${deps.mkString(", ")}\n")
                 }
              }
            }
            
            // Control dependencies (Local only for now to avoid explosion, or could trace back)
            if (includeControlFlow) {
               // We only show control deps for the target method to keep it readable
              val controlDeps = method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > 0 && c.lineNumber.getOrElse(0) < targetLine)
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.file.name.headOption.getOrElse("unknown"), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse(ctrl.code.take(60))))
                .l.distinct.take(30)
              
              if (controlDeps.nonEmpty) {
                output.append("\n  Control Dependencies (Target Method):\n")
                controlDeps.foreach { case (line, file, ctrlType, cond) =>
                  output.append(s"    [$file:$line] $ctrlType: $cond\n")
                }
              }
            }
            
            // Parameters used
            val params = method.parameter.filter(p => argVars.contains(p.name)).l
            if (params.nonEmpty) {
              val paramStr = params.map(p => s"${p.name} (${p.typeFullName})").mkString(", ")
              output.append(s"\n  Parameters: $paramStr\n")
            }
          }
          
          // === FORWARD SLICE ===
          if (includeForward) {
            val resultVars = method.assignment
              .filter(a => a.lineNumber.getOrElse(0) == targetLine)
              .filter(a => a.source.code.contains(targetCall.name))
              .target.code.l.distinct
            
            val forwardVisited = mutable.Set[String]()
            val propagationsList = mutable.ListBuffer[(Int, String, String, String, String)]()
            
            def forwardTrace(currMethod: io.shiftleft.codepropertygraph.generated.nodes.Method, 
                             varName: String, 
                             afterLine: Int, 
                             depth: Int): Unit = {
                             
              val methodId = currMethod.fullName
              val uniqueId = s"$methodId:$varName:$afterLine"
              
              if (depth <= 0 || forwardVisited.contains(uniqueId)) return
              forwardVisited.add(uniqueId)
              
              // 1. Local Usage & Propagation
              // usages in calls
              currMethod.call
                .filter(c => c.lineNumber.getOrElse(0) > afterLine)
                .filter(c => c.argument.code.l.exists(_.contains(varName)))
                .l.take(15)
                .foreach { call =>
                  val callFile = call.file.name.headOption.getOrElse("unknown")
                  propagationsList += ((call.lineNumber.getOrElse(-1), callFile, "usage", varName, call.code))
                  
                  // 2. Inter-procedural: If passed to a call, trace into Callee
                  call.argument.filter(_.code.contains(varName)).foreach { arg =>
                     call.callee.foreach { calleeMethod =>
                        // partial match on index
                        calleeMethod.parameter.filter(_.order == arg.argumentIndex).foreach { param =>
                            val paramName = param.name
                            propagationsList += ((calleeMethod.lineNumber.getOrElse(-1), calleeMethod.file.name.headOption.getOrElse("unknown"), "passed_to_func", varName, s"Passed to ${calleeMethod.name} as $paramName"))
                            forwardTrace(calleeMethod, paramName, calleeMethod.lineNumber.getOrElse(0), depth - 1)
                        }
                     }
                  }
                }
              
              // assignments
              currMethod.assignment
                .filter(a => a.lineNumber.getOrElse(0) > afterLine)
                .filter(a => a.source.code.contains(varName))
                .l.take(15)
                .foreach { assign =>
                  val targetVar = assign.target.code
                  val assignFile = assign.file.name.headOption.getOrElse("unknown")
                  propagationsList += ((assign.lineNumber.getOrElse(-1), assignFile, "propagation", varName, assign.code))
                  if (targetVar != varName) forwardTrace(currMethod, targetVar, assign.lineNumber.getOrElse(0), depth - 1)
                }
            }
            
            resultVars.foreach(v => forwardTrace(method, v, targetLine, maxDepth))
            
            val sortedProps = propagationsList.toList.distinct.sortBy(_._1)
            val forwardCount = sortedProps.size
            
            output.append(s"\n[FORWARD SLICE] (${forwardCount} propagations)\n")
            
            if (resultVars.nonEmpty) {
              output.append(s"  Result stored in: ${resultVars.mkString(", ")}\n")
            }
            
            if (sortedProps.nonEmpty) {
              output.append("\n  Propagations:\n")
               sortedProps.groupBy(_._2).foreach { case (file, props) =>
                 output.append(s"  File: $file\n")
                 props.sortBy(_._1).foreach { case (line, _, propType, varName, code) =>
                   output.append(s"    [$line] $propType ($varName): $code\n")
                 }
               }
            }
            
            // Control flow affected (Target Method only)
            if (includeControlFlow) {
              val controlAffected = method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > targetLine)
                .filter(c => resultVars.exists(v => c.condition.code.headOption.getOrElse("").contains(v)))
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.file.name.headOption.getOrElse("unknown"), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse("")))
                .l.distinct.take(20)
              
              if (controlAffected.nonEmpty) {
                output.append("\n  Control Flow Affected (Target Method):\n")
                controlAffected.foreach { case (line, file, ctrlType, cond) =>
                  output.append(s"    [$file:$line] $ctrlType: $cond\n")
                }
              }
            }
          }
        }
        case None => {
          // Diagnostic info about what calls exist on this line
          val callsOnLine = method.call.filter(c => c.lineNumber.getOrElse(-1) == lineNum).l
          val callNames = callsOnLine.map(_.name).distinct
          output.append(s"ERROR: No call '${if (callName.nonEmpty) callName else "<any>"}' found on line $lineNum in method ${method.name}\n")
          if (callNames.nonEmpty) {
            output.append(s"Available calls on line $lineNum: ${callNames.mkString(", ")}\n")
          } else {
            output.append(s"No calls found on line $lineNum in this method.\n")
            val nearbyLines = method.call.lineNumber.l.filter(l => Math.abs(l - lineNum) <= 5).distinct.sorted
            if (nearbyLines.nonEmpty) output.append(s"Nearby lines with calls: ${nearbyLines.mkString(", ")}\n")
          }
        }
      }
    }
    case None => {
      // Diagnostic info about available files
      val allFiles = cpg.file.name.l.distinct.take(20)
      val matchingFiles = cpg.file.name.l.filter(f => f.contains(filename) || filename.split("/").lastOption.exists(f.endsWith(_))).distinct.take(10)
      val methodsInFile = cpg.method.filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename)).filterNot(_.name == "\u003cglobal\u003e").l.take(10)
      
      output.append(s"ERROR: No method found containing line $lineNum in '$filename'\n\n")
      
      if (matchingFiles.nonEmpty) {
        output.append(s"Matching files in CPG:\n")
        matchingFiles.foreach(f => output.append(s"  - $f\n"))
      }
      
      if (methodsInFile.nonEmpty) {
        output.append(s"\nMethods in matching file(s):\n")
        methodsInFile.foreach { m =>
          output.append(s"  - ${m.name}: lines ${m.lineNumber.getOrElse(-1)}-${m.lineNumberEnd.getOrElse(-1)}\n")
        }
      }
      
      if (matchingFiles.isEmpty && methodsInFile.isEmpty) {
        output.append(s"Sample files in CPG (first 5):\n")
        allFiles.take(5).foreach(f => output.append(s"  - $f\n"))
      }
    }
  }
  
  // Return with markers for easy extraction
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}

