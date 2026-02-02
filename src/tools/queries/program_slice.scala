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
            val dataDepsList = mutable.ListBuffer[(Int, String, String, List[String])]()
            
            def backwardTrace(varName: String, beforeLine: Int, depth: Int): Unit = {
              if (depth <= 0 || visited.contains(s"$varName:$beforeLine")) return
              visited.add(s"$varName:$beforeLine")
              
              method.assignment
                .filter(a => a.lineNumber.getOrElse(0) > 0 && a.lineNumber.getOrElse(0) < beforeLine)
                .filter(a => a.target.code == varName || a.target.code.startsWith(varName + "[") || a.target.code.startsWith(varName + "->"))
                .l
                .foreach { assign =>
                  val rhsVars = assign.source.ast.isIdentifier.name.l.distinct.filter(_ != varName)
                  dataDepsList += ((assign.lineNumber.getOrElse(-1), varName, assign.code, rhsVars))
                  rhsVars.foreach(v => backwardTrace(v, assign.lineNumber.getOrElse(0), depth - 1))
                }
            }
            
            argVars.foreach(v => backwardTrace(v, targetLine, maxDepth))
            
            val sortedDeps = dataDepsList.toList.sortBy(_._1)
            val backwardCount = sortedDeps.size
            
            output.append(s"\n[BACKWARD SLICE] (${backwardCount} data dependencies)\n")
            
            if (sortedDeps.nonEmpty) {
              output.append("\n  Data Dependencies:\n")
              sortedDeps.foreach { case (line, varName, code, deps) =>
                val lineInfo = if (line != -1) s"[L$line]" else "[Local]"
                output.append(s"    $lineInfo $varName: $code\n")
                if (deps.nonEmpty) output.append(s"      <- depends on: ${deps.mkString(", ")}\n")
              }
            }
            
            // Control dependencies
            if (includeControlFlow) {
              val controlDeps = method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > 0 && c.lineNumber.getOrElse(0) < targetLine)
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse(ctrl.code.take(60))))
                .l.take(30)
              
              if (controlDeps.nonEmpty) {
                output.append("\n  Control Dependencies:\n")
                controlDeps.foreach { case (line, ctrlType, cond) =>
                  output.append(s"    [L$line] $ctrlType: $cond\n")
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
            val propagationsList = mutable.ListBuffer[(Int, String, String, String)]()
            
            def forwardTrace(varName: String, afterLine: Int, depth: Int): Unit = {
              if (depth <= 0 || forwardVisited.contains(s"$varName:$afterLine")) return
              forwardVisited.add(s"$varName:$afterLine")
              
              method.call
                .filter(c => c.lineNumber.getOrElse(0) > afterLine)
                .filter(c => c.argument.code.l.exists(_.contains(varName)))
                .l.take(15)
                .foreach { call =>
                  propagationsList += ((call.lineNumber.getOrElse(-1), "usage", varName, call.code))
                }
              
              method.assignment
                .filter(a => a.lineNumber.getOrElse(0) > afterLine)
                .filter(a => a.source.code.contains(varName))
                .l.take(15)
                .foreach { assign =>
                  val targetVar = assign.target.code
                  propagationsList += ((assign.lineNumber.getOrElse(-1), "propagation", varName, assign.code))
                  if (targetVar != varName) forwardTrace(targetVar, assign.lineNumber.getOrElse(0), depth - 1)
                }
            }
            
            resultVars.foreach(v => forwardTrace(v, targetLine, maxDepth))
            
            val sortedProps = propagationsList.toList.sortBy(_._1).distinct
            val forwardCount = sortedProps.size
            
            output.append(s"\n[FORWARD SLICE] (${forwardCount} propagations)\n")
            
            if (resultVars.nonEmpty) {
              output.append(s"  Result stored in: ${resultVars.mkString(", ")}\n")
            }
            
            if (sortedProps.nonEmpty) {
              output.append("\n  Propagations:\n")
              sortedProps.foreach { case (line, propType, varName, code) =>
                output.append(s"    [L$line] $propType ($varName): $code\n")
              }
            }
            
            // Control flow affected
            if (includeControlFlow) {
              val controlAffected = method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > targetLine)
                .filter(c => resultVars.exists(v => c.condition.code.headOption.getOrElse("").contains(v)))
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse("")))
                .l.take(20)
              
              if (controlAffected.nonEmpty) {
                output.append("\n  Control Flow Affected:\n")
                controlAffected.foreach { case (line, ctrlType, cond) =>
                  output.append(s"    [L$line] $ctrlType: $cond\n")
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
