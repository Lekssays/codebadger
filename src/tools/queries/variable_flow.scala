{
  val targetLine = {{line_num}}
  val targetVar = "{{variable}}"
  val filename = "{{filename}}"
  val direction = "{{direction}}"
  val maxResults = 50

  val targetMethodOpt = cpg.method
    .filter(m => {
      val f = m.file.name.headOption.getOrElse("")
      f.endsWith(filename) || f.contains(filename)
    })
    .filterNot(_.name == "<global>")
    .filter(m => {
      val start = m.lineNumber.getOrElse(-1)
      val end = m.lineNumberEnd.getOrElse(-1)
      start <= targetLine && end >= targetLine
    })
    .headOption

  val result = targetMethodOpt match {
    case Some(method) => {
      val sb = new StringBuilder
      val methodName = method.name
      val methodFile = method.file.name.headOption.getOrElse("unknown")
      
      sb.append(s"Variable Flow Analysis\n")
      sb.append(s"======================\n")
      sb.append(s"Target: variable '$targetVar' at $filename:$targetLine\n")
      sb.append(s"Method: $methodName\n")
      sb.append(s"Direction: $direction\n")

      // 1. Identify Aliases
      // Find local variables that are assigned the address of targetVar (e.g. p = &x)
      val pointerAliases = method.assignment
        .filter(_.source.code.contains("&" + targetVar))
        .map(_.target.code)
        .l.distinct
        
      // Combined set of variables to track (target + aliases)
      val monitoredVars = (targetVar :: pointerAliases).distinct
      
      if (pointerAliases.nonEmpty) {
        sb.append(s"Aliases detected: ${pointerAliases.mkString(", ")}\n")
      }
      
      sb.append("\nDependencies:\n")

      // Helper to match code against monitored variables
      def isRelevant(code: String): Boolean = {
        monitoredVars.exists(v => 
          code == v || 
          code.startsWith(v + ".") || 
          code.startsWith(v + "[") || 
          code.startsWith("*" + v) || 
          code.startsWith(v + "->") ||
          code == "&" + v
        )
      }

      val dependencies = scala.collection.mutable.ListBuffer[(Int, String, String)]()

      if (direction == "backward") {
        // 0. Parameters
        method.parameter.nameExact(targetVar).l.foreach { param =>
           dependencies += ((param.lineNumber.getOrElse(-1), s"${param.typeFullName} ${param.name}", "parameter"))
        }

        // 1. Initializations (Declarations)
        method.local.nameExact(targetVar).l.foreach { local =>
          dependencies += ((local.lineNumber.getOrElse(-1), s"${local.typeFullName} ${local.code}", "initialization"))
        }

        // 2. Assignments
        method.assignment
          .filter(_.lineNumber.getOrElse(-1) <= targetLine)
          .filter(a => isRelevant(a.target.code) || a.target.code == targetVar) 
          .take(maxResults)
          .foreach { assign =>
             dependencies += ((assign.lineNumber.getOrElse(-1), assign.code, "assignment"))
          }

        // 3. Modifications (Inc/Dec)
        method.call
          .name("<operator>.(postIncrement|preIncrement|postDecrement|preDecrement|assignmentPlus|assignmentMinus|assignmentMultiplication|assignmentDivision)")
          .filter(_.lineNumber.getOrElse(-1) <= targetLine)
          .filter(c => c.argument.code.l.exists(isRelevant))
          .take(maxResults)
          .foreach { call =>
            dependencies += ((call.lineNumber.getOrElse(-1), call.code, "modification"))
          }
          
        // 4. Function Calls (Any usage in args, potential pass-by-ref or logic dependency)
        method.call
          .filter(_.lineNumber.getOrElse(-1) <= targetLine)
          .filter(c => c.argument.code.l.exists(arg => 
             // Argument contains variable name (relaxed from just &varName)
               monitoredVars.exists(v => arg.contains(v))
          ))
          .take(maxResults)
          .foreach { call =>
             dependencies += ((call.lineNumber.getOrElse(-1), call.code, "function_call"))
          }

      } else { // forward
        // 1. Usages
        method.call
          .filter(_.lineNumber.getOrElse(-1) >= targetLine)
          .filter(c => c.argument.code.l.exists(arg => isRelevant(arg) || arg.contains(targetVar)))
          .take(maxResults)
          .foreach { call =>
             dependencies += ((call.lineNumber.getOrElse(-1), call.code, "usage"))
          }

        // 2. Propagations (assignments where source involves var)
        method.assignment
          .filter(_.lineNumber.getOrElse(-1) >= targetLine)
          .filter(a => isRelevant(a.source.code) || a.source.code.contains(targetVar))
          .take(maxResults)
          .foreach { assign =>
             dependencies += ((assign.lineNumber.getOrElse(-1), assign.code, "propagation"))
          }
          
        // 3. Modifications (future)
         method.call
          .name("<operator>.(postIncrement|preIncrement|postDecrement|preDecrement|assignmentPlus|assignmentMinus|assignmentMultiplication|assignmentDivision)")
          .filter(_.lineNumber.getOrElse(-1) >= targetLine)
          .filter(c => c.argument.code.l.exists(isRelevant))
          .take(maxResults)
          .foreach { call =>
            dependencies += ((call.lineNumber.getOrElse(-1), call.code, "modification"))
          }
      }

      val sortedDeps = dependencies.sortBy(_._1)
      if (sortedDeps.isEmpty) {
        sb.append("(No dependencies found)\n")
      } else {
        // Deduplicate output based on line and code to clean up potential overlaps
        val uniqueDeps = sortedDeps.distinct
        uniqueDeps.foreach { case (line, code, typeName) =>
          sb.append(f"[Line $line%4d] $code ($typeName)\n")
        }
      }
      
      sb.toString()
    }
    case None => {
      s"Error: No method found containing line $targetLine in file '$filename'"
    }
  }

  // Return list containing string to be compatible with parsing logic
  List(result)
}
