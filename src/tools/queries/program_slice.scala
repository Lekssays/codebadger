{
  import scala.collection.mutable
  
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
  }
  
  def normalizeFilename(path: String, filename: String): Boolean = {
    path.endsWith("/" + filename) || path == filename || path.endsWith(filename)
  }
  
  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  val useNodeId = {{use_node_id}}
  val nodeId = "{{node_id}}"
  val callName = "{{call_name}}"
  val maxDepth = {{max_depth}}
  val includeBackward = {{include_backward}}
  val includeForward = {{include_forward}}
  val includeControlFlow = {{include_control_flow}}
  
  // Find target method
  val targetMethodOpt = if (useNodeId && nodeId.nonEmpty) {
    cpg.call.id(nodeId.toLong).method.headOption
  } else {
    cpg.method
      .filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename))
      .filterNot(_.name == "\u003cglobal\u003e")
      .filter(m => {
        val start = m.lineNumber.getOrElse(-1)
        val end = m.lineNumberEnd.getOrElse(-1)
        start <= lineNum && end >= lineNum
      })
      .headOption
  }
  
  targetMethodOpt match {
    case Some(method) => {
      // Find target call
      val targetCallOpt = if (useNodeId && nodeId.nonEmpty) {
        cpg.call.id(nodeId.toLong).headOption
      } else {
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
          
          // === BACKWARD SLICE ===
          val backwardSlice = if (includeBackward) {
            val visited = mutable.Set[String]()
            val dataDepsList = mutable.ListBuffer[Map[String, Any]]()
            
            def backwardTrace(varName: String, beforeLine: Int, depth: Int): Unit = {
              if (depth <= 0 || visited.contains(s"$varName:$beforeLine")) return
              visited.add(s"$varName:$beforeLine")
              
              method.assignment
                .filter(a => a.lineNumber.getOrElse(0) > 0 && a.lineNumber.getOrElse(0) < beforeLine)
                .filter(a => a.target.code == varName || a.target.code.startsWith(varName + "[") || a.target.code.startsWith(varName + "->"))
                .l
                .foreach { assign =>
                  val rhsVars = assign.source.ast.isIdentifier.name.l.distinct.filter(_ != varName)
                  dataDepsList += Map(
                    "variable" -> varName,
                    "line" -> assign.lineNumber.getOrElse(-1),
                    "code" -> escapeJson(assign.code),
                    "depends_on" -> rhsVars
                  )
                  rhsVars.foreach(v => backwardTrace(v, assign.lineNumber.getOrElse(0), depth - 1))
                }
            }
            
            argVars.foreach(v => backwardTrace(v, targetLine, maxDepth))
            
            val controlDeps = if (includeControlFlow) {
              method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > 0 && c.lineNumber.getOrElse(0) < targetLine)
                .map(ctrl => Map(
                  "line" -> ctrl.lineNumber.getOrElse(-1),
                  "type" -> ctrl.controlStructureType,
                  "condition" -> escapeJson(ctrl.condition.code.headOption.getOrElse(ctrl.code.take(60)))
                ))
                .l.take(30)
            } else List()
            
            val params = method.parameter
              .filter(p => argVars.contains(p.name))
              .map(p => Map("name" -> p.name, "type" -> p.typeFullName, "position" -> p.index))
              .l
            
            val locals = method.local
              .filter(l => argVars.contains(l.name))
              .map(l => Map("name" -> l.name, "type" -> l.typeFullName, "line" -> l.lineNumber.getOrElse(-1)))
              .l
            
            Map(
              "data_dependencies" -> dataDepsList.toList.sortBy(_("line").asInstanceOf[Int]),
              "control_dependencies" -> controlDeps,
              "parameters" -> params,
              "locals" -> locals
            )
          } else Map[String, Any]()
          
          // === FORWARD SLICE ===
          val forwardSlice = if (includeForward) {
            val resultVars = method.assignment
              .filter(a => a.lineNumber.getOrElse(0) == targetLine)
              .filter(a => a.source.code.contains(targetCall.name))
              .target.code.l.distinct
            
            val forwardVisited = mutable.Set[String]()
            val propagationsList = mutable.ListBuffer[Map[String, Any]]()
            
            def forwardTrace(varName: String, afterLine: Int, depth: Int): Unit = {
              if (depth <= 0 || forwardVisited.contains(s"$varName:$afterLine")) return
              forwardVisited.add(s"$varName:$afterLine")
              
              method.call
                .filter(c => c.lineNumber.getOrElse(0) > afterLine)
                .filter(c => c.argument.code.l.exists(_.contains(varName)))
                .l.take(15)
                .foreach { call =>
                  propagationsList += Map(
                    "line" -> call.lineNumber.getOrElse(-1),
                    "code" -> escapeJson(call.code),
                    "type" -> "usage",
                    "variable" -> varName
                  )
                }
              
              method.assignment
                .filter(a => a.lineNumber.getOrElse(0) > afterLine)
                .filter(a => a.source.code.contains(varName))
                .l.take(15)
                .foreach { assign =>
                  val targetVar = assign.target.code
                  propagationsList += Map(
                    "line" -> assign.lineNumber.getOrElse(-1),
                    "code" -> escapeJson(assign.code),
                    "type" -> "propagation",
                    "variable" -> varName,
                    "propagates_to" -> targetVar
                  )
                  if (targetVar != varName) forwardTrace(targetVar, assign.lineNumber.getOrElse(0), depth - 1)
                }
            }
            
            resultVars.foreach(v => forwardTrace(v, targetLine, maxDepth))
            
            val controlAffected = if (includeControlFlow) {
              method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > targetLine)
                .filter(c => resultVars.exists(v => c.condition.code.headOption.getOrElse("").contains(v)))
                .map(ctrl => Map(
                  "line" -> ctrl.lineNumber.getOrElse(-1),
                  "type" -> ctrl.controlStructureType,
                  "condition" -> escapeJson(ctrl.condition.code.headOption.getOrElse(""))
                ))
                .l.take(20)
            } else List()
            
            Map(
              "result_variable" -> resultVars.headOption.getOrElse(""),
              "propagations" -> propagationsList.toList.sortBy(_("line").asInstanceOf[Int]).distinct,
              "control_affected" -> controlAffected
            )
          } else Map[String, Any]()
          
          // Build response
          Map(
            "success" -> true,
            "target" -> Map(
              "node_id" -> targetCall.id.toString,
              "name" -> targetCall.name,
              "code" -> escapeJson(targetCall.code),
              "file" -> escapeJson(targetCall.file.name.headOption.getOrElse("unknown")),
              "line" -> targetCall.lineNumber.getOrElse(-1),
              "method" -> escapeJson(method.fullName),
              "arguments" -> targetCall.argument.code.l
            ),
            "backward_slice" -> backwardSlice,
            "forward_slice" -> forwardSlice,
            "summary" -> Map(
              "direction" -> "{{direction}}",
              "max_depth" -> maxDepth,
              "backward_nodes" -> (if (includeBackward) backwardSlice.getOrElse("data_dependencies", List()).asInstanceOf[List[Any]].size + backwardSlice.getOrElse("control_dependencies", List()).asInstanceOf[List[Any]].size else 0),
              "forward_nodes" -> (if (includeForward) forwardSlice.getOrElse("propagations", List()).asInstanceOf[List[Any]].size + forwardSlice.getOrElse("control_affected", List()).asInstanceOf[List[Any]].size else 0)
            )
          )
        }
        case None => Map(
          "success" -> false,
          "error" -> Map("code" -> "CALL_NOT_FOUND", "message" -> s"No call found at $filename:$lineNum")
        )
      }
    }
    case None => Map(
      "success" -> false,
      "error" -> Map("code" -> "METHOD_NOT_FOUND", "message" -> s"No method found containing line $lineNum in $filename")
    )
  }
}.toJsonPretty
