{
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
  }

  val methodName = "{{method_name}}"
  val maxDepth = {{depth}}
  val direction = "{{direction}}"
  val maxResults = 500

  val rootMethodOpt = cpg.method.name(methodName).headOption

  val result = rootMethodOpt match {
    case Some(rootMethod) => {
      val rootName = rootMethod.name
      val allCalls = scala.collection.mutable.ListBuffer[Map[String, Any]]()
      
      if (direction == "outgoing") {
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String, Int)]()
        
        toVisit.enqueue((rootMethod, 0))
        
        while (toVisit.nonEmpty && allCalls.size < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name
          
          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName
            
            val callees = current.call.callee.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)
            
            for (callee <- callees) {
              val calleeName = callee.name
              val edgeKey = (currentName, calleeName, currentDepth + 1)
              
              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                allCalls += Map(
                  "from" -> currentName,
                  "to" -> escapeJson(calleeName),
                  "depth" -> (currentDepth + 1)
                )
                
                if (!visited.contains(calleeName) && currentDepth + 1 < maxDepth) {
                  toVisit.enqueue((callee, currentDepth + 1))
                }
              }
            }
          }
        }
        
        List(
          Map(
            "success" -> true,
            "root_method" -> rootName,
            "direction" -> direction,
            "calls" -> allCalls.toList.sortBy(c => (c.getOrElse("depth", 0).asInstanceOf[Int], c.getOrElse("from", "").asInstanceOf[String])),
            "total" -> allCalls.size
          )
        )
      } else if (direction == "incoming") {
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String, Int)]()
        
        val directCallers = rootMethod.caller.l.filterNot(_.name.startsWith("<operator>"))
        for (caller <- directCallers) {
          val edgeKey = (caller.name, rootName, 1)
          if (!edgesVisited.contains(edgeKey)) {
            edgesVisited = edgesVisited + edgeKey
            allCalls += Map(
              "from" -> escapeJson(caller.name),
              "to" -> rootName,
              "depth" -> 1
            )
            toVisit.enqueue((caller, 1))
          }
        }
        
        visited = visited + rootName
        
        while (toVisit.nonEmpty && allCalls.size < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name
          
          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName
            
            val incomingCallers = current.caller.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)
            
            for (caller <- incomingCallers) {
              val callerName = caller.name
              val edgeKey = (callerName, rootName, currentDepth + 1)
              
              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                allCalls += Map(
                  "from" -> escapeJson(callerName),
                  "to" -> rootName,
                  "depth" -> (currentDepth + 1)
                )
                
                if (!visited.contains(callerName) && currentDepth + 1 < maxDepth) {
                  toVisit.enqueue((caller, currentDepth + 1))
                }
              }
            }
          }
        }
        
        List(
          Map(
            "success" -> true,
            "root_method" -> rootName,
            "direction" -> direction,
            "calls" -> allCalls.toList.sortBy(c => (c.getOrElse("depth", 0).asInstanceOf[Int], c.getOrElse("from", "").asInstanceOf[String])),
            "total" -> allCalls.size
          )
        )
      } else {
        List(
          Map(
            "success" -> false,
            "error" -> Map(
              "code" -> "INVALID_DIRECTION",
              "message" -> s"Direction must be 'outgoing' or 'incoming', got: '$direction'"
            )
          )
        )
      }
    }
    case None => {
      List(
        Map(
          "success" -> false,
          "error" -> Map(
            "code" -> "METHOD_NOT_FOUND",
            "message" -> s"Method not found: $methodName"
          )
        )
      )
    }
  }

  result.toJsonPretty
}
