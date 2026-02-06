{
  val methodName = "{{method_name}}"
  val maxDepth = {{depth}}
  val direction = "{{direction}}"
  val maxResults = 500

  val output = new StringBuilder()
  
  val rootMethodOpt = cpg.method.name(methodName).headOption

  rootMethodOpt match {
    case Some(rootMethod) => {
      val rootName = rootMethod.name
      val rootFile = rootMethod.file.name.headOption.getOrElse("unknown")
      val rootLine = rootMethod.lineNumber.getOrElse(-1)
      
      // Header
      output.append(s"Call Graph for $rootName ($direction)\n")
      output.append("=" * 60 + "\n")
      output.append(s"Root: $rootName at $rootFile:$rootLine\n")
      
      if (direction == "outgoing") {
        // BFS for outgoing calls (callees)
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String)]()
        val edgesByDepth = scala.collection.mutable.Map[Int, scala.collection.mutable.ListBuffer[(String, String, String, Int, Boolean)]]()

        toVisit.enqueue((rootMethod, 0))
        var totalEdges = 0

        while (toVisit.nonEmpty && totalEdges < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name

          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName

            val callees = current.call.callee.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)

            for (callee <- callees) {
              val calleeName = callee.name
              val calleeFile = callee.file.name.headOption.getOrElse("unknown")
              val calleeLine = callee.lineNumber.getOrElse(-1)
              val depth = currentDepth + 1
              val edgeKey = (currentName, calleeName)
              val isCycle = visited.contains(calleeName)

              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                totalEdges += 1

                if (!edgesByDepth.contains(depth)) {
                  edgesByDepth(depth) = scala.collection.mutable.ListBuffer()
                }
                edgesByDepth(depth) += ((currentName, calleeName, calleeFile, calleeLine, isCycle))

                if (!isCycle && depth < maxDepth) {
                  toVisit.enqueue((callee, depth))
                }
              }
            }
          }
        }

        // Output edges grouped by depth
        val cycleCount = edgesByDepth.values.flatten.count(_._5)
        for (depth <- edgesByDepth.keys.toList.sorted) {
          output.append(s"\n[DEPTH $depth]\n")
          for ((from, to, file, line, isCycle) <- edgesByDepth(depth)) {
            val location = if (line > 0) s"$file:$line" else file
            val tag = if (isCycle) " [CYCLE]" else ""
            output.append(s"  $from → $to ($location)$tag\n")
          }
        }

        output.append(s"\nTotal: $totalEdges edges")
        if (cycleCount > 0) output.append(s" ($cycleCount cyclic)")
        output.append("\n")
        
      } else if (direction == "incoming") {
        // BFS for incoming calls (callers)
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String)]()
        val edgesByDepth = scala.collection.mutable.Map[Int, scala.collection.mutable.ListBuffer[(String, String, String, Int, Boolean)]]()

        // Initial: find direct callers of root method
        visited = visited + rootName
        val directCallers = rootMethod.caller.l.filterNot(_.name.startsWith("<operator>"))
        for (caller <- directCallers) {
          val callerName = caller.name
          val callerFile = caller.file.name.headOption.getOrElse("unknown")
          val callerLine = caller.lineNumber.getOrElse(-1)
          val edgeKey = (callerName, rootName)
          val isCycle = visited.contains(callerName)

          if (!edgesVisited.contains(edgeKey)) {
            edgesVisited = edgesVisited + edgeKey

            if (!edgesByDepth.contains(1)) {
              edgesByDepth(1) = scala.collection.mutable.ListBuffer()
            }
            edgesByDepth(1) += ((callerName, rootName, callerFile, callerLine, isCycle))

            if (!isCycle) {
              toVisit.enqueue((caller, 1))
            }
          }
        }

        var totalEdges = edgesVisited.size

        while (toVisit.nonEmpty && totalEdges < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name

          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName

            val incomingCallers = current.caller.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)

            for (caller <- incomingCallers) {
              val callerName = caller.name
              val callerFile = caller.file.name.headOption.getOrElse("unknown")
              val callerLine = caller.lineNumber.getOrElse(-1)
              val depth = currentDepth + 1
              val edgeKey = (callerName, currentName)
              val isCycle = visited.contains(callerName)

              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                totalEdges += 1

                if (!edgesByDepth.contains(depth)) {
                  edgesByDepth(depth) = scala.collection.mutable.ListBuffer()
                }
                edgesByDepth(depth) += ((callerName, currentName, callerFile, callerLine, isCycle))

                if (!isCycle && depth < maxDepth) {
                  toVisit.enqueue((caller, depth))
                }
              }
            }
          }
        }

        // Output edges grouped by depth
        val cycleCount = edgesByDepth.values.flatten.count(_._5)
        for (depth <- edgesByDepth.keys.toList.sorted) {
          output.append(s"\n[DEPTH $depth]\n")
          for ((from, to, file, line, isCycle) <- edgesByDepth(depth)) {
            val location = if (line > 0) s"$file:$line" else file
            val tag = if (isCycle) " [CYCLE]" else ""
            output.append(s"  $from → $to ($location)$tag\n")
          }
        }

        output.append(s"\nTotal: $totalEdges edges")
        if (cycleCount > 0) output.append(s" ($cycleCount cyclic)")
        output.append("\n")
        
      } else {
        output.append(s"ERROR: Direction must be 'outgoing' or 'incoming', got: '$direction'\n")
      }
    }
    case None => {
      output.append(s"ERROR: Method not found: $methodName\n")
      
      // Show similar method names as suggestions
      val similar = cpg.method.name(s".*$methodName.*").name.l.distinct.take(10)
      if (similar.nonEmpty) {
        output.append(s"\nDid you mean one of these?\n")
        similar.foreach(m => output.append(s"  - $m\n"))
      }
    }
  }
  
  // Return with markers for easy extraction
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
