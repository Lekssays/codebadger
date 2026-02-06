{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable
  
  val sourceFile = "{{source_file}}"
  val sourceLine = {{source_line}}
  val sinkFile = "{{sink_file}}"
  val sinkLine = {{sink_line}}
  val sourceNodeId = {{source_node_id}}L
  val sinkNodeId = {{sink_node_id}}L
  val maxResults = {{max_results}}
  
  val output = new StringBuilder()
  
  // Helper to get method name safely from any node
  def getMethodName(node: StoredNode): String = {
    node match {
      case c: Call => c.method.name
      case i: Identifier => i.method.name
      case l: Literal => l.method.name
      case m: MethodParameterIn => m.method.name
      case r: Return => r.method.name
      case b: Block => b.method.name
      case _ => "unknown"
    }
  }

  // Helper to get name safely
  def getName(node: StoredNode): String = {
     node match {
       case c: Call => c.name
       case i: Identifier => i.name
       case l: Literal => "literal" 
       case m: MethodParameterIn => m.name
       case _ => node.label
     }
  }
  
  // Build source nodes - by node ID or by location
  val sources: List[CfgNode] = {
    if (sourceNodeId > 0) {
      cpg.call.filter(_.id == sourceNodeId).l ++
      cpg.identifier.filter(_.id == sourceNodeId).l ++
      cpg.literal.filter(_.id == sourceNodeId).l
    } else if (sourceFile.nonEmpty && sourceLine > 0) {
      cpg.call.where(_.file.name(".*" + sourceFile + "$")).lineNumber(sourceLine).l ++
      cpg.identifier.where(_.file.name(".*" + sourceFile + "$")).lineNumber(sourceLine).l ++
      cpg.literal.where(_.file.name(".*" + sourceFile + "$")).lineNumber(sourceLine).l
    } else {
      List()
    }
  }
  
  // Build sink nodes - by node ID or by location
  val sinks: List[CfgNode] = {
    if (sinkNodeId > 0) {
      cpg.call.filter(_.id == sinkNodeId).l ++
      cpg.identifier.filter(_.id == sinkNodeId).l ++
      cpg.literal.filter(_.id == sinkNodeId).l
    } else if (sinkFile.nonEmpty && sinkLine > 0) {
      cpg.call.where(_.file.name(".*" + sinkFile + "$")).lineNumber(sinkLine).l ++
      cpg.identifier.where(_.file.name(".*" + sinkFile + "$")).lineNumber(sinkLine).l ++
      cpg.literal.where(_.file.name(".*" + sinkFile + "$")).lineNumber(sinkLine).l
    } else {
      List()
    }
  }

  // Expand sinks: If a sink is a function call, we usually mean "flow to any argument of this call"
  // e.g. sink = memcpy(...) -> we want to catch taint flowing into 'src' argument.
  val effectiveSinks: List[CfgNode] = sinks.flatMap {
    case c: Call => c :: c.argument.l
    case other => List(other)
  }
  
  // Header
  output.append("Taint Flow Analysis\n")
  output.append("=" * 60 + "\n")
  
  if (sources.nonEmpty) {
    val src = sources.head
    val srcFile = src.file.name.headOption.getOrElse("?")
    val srcLine = src.lineNumber.getOrElse(-1)
    output.append(s"Source: ${src.code.take(60)}\n")
    output.append(s"  Location: $srcFile:$srcLine\n")
    if (sourceNodeId > 0) output.append(s"  Node ID: $sourceNodeId\n")
  }
  
  if (sinks.nonEmpty) {
    val snk = sinks.head
    val snkFile = snk.file.name.headOption.getOrElse("?")
    val snkLine = snk.lineNumber.getOrElse(-1)
    output.append(s"Sink: ${snk.code.take(60)}\n")
    output.append(s"  Location: $snkFile:$snkLine\n")
    if (sinkNodeId > 0) output.append(s"  Node ID: $sinkNodeId\n")
  }
  
  output.append("\n")
  
  if (sources.isEmpty) {
    output.append("ERROR: No source found matching the criteria.\n")
    if (sourceFile.nonEmpty) {
      output.append(s"  Searched for calls at $sourceFile:$sourceLine\n")
    } else if (sourceNodeId > 0) {
      output.append(s"  Searched for node ID $sourceNodeId\n")
    }
  } else if (sinks.isEmpty) {
    output.append("ERROR: No sink found matching the criteria.\n")
    if (sinkFile.nonEmpty) {
      output.append(s"  Searched for calls at $sinkFile:$sinkLine\n")
    } else if (sinkNodeId > 0) {
      output.append(s"  Searched for node ID $sinkNodeId\n")
    }
  } else {
    // Use Joern's native reachableByFlows for taint tracking
    val flows = effectiveSinks.reachableByFlows(sources).l.take(maxResults)
    
    if (flows.isEmpty) {
      output.append("No taint flow found between source and sink.\n\n")
      
      // Diagnostic: Check if they're in the same file at least
      val srcFile = sources.head.file.name.headOption.getOrElse("")
      val snkFile = sinks.head.file.name.headOption.getOrElse("")
      
      if (srcFile != snkFile) {
        output.append("Note: Source and sink are in different files.\n")
        output.append("  Inter-procedural taint tracking requires call graph connection.\n")
      }
      
      // Show what we checked
      output.append("\nSource node:\n")
      val src = sources.head
      output.append(s"  ${getName(src)}: ${src.code}\n")
      output.append(s"  Method: ${getMethodName(src)}\n")
      
      output.append("\nSink node:\n")
      val snk = sinks.head
      output.append(s"  ${getName(snk)}: ${snk.code}\n")
      output.append(s"  Method: ${getMethodName(snk)}\n")

      // --- Fallback: Check for Call Graph Connection ---
      // If data flow is missing, maybe they are connected via function calls?
      val sourceMethods = sources.flatMap(_.method).dedup.l
      val sinkMethods = sinks.flatMap(_.method).dedup.l
      
      if (sourceMethods.nonEmpty && sinkMethods.nonEmpty) {
        val srcM = sourceMethods.head
        val snkM = sinkMethods.head
        
        if (srcM.fullName != snkM.fullName) {
          // Check if Source Method calls Sink Method (directly or indirectly)
          // Limit depth to avoid performance hit on large graphs
          // Use .start to turn Node into Traversal, and _.call.callee to jump Method -> Method
          val path = srcM.start.repeat(_.call.callee)(_.until(_.id(snkM.id)).maxDepth(5)).l
          
          if (path.nonEmpty) {
             output.append("\nPotential Call Path Found:\n")
             output.append("  (Data flow not detected, but functions are connected in call graph)\n")
             output.append(s"  ${srcM.name} -> ... -> ${snkM.name}\n")
             output.append("  This suggests an Inter-procedural flow is possible.\n")
          }
        }
      }
    } else {
      output.append(s"Found ${flows.size} taint flow(s):\n\n")
      
      flows.zipWithIndex.foreach { case (flow, idx) =>
        output.append(s"--- Flow ${idx + 1} ---\n")
        
        val elements = flow.elements.l
        if (elements.nonEmpty) {
          // Source (first element)
          val source = elements.head
          val srcFile = source.file.name.headOption.getOrElse("?")
          val srcLine = source.lineNumber.getOrElse(-1)
          val srcMethod = getMethodName(source)
          output.append(s"Source: ${source.code}\n")
          output.append(s"  Location: $srcFile:$srcLine in $srcMethod()\n")
          
          // Path elements (intermediate steps)
          if (elements.size > 2) {
            output.append(s"\nPath (${elements.size - 2} intermediate steps):\n")
            elements.slice(1, elements.size - 1).take(15).foreach { elem =>
              val elemFile = elem.file.name.headOption.getOrElse("?")
              val elemLine = elem.lineNumber.getOrElse(-1)
              val elemMethod = getMethodName(elem)
              val codeSnippet = elem.code.take(60).replaceAll("\n", " ")
              output.append(s"  [L$elemLine] $codeSnippet\n")
              output.append(s"           in $elemMethod() at $elemFile\n")
            }
            if (elements.size - 2 > 15) {
              output.append(s"  ... and ${elements.size - 17} more steps\n")
            }
          }
          
          // Sink (last element)
          val sink = elements.last
          val snkFile = sink.file.name.headOption.getOrElse("?")
          val snkLine = sink.lineNumber.getOrElse(-1)
          val snkMethod = getMethodName(sink)
          output.append(s"\nSink: ${sink.code}\n")
          output.append(s"  Location: $snkFile:$snkLine in $snkMethod()\n")
          
          output.append(s"\nPath length: ${elements.size} nodes\n")
        }
        output.append("\n")
      }
    }
  }
  
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
