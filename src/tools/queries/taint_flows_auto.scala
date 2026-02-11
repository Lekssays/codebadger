{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val sourcePattern = "{{source_pattern}}"
  val sinkPattern = "{{sink_pattern}}"
  val sanitizerPattern = "{{sanitizer_pattern}}"
  val fileFilter = "{{file_filter}}"
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

  // Build source nodes from pattern, with optional file filter
  // fileFilter is pre-built with path-boundary anchoring (e.g., "(^|.*/)parser\\.c.*")
  val sources: List[CfgNode] = {
    if (fileFilter.nonEmpty) {
      cpg.call.name(sourcePattern).where(_.file.name(fileFilter)).l
    } else {
      cpg.call.name(sourcePattern).l
    }
  }

  // Build sink nodes from pattern, with optional file filter
  val sinkCalls: List[Call] = {
    if (fileFilter.nonEmpty) {
      cpg.call.name(sinkPattern).where(_.file.name(fileFilter)).l
    } else {
      cpg.call.name(sinkPattern).l
    }
  }

  // Expand sinks: include arguments of each call so we catch taint flowing into any arg
  val effectiveSinks: List[CfgNode] = sinkCalls.flatMap { c =>
    c :: c.argument.l
  }

  // Header
  output.append("Auto Taint Flow Analysis\n")
  output.append("=" * 60 + "\n")
  output.append(s"Sources matched: ${sources.size} nodes (pattern: $sourcePattern)\n")
  output.append(s"Sinks matched: ${sinkCalls.size} nodes (pattern: $sinkPattern)\n")
  if (fileFilter.nonEmpty) {
    output.append(s"File filter: $fileFilter\n")
  }
  if (sanitizerPattern.nonEmpty) {
    output.append(s"Sanitizers: $sanitizerPattern\n")
  }
  output.append("\n")

  if (sources.isEmpty) {
    output.append("No source nodes found matching the pattern.\n")
    output.append("Try broadening source_patterns or removing the filename filter.\n")
  } else if (sinkCalls.isEmpty) {
    output.append("No sink nodes found matching the pattern.\n")
    output.append("Try broadening sink_patterns or removing the filename filter.\n")
  } else {
    // Run batch taint analysis: all sinks reachable from all sources
    val rawFlows = effectiveSinks.reachableByFlows(sources).l.take(maxResults)

    // Filter out flows that pass through sanitizer functions
    val flows = if (sanitizerPattern.isEmpty) rawFlows else {
      rawFlows.filterNot { flow =>
        val elements = flow.elements.l
        // Check intermediate elements (exclude first=source and last=sink)
        elements.size > 2 && elements.slice(1, elements.size - 1).exists {
          case c: Call => c.name.matches(sanitizerPattern)
          case _ => false
        }
      }
    }

    if (flows.isEmpty) {
      output.append("No confirmed taint flows found.\n")
      output.append(s"Tested ${sources.size} sources against ${sinkCalls.size} sinks.\n")
      if (sanitizerPattern.nonEmpty && rawFlows.nonEmpty) {
        output.append(s"Note: ${rawFlows.size} flow(s) were filtered out by sanitizer functions.\n")
      }
    } else {
      val filteredCount = rawFlows.size - flows.size
      output.append(s"Found ${flows.size} confirmed taint flow(s):\n")
      if (filteredCount > 0) {
        output.append(s"($filteredCount flow(s) filtered out by sanitizer functions)\n")
      }
      output.append("\n")

      // Deduplicate: track seen (source_file:line -> sink_file:line) pairs
      val seen = mutable.Set[String]()

      flows.zipWithIndex.foreach { case (flow, idx) =>
        val elements = flow.elements.l
        if (elements.nonEmpty) {
          val source = elements.head
          val sink = elements.last

          val srcFile = source.file.name.headOption.getOrElse("?")
          val srcLine = source.lineNumber.getOrElse(-1)
          val snkFile = sink.file.name.headOption.getOrElse("?")
          val snkLine = sink.lineNumber.getOrElse(-1)

          val key = s"$srcFile:$srcLine->$snkFile:$snkLine"
          if (!seen.contains(key)) {
            seen.add(key)

            output.append(s"--- Flow ${seen.size} ---\n")

            // Source info
            val srcMethod = getMethodName(source)
            output.append(s"Source: ${source.code.take(80)}\n")
            output.append(s"  Location: $srcFile:$srcLine in $srcMethod()\n")

            // Path summary (intermediate steps)
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

            // Sink info
            val snkMethod = getMethodName(sink)
            output.append(s"\nSink: ${sink.code.take(80)}\n")
            output.append(s"  Location: $snkFile:$snkLine in $snkMethod()\n")
            output.append(s"\nPath length: ${elements.size} nodes\n\n")
          }
        }
      }

      output.append("=" * 60 + "\n")
      output.append(s"Summary: ${seen.size} unique flow(s) from ${sources.size} sources to ${sinkCalls.size} sinks\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
