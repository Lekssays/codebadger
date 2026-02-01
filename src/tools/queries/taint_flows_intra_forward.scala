{
  val sources = {{source_selector}}.l.take({{max_results}})
  val flows = sources.flatMap { src =>
    val method = src.method
    val sinks = method.call.name("{{sink_pattern}}").l
    
    sinks.flatMap { snk =>
      // Check if there's data flow from source to sink
      val srcAssigns = src.inAssignment.l
      if (srcAssigns.nonEmpty) {
        val varName = srcAssigns.head.target.code
        val sinkArgs = snk.argument.code.l
        if (sinkArgs.contains(varName)) {
          Some(Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "path_length" -> 1
          ))
        } else None
      } else None
    }
  }.take({{max_results}})
  flows
}.toJsonPretty
