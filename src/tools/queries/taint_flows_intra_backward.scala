{
  val sinks = {{sink_selector}}.l.take({{max_results}})
  val flows = sinks.flatMap { snk =>
    val method = snk.method
    val sources = method.call.name("{{source_pattern}}").l
    
    sources.flatMap { src =>
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
