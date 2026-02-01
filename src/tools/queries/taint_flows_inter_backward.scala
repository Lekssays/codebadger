{
  // Step 1: Find sinks
  val sinks = {{sink_selector}}.l.take({{max_results}})
  
  // Step 2: Find bridge functions containing these sinks
  val bridgeFunctions = sinks.map(_.method).dedup.filterNot(_.name == "<global>").l
  
  // Step 3: Find calls to bridge functions from methods containing sources
  val flows = bridgeFunctions.flatMap { bridgeFunc =>
    // Find who calls this bridge function
    val callers = cpg.call.name(bridgeFunc.name).l
    
    callers.flatMap { callSite =>
      val callerMethod = callSite.method
      // Check if caller method has source calls
      val sourceCalls = callerMethod.call.name("{{source_pattern}}").l
      
      if (sourceCalls.nonEmpty) {
        val src = sourceCalls.head
        val snk = bridgeFunc.call.name("{{sink_pattern}}").headOption.getOrElse(null)
        
        if (snk != null) {
          Some(Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "bridge_function" -> bridgeFunc.name,
            "path_length" -> 2
          ))
        } else None
      } else None
    }
  }.take({{max_results}})
  
  flows
}.toJsonPretty
