{
  // Step 1: Find bridge functions (functions containing sinks)
  val bridgeFunctions = cpg.method
    .where(_.call.name("{{sink_pattern}}"))
    .filterNot(_.name == "<global>")
    .l
    
  // Step 2: Find sources
  val sources = {{source_selector}}.l.take({{max_results_x3}})
  
  // Step 3: For each source, find calls to bridge functions
  val flows = sources.flatMap { src =>
    val srcMethod = src.method
    
    // Find calls from source's method to bridge functions
    bridgeFunctions.flatMap { bridgeFunc =>
      val callsToBridge = srcMethod.call.name(bridgeFunc.name).l
      
      if (callsToBridge.nonEmpty) {
        // Get the actual sink call inside bridge function
        val sinkInBridge = bridgeFunc.call.name("{{sink_pattern}}").headOption
        
        sinkInBridge.map { snk =>
          Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "bridge_function" -> bridgeFunc.name,
            "path_length" -> 2
          )
        }
      } else None
    }
  }.take({{max_results}})
  
  flows
}.toJsonPretty
