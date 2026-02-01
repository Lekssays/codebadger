{
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
  }
  
  def extractIndexVariable(indexExpr: String): String = {
    indexExpr.replaceAll("[^a-zA-Z0-9_].*", "").trim
  }
  
  def getOperatorSymbol(operatorName: String): String = {
    operatorName match {
      case "<operator>.lessThan" => "<"
      case "<operator>.greaterThan" => ">"
      case "<operator>.lessEqualsThan" => "<="
      case "<operator>.greaterEqualsThan" => ">="
      case "<operator>.notEquals" => "!="
      case "<operator>.equals" => "=="
      case _ => "?"
    }
  }
  
  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  
  val bufferAccessOpt = cpg.call
    .name("<operator>.indirectIndexAccess")
    .filter(c => {
      val f = c.file.name.headOption.getOrElse("")
      f.endsWith("/" + filename) || f == filename
    })
    .filter(c => c.lineNumber.getOrElse(-1) == lineNum)
    .headOption
  
  val resultMap = bufferAccessOpt match {
    case Some(bufferAccess) =>
      val accessLine = bufferAccess.lineNumber.getOrElse(0)
      val args = bufferAccess.argument.l
      
      val bufferName = if (args.nonEmpty) escapeJson(args.head.code) else "unknown"
      val indexExpr = if (args.size > 1) escapeJson(args.last.code) else "unknown"
      val indexVar = extractIndexVariable(args.lastOption.map(_.code).getOrElse(""))
      
      val method = bufferAccess.method
      
      val comparisons = method.call
        .filter(c => {
          val name = c.name
          name.contains("<operator>") && 
          (name.contains("essThan") || name.contains("ualsThan") || name.contains("quals") || name.contains("otEquals"))
        })
        .filter(cmp => {
          val cmpCode = cmp.code
          cmpCode.contains(indexVar) || cmpCode.contains(indexExpr.replaceAll("\\\\\"", "\""))
        })
        .l
      
      val boundsChecksList = comparisons
        .map(cmp => {
          val cmpLine = cmp.lineNumber.getOrElse(0)
          val position = if (cmpLine < accessLine) {
            "BEFORE_ACCESS"
          } else if (cmpLine > accessLine) {
            "AFTER_ACCESS"
          } else {
            "SAME_LINE"
          }
          
          val cmpArgs = cmp.argument.l
          val leftArg = if (cmpArgs.nonEmpty) cmpArgs.head.code else "?"
          val rightArg = if (cmpArgs.size > 1) cmpArgs.last.code else "?"
          val operator = getOperatorSymbol(cmp.name)
          
          Map(
            "line" -> cmpLine,
            "code" -> escapeJson(cmp.code),
            "checked_variable" -> escapeJson(leftArg),
            "bound" -> escapeJson(rightArg),
            "operator" -> operator,
            "position" -> position
          )
        })
        .take(50)
      
      val checkBefore = comparisons.exists(c => c.lineNumber.getOrElse(0) < accessLine)
      val checkAfter = comparisons.exists(c => c.lineNumber.getOrElse(0) > accessLine)
      
      Map(
        "success" -> true,
        "buffer_access" -> Map(
          "line" -> accessLine,
          "code" -> escapeJson(bufferAccess.code),
          "buffer" -> bufferName,
          "index" -> indexExpr
        ),
        "bounds_checks" -> boundsChecksList,
        "check_before_access" -> checkBefore,
        "check_after_access" -> checkAfter,
        "index_variable" -> indexVar
      )
    
    case None =>
      Map(
        "success" -> false,
        "error" -> Map(
          "code" -> "NOT_FOUND",
          "message" -> s"No buffer access found at $filename:$lineNum"
        )
      )
  }
  
  List(resultMap)
}.toJsonPretty
