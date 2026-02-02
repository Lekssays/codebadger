{
  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  val output = new StringBuilder()

  def getOperatorSymbol(operatorName: String): String = {
    operatorName match {
      case name if name.contains("lessThan") => "<"
      case name if name.contains("greaterThan") => ">"
      case name if name.contains("lessEqualsThan") => "<="
      case name if name.contains("greaterEqualsThan") => ">="
      case name if name.contains("notEquals") => "!="
      case name if name.contains("equals") => "=="
      case _ => "?"
    }
  }

  def extractIndexVariable(indexExpr: String): String = {
    Option(indexExpr).getOrElse("").replaceAll("[^a-zA-Z0-9_].*", "").trim
  }

  val bufferAccessOpt = cpg.call
    .name("<operator>.indirectIndexAccess")
    .filter(c => {
      val f = c.file.name.headOption.getOrElse("")
      f.endsWith("/" + filename) || f == filename
    })
    .filter(c => c.lineNumber.getOrElse(-1) == lineNum)
    .l.headOption

  bufferAccessOpt match {
    case Some(ba) =>
      val accessLine = ba.lineNumber.getOrElse(0)
      val method = ba.method
      val args = ba.argument.l
      val bufferArg = args.find(_.order == 1)
      val indexArg = args.find(_.order == 2)
      val bufferName = bufferArg.map(_.code).getOrElse("unknown")
      val indexExpr = indexArg.map(_.code).getOrElse("unknown")
      val indexVar = extractIndexVariable(indexExpr)

      output.append(s"Bounds Check Analysis for $filename:$lineNum\n")
      output.append("=" * 60 + "\n")
      output.append(s"Buffer Access: ${ba.code}\n")
      output.append(s"Buffer Name:   $bufferName\n")
      output.append(s"Index Expr:    $indexExpr\n")
      output.append(s"Index Var:     $indexVar\n\n")

      // 1. Local checks
      val localChecks = method.call
        .filter(c => c.name.contains("<operator>") &&
                     (c.name.contains("essThan") || c.name.contains("ualsThan") || c.name.contains("quals") || c.name.contains("otEquals")))
        .filter(cmp => cmp.code.contains(indexVar))
        .l

      output.append("LOCAL CHECKS\n")
      output.append("-" * 30 + "\n")
      if (localChecks.isEmpty) {
        output.append("  None found.\n")
      } else {
        localChecks.foreach(cmp => {
          val cmpLine = cmp.lineNumber.getOrElse(0)
          val dominates = cmp.dominates.id(ba.id).nonEmpty
          val pos = if (cmpLine < accessLine) "BEFORE" else if (cmpLine > accessLine) "AFTER" else "SAME LINE"
          val status = if (dominates) "[GUARDED]" else "[NOT GUARDING]"
          output.append(f"  Line $cmpLine%-4d: ${cmp.code}%-20s | $pos%-10s | $status\n")
        })
      }
      output.append("\n")

      // 2. Inter-procedural checks
      val paramOpt = method.parameter.filter(_.name == indexVar).l.headOption
      output.append("INTER-PROCEDURAL CHECKS\n")
      output.append("-" * 30 + "\n")
      
      paramOpt match {
        case Some(pNode) =>
          val pIndex = pNode.order
          val callSites = cpg.call.methodFullNameExact(method.fullName).l
          
          if (callSites.isEmpty) {
            output.append("  No callers found.\n")
          } else {
            var foundInter = false
            callSites.foreach(callSite => {
              val callerMethod = callSite.method
              val argAtCallSite = callSite.argument.l.find(_.order == pIndex)
              
              argAtCallSite.foreach(arg => {
                val argVarInCaller = extractIndexVariable(arg.code)
                val callerChecks = callerMethod.call
                  .filter(c => c.name.contains("<operator>") &&
                               (c.name.contains("essThan") || c.name.contains("ualsThan") || c.name.contains("quals") || c.name.contains("otEquals")))
                  .filter(cmp => cmp.code.contains(argVarInCaller))
                  .filter(cmp => cmp.dominates.id(callSite.id).nonEmpty)
                  .l
                
                if (callerChecks.nonEmpty) {
                  foundInter = true
                  output.append(s"  In Caller: ${callerMethod.name} (${callerMethod.file.name.headOption.getOrElse("?")})\n")
                  callerChecks.foreach(cmp => {
                    output.append(f"    Line ${cmp.lineNumber.getOrElse(0)}%-4d: ${cmp.code}\n")
                  })
                }
              })
            })
            if (!foundInter) output.append("  None found in callers.\n")
          }
        case None =>
          output.append("  N/A (Index is not a method parameter).\n")
      }
      
      val isGuarded = localChecks.exists(_.dominates.id(ba.id).nonEmpty) || {
        paramOpt.map(p => {
          val pIndex = p.order
          cpg.call.methodFullNameExact(method.fullName).l.exists(cs => {
            val arg = cs.argument.l.find(_.order == pIndex)
            arg.exists(a => {
              val av = extractIndexVariable(a.code)
              cs.method.call
                .filter(c => c.name.contains("<operator>") &&
                             (c.name.contains("essThan") || c.name.contains("ualsThan") || c.name.contains("quals") || c.name.contains("otEquals")))
                .filter(_.code.contains(av))
                .exists(_.dominates.id(cs.id).nonEmpty)
            })
          })
        }).getOrElse(false)
      }

      output.append("\nSUMMARY\n")
      output.append("-" * 30 + "\n")
      output.append(s"Overall Status: ${if (isGuarded) "GUARDED" else "UNGUARDED OR INSUFFICIENT CHECKS"}\n")

    case None =>
      output.append(s"ERROR: No buffer access found at $filename:$lineNum\n")
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
