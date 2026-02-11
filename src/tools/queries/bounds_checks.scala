{
  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  val output = new StringBuilder()

  // --- Helper Functions ---

  def extractVariable(expr: String): String = {
    Option(expr).getOrElse("").replaceAll("[^a-zA-Z0-9_].*", "").trim
  }

  /** Classify a call as a sized operation based on its name.
    * Uses case-insensitive matching to generically handle library wrappers
    * (e.g., xmlMalloc, g_malloc, xmlRealloc, g_realloc, xmlStrndup, etc.)
    * without hardcoding specific function names.
    *
    * Returns: (typeLabel, sizeArgOrder, sizeLabel, optDstArgOrder)
    */
  def classifySizedOp(callName: String): Option[(String, Int, String, Option[Int])] = {
    val n = callName.toLowerCase
    // Order matters: check specific patterns (realloc, calloc) before generic (malloc)
    if (n.matches(".*mem(cpy|move).*") || n.matches(".*strncpy.*") || n.matches(".*strlcpy.*"))
      Some(("Memory/String Copy", 3, "Length", Some(1)))
    else if (n.matches(".*memset.*"))
      Some(("Memory Set", 3, "Length", Some(1)))
    else if (n.matches("v?snprintf"))
      Some(("Formatted Output", 2, "Buffer Size", Some(1)))
    else if (n.matches(".*realloc.*"))
      Some(("Memory Reallocation", 2, "Size", None))
    else if (n.matches(".*calloc.*"))
      Some(("Memory Allocation", 1, "Count", None))
    else if (n == "aligned_alloc")
      Some(("Memory Allocation", 2, "Size", None))
    else if (n.matches(".*malloc.*"))
      Some(("Memory Allocation", 1, "Size", None))
    else if (n.matches(".*strndup.*"))
      Some(("String Duplication", 2, "Length", None))
    else
      None
  }

  // --- Target Identification ---

  // 1. Buffer Access (buf[i])
  val bufferAccessOpt = cpg.call
    .name("<operator>.indirectIndexAccess")
    .filter(c => {
      val f = c.file.name.headOption.getOrElse("")
      f.endsWith("/" + filename) || f == filename
    })
    .filter(c => c.lineNumber.getOrElse(-1) == lineNum)
    .l.headOption

  // 2. Sized operations (allocation, memory copy/set, snprintf, strndup, etc.)
  // Broad regex pre-filter for performance; classifySizedOp does precise classification.
  // Uses [Mm], [Cc], [Rr], [Ss] character classes to handle camelCase wrappers (xmlMalloc, etc.)
  val sizedCallPattern = ".*[Mm]alloc.*|.*[Cc]alloc.*|.*[Rr]ealloc.*|.*[Mm]em(cpy|move|set).*|.*[Ss]trncpy.*|.*[Ss]trlcpy.*|v?snprintf|aligned_alloc|.*[Ss]trndup.*"
  val sizedCallOpt = cpg.call
    .name(sizedCallPattern)
    .filter(c => {
      val f = c.file.name.headOption.getOrElse("")
      f.endsWith("/" + filename) || f == filename
    })
    .filter(c => c.lineNumber.getOrElse(-1) == lineNum)
    .l.headOption


  // --- Analysis Logic ---

  var foundTarget = false

  // Handle Buffer Access
  bufferAccessOpt.foreach(ba => {
    foundTarget = true
    val method = ba.method
    val args = ba.argument.l
    val bufferArg = args.find(_.order == 1)
    val indexArg = args.find(_.order == 2)
    val bufferName = bufferArg.map(_.code).getOrElse("unknown")
    val indexExpr = indexArg.map(_.code).getOrElse("unknown")
    val indexVar = extractVariable(indexExpr)

    output.append(s"Bounds Check Analysis for $filename:$lineNum\n")
    output.append("=" * 60 + "\n")
    output.append(s"Type:          Buffer Access (buf[i])\n")
    output.append(s"Operation:     ${ba.code}\n")
    output.append(s"Buffer:        $bufferName\n")
    output.append(s"Index:         $indexExpr (Variable: $indexVar)\n\n")

    analyzeChecks(method, ba, indexVar, output)
  })

  // Handle Sized Operations (allocation, memcpy, memset, snprintf, strndup, etc.)
  if (!foundTarget) {
    sizedCallOpt.foreach(sc => {
      classifySizedOp(sc.name).foreach { case (typeLabel, sizeArgOrder, sizeLabel, dstArgOrderOpt) =>
        foundTarget = true
        val method = sc.method
        val args = sc.argument.l
        val sizeArg = args.find(_.order == sizeArgOrder)
        val sizeExpr = sizeArg.map(_.code).getOrElse("unknown")
        val sizeVar = extractVariable(sizeExpr)

        output.append(s"Bounds Check Analysis for $filename:$lineNum\n")
        output.append("=" * 60 + "\n")
        output.append(s"Type:          $typeLabel\n")
        output.append(s"Function:      ${sc.name}\n")
        output.append(s"Operation:     ${sc.code}\n")

        dstArgOrderOpt.foreach { dstOrder =>
          val dstArg = args.find(_.order == dstOrder)
          val dstName = dstArg.map(_.code).getOrElse("unknown")
          output.append(s"Destination:   $dstName\n")
        }

        val pad = " " * math.max(1, 15 - sizeLabel.length)
        output.append(s"$sizeLabel:$pad$sizeExpr (Variable: $sizeVar)\n\n")

        analyzeChecks(method, sc, sizeVar, output)
      }
    })
  }

  if (!foundTarget) {
     output.append(s"ERROR: No supported operation found at $filename:$lineNum\n")
     output.append("Supported: buf[i], memory copy/set functions, allocation functions,\n")
     output.append("           snprintf, and their library-specific wrappers.\n")
  }


  // --- Common Analysis Method ---

  def analyzeChecks(method: Method, targetCall: Call, variable: String, out: StringBuilder): Unit = {

      // 1. Control Dependence Checks
      // Match actual Joern comparison operator names semantically
      val comparisonOps = Set(
        "<operator>.lessThan", "<operator>.greaterThan",
        "<operator>.lessEqualsThan", "<operator>.greaterEqualsThan",
        "<operator>.equals", "<operator>.notEquals"
      )
      val guardingChecks = targetCall.controlledBy.isCall.filter(c => {
         c.code.contains(variable) && comparisonOps.contains(c.name)
      }).l

      out.append("LOCAL CHECKS\n")
      out.append("-" * 30 + "\n")

      var guarded = false

      if (guardingChecks.isEmpty) {
         out.append("  None found.\n")
      } else {
         guardingChecks.foreach(cmp => {
             // Restart traversal from cmp to use .astParent steps
             val isLoop = cmp.start.astParent.isControlStructure.controlStructureType.l.exists(t => t == "WHILE" || t == "FOR" || t == "DO")
             val typeLabel = if (isLoop) "[LOOP GUARD]" else "[GUARD]"
             guarded = true
             out.append(f"  Line ${cmp.lineNumber.getOrElse(0)}%-4d: ${cmp.code}%-20s | $typeLabel\n")
         })
      }
      out.append("\n")

      // 2. Inter-procedural Checks
      val paramOpt = method.parameter.filter(_.name == variable).l.headOption
      out.append("INTER-PROCEDURAL CHECKS\n")
      out.append("-" * 30 + "\n")

      paramOpt match {
        case Some(pNode) =>
          val pIndex = pNode.order
          val callSites = cpg.call.methodFullNameExact(method.fullName).l

          if (callSites.isEmpty) {
            out.append("  No callers found.\n")
          } else {
            var foundInter = false
            callSites.foreach(callSite => {
              val callerMethod = callSite.method
              val argAtCallSite = callSite.argument.l.find(_.order == pIndex)

              argAtCallSite.foreach(arg => {
                val argVarInCaller = extractVariable(arg.code)
                // Check controllers for the call site!
                val callerGuards = callSite.controlledBy.isCall.filter(c => {
                    c.code.contains(argVarInCaller) && comparisonOps.contains(c.name)
                }).l

                if (callerGuards.nonEmpty) {
                   foundInter = true
                   guarded = true
                   out.append(s"  In Caller: ${callerMethod.name} (${callerMethod.file.name.headOption.getOrElse("?")})\n")
                   callerGuards.foreach(cmp => {
                     out.append(f"    Line ${cmp.lineNumber.getOrElse(0)}%-4d: ${cmp.code}\n")
                   })
                }
              })
            })
            if (!foundInter) out.append("  None found in callers.\n")
          }
        case None =>
          out.append("  N/A (Variable is not a method parameter).\n")
      }

      out.append("\nSUMMARY\n")
      out.append("-" * 30 + "\n")
      out.append(s"Overall Status: ${if (guarded) "GUARDED" else "UNGUARDED OR INSUFFICIENT CHECKS"}\n")
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
