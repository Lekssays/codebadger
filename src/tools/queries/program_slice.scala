{
  import scala.collection.mutable

  def normalizeFilename(path: String, target: String): Boolean = {
    def toPath(p: String) = p.replaceAll("\\\\", "/")
    val p = toPath(path)
    val t = toPath(target)
    p == t || p.endsWith("/" + t) || t.endsWith("/" + p)
  }

  val filename = "{{filename}}"
  val lineNum = {{line_num}}
  val callName = "{{call_name}}"
  val maxDepth = {{max_depth}}
  val includeBackward = {{include_backward}}
  val includeForward = {{include_forward}}
  val includeControlFlow = {{include_control_flow}}
  val direction = "{{direction}}"

  val output = new StringBuilder()

  // Per-node code clip: one macro-expanded statement (jq assert macros, simdjson
  // SIMD/template headers) can be enormous and blow the response budget. Cap the
  // .code of any single node and mark how much was dropped.
  def clip(s: String, n: Int = 200): String =
    if (s != null && s.length > n) s.take(n) + s"…(+${s.length - n} chars)" else s

  // Cap on how many slice nodes (data deps / propagations) we emit per direction,
  // so a huge slice can't overflow the response. Surfaced via a truncation note.
  val maxNodes = 60

  val isHeaderFile = filename.endsWith(".h") || filename.endsWith(".hpp") || filename.endsWith(".hxx")

  // All assignment-like operator names (simple + compound)
  def isAssignmentOp(name: String): Boolean =
    name == "<operator>.assignment" || name.startsWith("<operator>.assignment")

  // Find target method - try non-global first, then relax (handles header inlines and <global>)
  val targetMethodOpt = {
    val nonGlobal = cpg.method
      .filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename))
      .filterNot(_.name == "<global>")
      .filter(m => {
        val start = m.lineNumber.getOrElse(-1)
        val end   = m.lineNumberEnd.getOrElse(-1)
        start <= lineNum && end >= lineNum
      })
      .headOption

    // For header files or when no non-global method encloses the line, also include <global>
    if (nonGlobal.isDefined) nonGlobal
    else cpg.method
      .filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename))
      .filter(m => {
        val start = m.lineNumber.getOrElse(-1)
        val end   = m.lineNumberEnd.getOrElse(-1)
        start <= lineNum && end >= lineNum
      })
      .headOption
  }

  // Return anchor info as (code, name, line, argVars) or None
  // Tries: real CALL → ASSIGNMENT → CONTROL_STRUCTURE condition → compound-assignment CALL → any CALL
  // If nothing found at lineNum, retries ±3 lines (macro-expansion fallback)
  def findAnchor(method: io.shiftleft.codepropertygraph.generated.nodes.Method, targetLine: Int)
      : Option[(String, String, Int, List[String])] = {

    def tryLine(ln: Int): Option[(String, String, Int, List[String])] = {
      // 1. Real (non-operator) CALL
      val callsOnLine = method.call.filter(c => c.lineNumber.getOrElse(-1) == ln).l
      val realCallOpt = if (callName.nonEmpty && callsOnLine.nonEmpty)
        callsOnLine.filter(_.name == callName).headOption
      else if (callsOnLine.nonEmpty)
        callsOnLine.filterNot(c => c.name.startsWith("<operator>")).headOption
      else None

      realCallOpt.map { c =>
        (c.code, c.name, c.lineNumber.getOrElse(ln), c.argument.ast.isIdentifier.name.l.distinct)
      }.orElse {
        // 2. ASSIGNMENT node
        val assigns = method.assignment.filter(a => a.lineNumber.getOrElse(-1) == ln).l
        assigns.headOption.map { a =>
          val vars = (a.target.ast.isIdentifier.name.l ++ a.source.ast.isIdentifier.name.l).distinct
          (a.code, "<assignment>", a.lineNumber.getOrElse(ln), vars)
        }
      }.orElse {
        // 3. CONTROL_STRUCTURE condition (if/while/for guards)
        val ctrls = method.controlStructure.filter(c => c.lineNumber.getOrElse(-1) == ln).l
        ctrls.headOption.map { ctrl =>
          val condCode = ctrl.condition.code.headOption.getOrElse(ctrl.code.take(80))
          val vars = ctrl.condition.ast.isIdentifier.name.l.distinct
          (condCode, "<condition>", ctrl.lineNumber.getOrElse(ln), vars)
        }
      }.orElse {
        // 4. Compound-assignment CALL (<operator>.assignmentAnd etc.)
        val compoundOpt = callsOnLine.filter(c => isAssignmentOp(c.name)).headOption
        compoundOpt.map { c =>
          (c.code, c.name, c.lineNumber.getOrElse(ln), c.argument.ast.isIdentifier.name.l.distinct)
        }
      }.orElse {
        // 5. Any CALL (last resort, e.g. pure comparison operators)
        callsOnLine.headOption.map { c =>
          (c.code, c.name, c.lineNumber.getOrElse(ln), c.argument.ast.isIdentifier.name.l.distinct)
        }
      }
    }

    // Try exact line first, then ±1..3 (macro-expansion fallback)
    tryLine(targetLine).orElse {
      (1 to 3).flatMap(d => List(-d, d)).flatMap(delta => tryLine(targetLine + delta)).headOption
    }
  }

  targetMethodOpt match {
    case Some(method) => {
      // Gated-body probe: an enclosing method with zero calls and a ≤1-line span
      // was almost certainly preprocessed out (#ifdef / feature macro), so the
      // slice will be empty/misleading. Warn so the caller rebuilds with defines.
      if (method.call.size == 0 && (method.lineNumberEnd.getOrElse(0) - method.lineNumber.getOrElse(0)) <= 1)
        output.append(
          s"WARNING: method '${method.name}' is present but has no body in this CPG — likely #ifdef/feature-gated. " +
          "Rebuild with generate_cpg(defines=[...], include_paths=[...]) before trusting this slice.\n")
      findAnchor(method, lineNum) match {
        case Some((anchorCode, anchorName, anchorLine, argVars)) => {
          val targetFile = method.file.name.headOption.getOrElse("unknown")

          output.append(s"Program Slice for ${anchorName} at $targetFile:$anchorLine\n")
          output.append("=" * 60 + "\n")
          output.append(s"Code: ${clip(anchorCode)}\n")
          output.append(s"Method: ${method.fullName}\n")
          if (argVars.nonEmpty) output.append(s"Variables: ${argVars.mkString(", ")}\n")

          // === BACKWARD SLICE ===
          if (includeBackward) {
            val visited      = mutable.Set[String]()
            val dataDepsList = mutable.ListBuffer[(Int, String, String, String, List[String])]()

            def backwardTrace(currMethod: io.shiftleft.codepropertygraph.generated.nodes.Method,
                              varName: String,
                              beforeLine: Int,
                              depth: Int): Unit = {

              val uniqueId = s"${currMethod.fullName}:$varName:$beforeLine"
              if (depth <= 0 || visited.contains(uniqueId)) return
              visited.add(uniqueId)

              // 1a. Simple assignments (<operator>.assignment)
              currMethod.assignment
                .filter(a => { val ln = a.lineNumber.getOrElse(0); ln > 0 && ln < beforeLine })
                .filter(a => {
                  val tc = a.target.code
                  tc == varName                       ||
                  tc.startsWith(varName + "[")        ||
                  tc.startsWith(varName + "->")       ||
                  tc.startsWith(varName + ".")        ||
                  tc.endsWith("->" + varName)         ||
                  tc.endsWith("." + varName)
                })
                .l.foreach { assign =>
                  val rhsVars = assign.source.ast.isIdentifier.name.l.distinct.filter(_ != varName)
                  val f = assign.file.name.headOption.getOrElse("unknown")
                  dataDepsList += ((assign.lineNumber.getOrElse(-1), f, varName, assign.code, rhsVars))
                  rhsVars.foreach(v => backwardTrace(currMethod, v, assign.lineNumber.getOrElse(0), depth - 1))
                }

              // 1b. Compound assignments (+=, &=, |=, etc.) — not returned by .assignment
              currMethod.call
                .filter(c => isAssignmentOp(c.name) && c.name != "<operator>.assignment")
                .filter(c => { val ln = c.lineNumber.getOrElse(0); ln > 0 && ln < beforeLine })
                .filter(c => {
                  val lhs = c.argument.filter(_.argumentIndex == 1).code.headOption.getOrElse("")
                  lhs == varName                  ||
                  lhs.startsWith(varName + "[")   ||
                  lhs.endsWith("->" + varName)    ||
                  lhs.endsWith("." + varName)
                })
                .l.foreach { call =>
                  val rhsVars = call.argument.filter(_.argumentIndex == 2).ast.isIdentifier.name.l.distinct.filter(_ != varName)
                  val f = call.file.name.headOption.getOrElse("unknown")
                  dataDepsList += ((call.lineNumber.getOrElse(-1), f, varName, call.code, rhsVars))
                  rhsVars.foreach(v => backwardTrace(currMethod, v, call.lineNumber.getOrElse(0), depth - 1))
                }

              // 2. Inter-procedural: varName is a parameter → trace callers
              val matchedParams = currMethod.parameter.filter(_.name == varName).l
              if (matchedParams.nonEmpty) {
                matchedParams.foreach { param =>
                  // Static dispatch callers
                  currMethod.callIn.foreach { call =>
                    val callerMethod = call.method
                    call.argument.filter(_.argumentIndex == param.order).foreach { arg =>
                      val avars = arg.ast.isIdentifier.name.l.distinct
                      if (avars.nonEmpty) {
                        val f  = call.file.name.headOption.getOrElse("unknown")
                        val ln = call.lineNumber.getOrElse(-1)
                        dataDepsList += ((ln, f, varName, s"Passed as arg to ${currMethod.name}", avars))
                        avars.foreach(v => backwardTrace(callerMethod, v, ln, depth - 1))
                      }
                    }
                  }
                  // C++ dynamic dispatch callers (virtual method calls)
                  cpg.call
                    .filter(c => c.dispatchType == "DYNAMIC_DISPATCH" && c.name == currMethod.name)
                    .foreach { call =>
                      val callerMethod = call.method
                      call.argument.filter(_.argumentIndex == param.order).foreach { arg =>
                        val avars = arg.ast.isIdentifier.name.l.distinct
                        if (avars.nonEmpty) {
                          val f  = call.file.name.headOption.getOrElse("unknown")
                          val ln = call.lineNumber.getOrElse(-1)
                          dataDepsList += ((ln, f, varName, s"Dynamic dispatch arg to ${currMethod.name}", avars))
                          avars.foreach(v => backwardTrace(callerMethod, v, ln, depth - 1))
                        }
                      }
                    }
                }
              }
            }

            argVars.foreach(v => backwardTrace(method, v, anchorLine, maxDepth))

            val sortedDeps  = dataDepsList.toList.distinct.sortBy(_._1)
            val backwardCount = sortedDeps.size

            output.append(s"\n[BACKWARD SLICE] (${backwardCount} data dependencies)\n")

            if (sortedDeps.nonEmpty) {
              output.append("\n  Data Dependencies:\n")
              val displayDeps = sortedDeps.take(maxNodes)
              displayDeps.groupBy(_._2).foreach { case (file, deps) =>
                output.append(s"  File: $file\n")
                deps.sortBy(_._1).foreach { case (line, _, vn, code, depVars) =>
                  val lineInfo = if (line != -1) s"[$file:$line]" else "[Local]"
                  output.append(s"    $lineInfo $vn: ${clip(code)}\n")
                  if (depVars.nonEmpty) output.append(s"      <- depends on: ${depVars.mkString(", ")}\n")
                }
              }
              if (sortedDeps.size > maxNodes)
                output.append(
                  s"  ... TRUNCATED: ${sortedDeps.size - maxNodes} more data dependencies omitted " +
                  s"(showing $maxNodes of ${sortedDeps.size}). Narrow with a smaller max_depth or a more specific line.\n")
            }

            if (includeControlFlow) {
              val controlDeps = method.controlStructure
                .filter(c => { val ln = c.lineNumber.getOrElse(0); ln > 0 && ln < anchorLine })
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.file.name.headOption.getOrElse("unknown"), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse(ctrl.code.take(60))))
                .l.distinct.take(30)

              if (controlDeps.nonEmpty) {
                output.append("\n  Control Dependencies (Target Method):\n")
                controlDeps.foreach { case (line, file, ctrlType, cond) =>
                  output.append(s"    [$file:$line] $ctrlType: ${clip(cond)}\n")
                }
              }
            }

            val params = method.parameter.filter(p => argVars.contains(p.name)).l
            if (params.nonEmpty) {
              val paramStr = params.map(p => s"${p.name} (${p.typeFullName})").mkString(", ")
              output.append(s"\n  Parameters: $paramStr\n")
            }
          }

          // === FORWARD SLICE ===
          if (includeForward) {
            val resultVars = method.assignment
              .filter(a => a.lineNumber.getOrElse(0) == anchorLine)
              .filter(a => a.source.code.contains(anchorName))
              .target.code.l.distinct

            val forwardVisited  = mutable.Set[String]()
            val propagationsList = mutable.ListBuffer[(Int, String, String, String, String)]()

            def forwardTrace(currMethod: io.shiftleft.codepropertygraph.generated.nodes.Method,
                             varName: String,
                             afterLine: Int,
                             depth: Int): Unit = {

              val uniqueId = s"${currMethod.fullName}:$varName:$afterLine"
              if (depth <= 0 || forwardVisited.contains(uniqueId)) return
              forwardVisited.add(uniqueId)

              currMethod.call
                .filter(c => c.lineNumber.getOrElse(0) > afterLine)
                .filter(c => c.argument.code.l.exists(_.contains(varName)))
                .l.take(15)
                .foreach { call =>
                  val callFile = call.file.name.headOption.getOrElse("unknown")
                  propagationsList += ((call.lineNumber.getOrElse(-1), callFile, "usage", varName, call.code))

                  call.argument.filter(_.code.contains(varName)).foreach { arg =>
                    call.callee.foreach { calleeMethod =>
                      calleeMethod.parameter.filter(_.order == arg.argumentIndex).foreach { param =>
                        val pName = param.name
                        propagationsList += ((calleeMethod.lineNumber.getOrElse(-1), calleeMethod.file.name.headOption.getOrElse("unknown"), "passed_to_func", varName, s"Passed to ${calleeMethod.name} as $pName"))
                        forwardTrace(calleeMethod, pName, calleeMethod.lineNumber.getOrElse(0), depth - 1)
                      }
                    }
                  }
                }

              currMethod.assignment
                .filter(a => a.lineNumber.getOrElse(0) > afterLine)
                .filter(a => a.source.code.contains(varName))
                .l.take(15)
                .foreach { assign =>
                  val targetVar = assign.target.code
                  val assignFile = assign.file.name.headOption.getOrElse("unknown")
                  propagationsList += ((assign.lineNumber.getOrElse(-1), assignFile, "propagation", varName, assign.code))
                  if (targetVar != varName) forwardTrace(currMethod, targetVar, assign.lineNumber.getOrElse(0), depth - 1)
                }
            }

            resultVars.foreach(v => forwardTrace(method, v, anchorLine, maxDepth))

            val sortedProps  = propagationsList.toList.distinct.sortBy(_._1)
            val forwardCount = sortedProps.size

            output.append(s"\n[FORWARD SLICE] (${forwardCount} propagations)\n")

            if (resultVars.nonEmpty) {
              output.append(s"  Result stored in: ${resultVars.mkString(", ")}\n")
            }

            if (sortedProps.nonEmpty) {
              output.append("\n  Propagations:\n")
              val displayProps = sortedProps.take(maxNodes)
              displayProps.groupBy(_._2).foreach { case (file, props) =>
                output.append(s"  File: $file\n")
                props.sortBy(_._1).foreach { case (line, _, propType, vn, code) =>
                  output.append(s"    [$file:$line] $propType ($vn): ${clip(code)}\n")
                }
              }
              if (sortedProps.size > maxNodes)
                output.append(
                  s"  ... TRUNCATED: ${sortedProps.size - maxNodes} more propagations omitted " +
                  s"(showing $maxNodes of ${sortedProps.size}). Narrow with a smaller max_depth.\n")
            }

            if (includeControlFlow) {
              val controlAffected = method.controlStructure
                .filter(c => c.lineNumber.getOrElse(0) > anchorLine)
                .filter(c => resultVars.exists(v => c.condition.code.headOption.getOrElse("").contains(v)))
                .map(ctrl => (ctrl.lineNumber.getOrElse(-1), ctrl.file.name.headOption.getOrElse("unknown"), ctrl.controlStructureType, ctrl.condition.code.headOption.getOrElse("")))
                .l.distinct.take(20)

              if (controlAffected.nonEmpty) {
                output.append("\n  Control Flow Affected (Target Method):\n")
                controlAffected.foreach { case (line, file, ctrlType, cond) =>
                  output.append(s"    [$file:$line] $ctrlType: $cond\n")
                }
              }
            }
          }
        }

        case None => {
          val callsOnLine = method.call.filter(c => c.lineNumber.getOrElse(-1) == lineNum).l
          val callNames   = callsOnLine.map(_.name).distinct
          output.append(s"ERROR: No anchor node found on line $lineNum in method ${method.name}\n")
          if (callNames.nonEmpty) {
            output.append(s"Available calls on line $lineNum: ${callNames.mkString(", ")}\n")
          } else {
            output.append(s"No calls, assignments, or control structures found on line $lineNum.\n")
            val nearbyLines = method.call.lineNumber.l.filter(l => Math.abs(l - lineNum) <= 5).distinct.sorted
            if (nearbyLines.nonEmpty) output.append(s"Nearby lines with calls: ${nearbyLines.mkString(", ")}\n")
          }
        }
      }
    }

    case None => {
      val allFiles      = cpg.file.name.l.distinct.take(20)
      val matchingFiles = cpg.file.name.l.filter(f => f.contains(filename) || filename.split("/").lastOption.exists(f.endsWith(_))).distinct.take(10)
      // Include all methods (including <global>) for diagnostics
      val methodsInFile = cpg.method.filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename)).l.take(10)

      output.append(s"ERROR: No method found containing line $lineNum in '$filename'\n\n")

      if (matchingFiles.nonEmpty) {
        output.append(s"Matching files in CPG:\n")
        matchingFiles.foreach(f => output.append(s"  - $f\n"))
      }

      if (methodsInFile.nonEmpty) {
        output.append(s"\nMethods in matching file(s):\n")
        methodsInFile.foreach { m =>
          output.append(s"  - ${m.name}: lines ${m.lineNumber.getOrElse(-1)}-${m.lineNumberEnd.getOrElse(-1)}\n")
        }
      }

      if (matchingFiles.isEmpty && methodsInFile.isEmpty) {
        output.append(s"Sample files in CPG (first 5):\n")
        allFiles.take(5).foreach(f => output.append(s"  - $f\n"))
      }
    }
  }

  // Return with markers for easy extraction
  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
