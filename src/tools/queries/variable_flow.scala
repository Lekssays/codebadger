{
  val targetLine = {{line_num}}
  val targetVar  = "{{variable}}"
  val filename   = "{{filename}}"
  val direction  = "{{direction}}"
  val maxResults = {{max_results}}

  val output = new StringBuilder

  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }
  val filePattern = pathBoundaryRegex(filename)

  // assignment-like operators: simple (=) and compound (+=, -=, &=, <<=, ...).
  // cpg.assignment only covers <operator>.assignment, so compound ops are matched by name.
  def isAssignmentOp(name: String): Boolean =
    name == "<operator>.assignment" || name.startsWith("<operator>.assignment")

  // Does `code` reference one of the tracked variables (direct, field, index, deref, addr)?
  def relevant(code: String, vars: List[String]): Boolean =
    vars.exists(v =>
      code == v ||
      code == "&" + v ||
      code == "*" + v ||
      code.startsWith(v + ".") ||
      code.startsWith(v + "[") ||
      code.startsWith(v + "->") ||
      code.startsWith("*" + v) ||
      code.startsWith("&" + v))

  val targetMethodOpt = cpg.method
    .where(_.file.name(filePattern))
    .filterNot(_.name == "<global>")
    .filter(m => {
      val s = m.lineNumber.getOrElse(-1)
      val e = m.lineNumberEnd.getOrElse(-1)
      s <= targetLine && e >= targetLine
    })
    .headOption

  output.append("Variable Flow Analysis\n")
  output.append("======================\n")
  output.append(s"Target: variable '$targetVar' at $filename:$targetLine\n")

  targetMethodOpt match {
    case None =>
      output.append(s"(No method found containing line $targetLine in '$filename')\n")

    case Some(method) =>
      output.append(s"Method: ${method.name}\n")
      output.append(s"Direction: $direction\n")

      // Gated-body probe: zero calls + ≤1-line span ⇒ the body was likely
      // preprocessed out (#ifdef / feature macro); the flow would be empty.
      if (method.call.size == 0 && (method.lineNumberEnd.getOrElse(0) - method.lineNumber.getOrElse(0)) <= 1)
        output.append(
          s"WARNING: method '${method.name}' is present but has no body in this CPG — likely #ifdef/feature-gated. " +
          "Rebuild with generate_cpg(defines=[...], include_paths=[...]) before trusting this flow.\n")

      // Alias discovery: pointers that take the address of the target (p = &x).
      val addrAliases = method.assignment
        .filter(_.source.code.contains("&" + targetVar))
        .target.code.l.distinct
      if (addrAliases.nonEmpty)
        output.append(s"Aliases (&$targetVar): ${addrAliases.mkString(", ")}\n")
      val monitored = (targetVar :: addrAliases).distinct

      // (line, file, code, kind) — collected, then sorted/deduped for output.
      val deps = scala.collection.mutable.ListBuffer[(Int, String, String, String)]()
      val seen = scala.collection.mutable.Set[String]()

      def trace(m: io.shiftleft.codepropertygraph.generated.nodes.Method,
                vars: List[String],
                scopeLine: Int,
                depth: Int): Unit = {
        val key = m.fullName + "::" + vars.mkString(",") + "::" + depth
        if (depth > 4 || seen.contains(key)) return
        seen.add(key)
        val f = m.file.name.headOption.getOrElse(filename)

        if (direction == "backward") {
          // Declarations / initializers of the tracked vars.
          vars.foreach { v =>
            m.local.nameExact(v).foreach { l =>
              deps += ((l.lineNumber.getOrElse(-1), f, s"${l.typeFullName} ${l.code}".trim, "declaration"))
            }
          }

          // Assignments (simple + compound) whose LHS is tracked, up to the use site.
          m.call.filter(c => isAssignmentOp(c.name))
            .filter(_.lineNumber.getOrElse(-1) <= scopeLine)
            .take(maxResults)
            .foreach { c =>
              val lhs = c.argument.filter(_.argumentIndex == 1).code.headOption.getOrElse("")
              if (relevant(lhs, vars)) {
                val kind = if (c.name == "<operator>.assignment") "assignment" else "modification"
                deps += ((c.lineNumber.getOrElse(-1), f, c.code.trim, kind))
                // Follow the RHS one hop back to surface the data's origin.
                val rhs = c.argument.filter(_.argumentIndex == 2).ast.isIdentifier.name.l.distinct
                  .filter(x => !vars.contains(x))
                rhs.foreach(rv => trace(m, List(rv), c.lineNumber.getOrElse(scopeLine), depth + 1))
              }
            }

          // Calls that consume a tracked var (may modify it through a pointer arg).
          m.call.filterNot(c => c.name.startsWith("<operator>"))
            .filter(_.lineNumber.getOrElse(-1) <= scopeLine)
            .filter(c => c.argument.code.l.exists(a => relevant(a, vars)))
            .take(maxResults)
            .foreach(c => deps += ((c.lineNumber.getOrElse(-1), f, c.code.trim, "use_in_call")))

          // Inter-procedural: a tracked var that is a parameter flows from the caller's argument.
          vars.foreach { v =>
            m.parameter.nameExact(v).foreach { p =>
              deps += ((p.lineNumber.getOrElse(-1), f, s"${p.typeFullName} ${p.name}".trim, "parameter"))
              m.callIn.take(maxResults).foreach { call =>
                val cf = call.file.name.headOption.getOrElse("unknown")
                call.argument.filter(_.argumentIndex == p.order).foreach { arg =>
                  deps += ((call.lineNumber.getOrElse(-1), cf,
                            s"${call.method.name}(... '${arg.code.trim}' ...)", "call_site_arg"))
                  arg.ast.isIdentifier.name.l.distinct
                    .foreach(av => trace(call.method, List(av), call.lineNumber.getOrElse(-1), depth + 1))
                }
              }
            }
          }

        } else { // forward
          // Uses of the tracked vars at/after the definition site.
          m.call.filterNot(c => c.name.startsWith("<operator>"))
            .filter(_.lineNumber.getOrElse(-1) >= scopeLine)
            .filter(c => c.argument.code.l.exists(a => relevant(a, vars)))
            .take(maxResults)
            .foreach(c => deps += ((c.lineNumber.getOrElse(-1), f, c.code.trim, "usage")))

          // Propagations: target = <expr involving tracked> — follow the new target forward.
          m.call.filter(c => isAssignmentOp(c.name))
            .filter(_.lineNumber.getOrElse(-1) >= scopeLine)
            .take(maxResults)
            .foreach { c =>
              val rhsRefsTracked =
                c.argument.filter(_.argumentIndex == 2).ast.isIdentifier.name.l.exists(n => vars.contains(n))
              if (rhsRefsTracked) {
                deps += ((c.lineNumber.getOrElse(-1), f, c.code.trim, "propagation"))
                val tgt = c.argument.filter(_.argumentIndex == 1).code.headOption.getOrElse("")
                if (tgt.nonEmpty && !vars.contains(tgt))
                  trace(m, List(tgt), c.lineNumber.getOrElse(scopeLine), depth + 1)
              }
            }
        }
      }

      trace(method, monitored, targetLine, 0)

      output.append(s"Tracked: ${monitored.mkString(", ")}\n")
      output.append("\nDependencies:\n")
      val uniq = deps.toList.distinct.sortBy(d => (d._1, d._4))
      if (uniq.isEmpty) output.append("(none found)\n")
      else uniq.take(maxResults).foreach { case (line, f, code, kind) =>
        output.append(s"[$f:$line] $code ($kind)\n")
      }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
