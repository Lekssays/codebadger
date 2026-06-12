{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val fileFilter = "{{filename}}"
  val maxResults = {{limit}}

  val output = new StringBuilder()

  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }

  output.append("Uninitialized Read Analysis\n")
  output.append("=" * 60 + "\n\n")

  // Collect all methods, optionally filtered by file
  val allMethods = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    cpg.method.filter(m => m.file.name.headOption.exists(_.matches(pattern))).l
  } else {
    cpg.method.l
  }

  // Filter out compiler-generated / library methods (no body)
  val candidateMethods = allMethods.filter(m => m.block.nonEmpty).l

  if (candidateMethods.isEmpty) {
    output.append("No methods found in the codebase.\n")
  } else {
    output.append(s"Analyzing ${candidateMethods.size} method(s) for uninitialized reads...\n\n")

    // (file, methodName, varName, varType, declLine, useLine, useCode, confidence, reason)
    val issues = mutable.ListBuffer[(String, String, String, String, Int, Int, String, String, String)]()

    candidateMethods.foreach { method =>
      val methName = method.name
      val methFile = method.file.name.headOption.getOrElse("unknown")

      // Pre-compute once per method — O(n) instead of O(locals × identifiers)
      val plainAssignments = method.call.nameExact("<operator>.assignment").l
      // IDs of identifiers that are the direct LHS of a plain assignment
      val lhsIds = plainAssignments.flatMap(_.argument.argumentIndex(1).l.headOption).map(_.id).toSet
      // Map varName → sorted list of plain-assignment line numbers
      val assignLinesByVar: Map[String, List[Int]] = plainAssignments
        .groupBy(c => c.argument.argumentIndex(1).l.headOption.map(_.code.trim).getOrElse(""))
        .view.mapValues(cs => cs.flatMap(_.lineNumber).sorted).toMap
      // Map varName → sorted lines where the variable's ADDRESS is taken (&x).
      // Passing &x to a function (memset(&x,…), scanf("%d",&x), read(fd,&x,…),
      // or any out-parameter) can initialize it, so the first such line is an
      // initialization boundary just like an assignment — without this, a read
      // after memset(&x,…)/scanf(…,&x) was a false "uninitialized" report.
      val addrOfLinesByVar: Map[String, List[Int]] =
        method.call.nameExact("<operator>.addressOf").l
          .flatMap { ao =>
            ao.argument.argumentIndex(1).l.headOption.collect {
              case id: Identifier => (id.name, ao.lineNumber.getOrElse(-1))
            }
          }
          .groupBy(_._1).view.mapValues(_.map(_._2).filter(_ > 0).sorted).toMap
      // Map varName → all identifier nodes (reads and compound-assign LHS)
      val identsByName: Map[String, List[Identifier]] =
        method.ast.isIdentifier.l.groupBy(_.name)

      method.local.l.foreach { local =>
        val varName  = local.name
        val varType  = local.typeFullName
        val declLine = local.lineNumber.getOrElse(-1)

        // Skip fixed-size arrays (covered by stack_overflow analysis)
        if (!varType.matches(".*\\[\\d*\\].*")) {
          val firstAssignLine: Option[Int] = assignLinesByVar.get(varName).flatMap(_.headOption)
          val firstAddrLine: Option[Int]   = addrOfLinesByVar.get(varName).flatMap(_.headOption)
          // Earliest point the variable may become initialized — by a plain
          // assignment OR by having its address escape to a function.
          val firstInitLine: Option[Int] =
            (firstAssignLine.toList ++ firstAddrLine.toList).reduceOption(_ min _)

          identsByName.getOrElse(varName, Nil).foreach { ident =>
            val readLine = ident.lineNumber.getOrElse(-1)
            if (readLine > 0 && declLine > 0) {
              // Skip: direct LHS of a plain assignment (x = ...)
              val isPlainLhs = lhsIds.contains(ident.id)
              // Skip: operand of addressOf — &x passes the address for output (scanf, read, etc.)
              val isAddressOf = {
                val p = ident.astParent
                p.isCall && p.asInstanceOf[Call].name == "<operator>.addressOf"
              }

              if (!isPlainLhs && !isAddressOf) {
                val isBeforeAssignment = firstInitLine match {
                  case None       => true
                  case Some(initLn) => readLine < initLn
                }
                if (isBeforeAssignment) {
                  val stmtCode = {
                    val parentCode = ident.astParent.code.trim
                    if (parentCode.length > 80) parentCode.take(77) + "..." else parentCode
                  }
                  val (confidence, reason) = firstInitLine match {
                    case None       => ("HIGH", "Variable declared but never assigned before use")
                    case Some(initLn)=> ("HIGH", s"Read at line $readLine precedes first initialization at line $initLn")
                  }
                  issues += ((methFile, methName, varName, varType, declLine, readLine, stmtCode, confidence, reason))
                }
              }
            }
          }
        }
      }
    }

    // Deduplicate and sort by file + method + read line
    val dedupIssues = issues.toList.distinct.sortBy(i => (i._1, i._2, i._6))

    if (dedupIssues.isEmpty) {
      output.append("No uninitialized read issues detected.\n")
      output.append("\nNote: This analysis looks for:\n")
      output.append("  - Local variables that are read before any explicit assignment\n")
      output.append("  - Local variables declared but never assigned (used with garbage value)\n")
      output.append("\nFiltered out:\n")
      output.append("  - Fixed-size array declarations (tracked by stack overflow analysis)\n")
      output.append("  - Identifier reads that are the direct LHS of an assignment\n")
    } else {
      output.append(s"Found ${dedupIssues.size} potential uninitialized read issue(s):\n\n")

      dedupIssues.take(maxResults).zipWithIndex.foreach { case ((file, meth, varName, varType, declLine, readLine, stmtCode, confidence, reason), idx) =>
        output.append(s"--- Issue ${idx + 1} ---\n")
        output.append(s"Confidence:  $confidence\n")
        output.append(s"CWE:         CWE-457 (Use of Uninitialized Variable)\n")
        output.append(s"Variable:    $varName  ($varType)\n")
        output.append(s"Declared:    $file:$declLine in $meth()\n")
        output.append(s"Read at:     $file:$readLine\n")
        output.append(s"Context:     $stmtCode\n")
        output.append(s"Reason:      $reason\n")
        output.append("\n")
      }

      if (dedupIssues.size > maxResults)
        output.append(s"(Showing $maxResults of ${dedupIssues.size} issues. Use limit parameter to see more.)\n\n")

      output.append(s"Total: ${dedupIssues.size} potential uninitialized read issue(s) found\n")
    }
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
