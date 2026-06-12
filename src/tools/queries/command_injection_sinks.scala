{
  import io.shiftleft.codepropertygraph.generated.nodes._
  import io.shiftleft.semanticcpg.language._
  import scala.collection.mutable

  val sinkPattern = "{{sink_pattern}}"
  val fileFilter  = "{{file_filter}}"
  val maxResults  = {{max_results}}

  val output = new StringBuilder()

  def pathBoundaryRegex(f: String): String = {
    val escaped = java.util.regex.Pattern.quote(f)
    "(^|.*/)" + escaped + "$"
  }

  output.append("Command Injection Sink Analysis (CWE-78)\n")
  output.append("=" * 60 + "\n\n")

  val sinks = cpg.call
    .name(sinkPattern)
    .where(_.argument.argumentIndex(1).whereNot(_.isLiteral))

  val filtered = if (fileFilter.nonEmpty) {
    val pattern = pathBoundaryRegex(fileFilter)
    sinks.filter(_.file.name.headOption.exists(_.matches(pattern)))
  } else {
    sinks
  }

  val results = filtered.take(maxResults).l

  if (results.isEmpty) {
    output.append("No command injection sink call sites found.\n")
    output.append("All shell-execution calls use literal (constant) arguments.\n")
  } else {
    output.append(s"Found ${results.size} call site(s) with dynamic arguments:\n\n")

    results.zipWithIndex.foreach { case (c, idx) =>
      val code = if (c.code.length > 80) c.code.take(77) + "..." else c.code
      output.append(s"--- Site ${idx + 1} ---\n")
      output.append(s"Function: ${c.name}\n")
      output.append(s"Location: ${c.location.filename}:${c.location.lineNumber.getOrElse(-1)}\n")
      output.append(s"Method:   ${c.method.name}\n")
      output.append(s"Code:     $code\n\n")
    }

    output.append(s"Total: ${results.size} dynamic sink call site(s)\n")
    output.append("\nNext step: Use find_taint_flows(mode='auto') to confirm reachability from user input.\n")
  }

  "<codebadger_result>\n" + output.toString() + "</codebadger_result>"
}
