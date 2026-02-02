{
  import scala.util.Try
  val methodName = "{{method_name}}"
  val maxNodes = {{max_nodes}}
  val sb = new StringBuilder()

  val m = cpg.method.name(methodName).take(1).l.headOption
  m match {
    case Some(method) =>
      sb.append(s"Control Flow Graph for ${method.name}\n")
      sb.append("=" * 60 + "\n")

      val nodes = method.cfgNode.take(maxNodes).l
      val nodeIds = nodes.map(_.id).toSet
      
      sb.append("Nodes:\n")
      nodes.foreach { n =>
        val id = n.id
        val code = n.code.take(50).replaceAll("\n", " ")
        val typeName = n.getClass.getSimpleName
        sb.append(s"  [$id] $typeName: $code\n")
      }
      
      sb.append("\nEdges:\n")
      val edges = nodes.flatMap(n => 
        n.outE("CFG")
          .filter(e => nodeIds.contains(e.dst.id))
          .map(e => (n.id, e.dst.id, Option(e.property).map(_.toString).getOrElse("")))
      ).distinct

      if (edges.isEmpty) {
        sb.append("  (No control flow edges found)\n")
      } else {
        edges.foreach { case (from, to, label) =>
          val labelStr = if (label.toString.nonEmpty) s" [Label: $label]" else ""
          sb.append(s"  [$from] -> [$to]$labelStr\n")
        }
      }

    case None => 
      sb.append(s"Method not found: $methodName\n")
  }
  
  "<codebadger_result>\n" + sb.toString() + "</codebadger_result>"
}
