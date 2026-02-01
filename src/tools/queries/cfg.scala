{
  val m = cpg.method.name("{{method_name}}").take(1).l.headOption
  m match {
    case Some(method) =>
      val nodes = method.cfgNode.take({{max_nodes}}).map(n => Map(
        "_1" -> n.id,
        "_2" -> n.code.take(100),
        "_3" -> n.getClass.getSimpleName
      )).l
      val nodeIds = nodes.map(_("_1")).toSet
      val edges = method.cfgNode.take({{max_nodes}}).flatMap(n => 
        n.cfgNext.filter(next => nodeIds.contains(next.id)).map(next => 
          Map("_1" -> n.id, "_2" -> next.id)
        )
      ).l.distinct
      Map("nodes" -> nodes, "edges" -> edges)
    case None => Map("nodes" -> List(), "edges" -> List())
  }
}.toJsonPretty
