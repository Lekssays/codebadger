cpg.call.where(_.file.name(".*{{filename}}.*")){{line_filter}}.take(50).map { c =>
  Map(
    "_1" -> c.name,
    "_2" -> c.code.take(100),
    "_3" -> c.lineNumber.getOrElse(-1),
    "_4" -> c.file.name.headOption.getOrElse("unknown"),
    "_5" -> c.dispatchType
  )
}.toJsonPretty
