cpg.typeDecl.name("{{type_name}}").filter(_.member.nonEmpty).take({{limit}}).map { t =>
  Map(
    "_1" -> t.name,
    "_2" -> t.fullName,
    "_3" -> t.file.name.headOption.getOrElse("unknown"),
    "_4" -> t.lineNumber.getOrElse(-1),
    "_5" -> t.member.take(20).map(m => Map("name" -> m.name, "type" -> m.typeFullName)).l
  )
}.toJsonPretty
