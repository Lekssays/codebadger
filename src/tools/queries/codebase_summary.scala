{
    val numFiles = cpg.file.size
    val numMethods = cpg.method.size
    val numMethodsUser = cpg.method.isExternal(false).size
    val numCalls = cpg.call.size
    val numLiterals = cpg.literal.size
    val language = cpg.metaData.language.headOption.getOrElse("unknown")
    
    Map(
        "success" -> true,
        "language" -> language,
        "total_files" -> numFiles,
        "total_methods" -> numMethods,
        "user_defined_methods" -> numMethodsUser,
        "total_calls" -> numCalls,
        "total_literals" -> numLiterals
    ).toJsonPretty
}
