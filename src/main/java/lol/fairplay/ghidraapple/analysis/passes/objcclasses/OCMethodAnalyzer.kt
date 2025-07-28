package lol.fairplay.ghidraapple.analysis.passes.objcclasses

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.analysis.objectivec.TypeResolver
import lol.fairplay.ghidraapple.analysis.objectivec.modelling.StructureParsing
import lol.fairplay.ghidraapple.analysis.passes.selectortrampoline.ARCFixupInstallerAnalyzer.Companion.OBJC_WO_SEL_CC
import lol.fairplay.ghidraapple.analysis.utilities.address
import lol.fairplay.ghidraapple.analysis.utilities.parameterNamesForMethod
import lol.fairplay.ghidraapple.analysis.utilities.parseObjCListSection
import lol.fairplay.ghidraapple.core.objc.encodings.EncodedSignature
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass
import lol.fairplay.ghidraapple.core.objc.modelling.OCField
import lol.fairplay.ghidraapple.core.objc.modelling.OCMethod
import lol.fairplay.ghidraapple.core.objc.modelling.OCProperty
import lol.fairplay.ghidraapple.core.objc.modelling.OCProtocol
import lol.fairplay.ghidraapple.core.objc.modelling.ResolvedEntity
import lol.fairplay.ghidraapple.core.objc.modelling.ResolvedMethod
import lol.fairplay.ghidraapple.core.objc.modelling.ResolvedProperty

class OCMethodAnalyzer : AbstractAnalyzer(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER) {
    private var renameFromSelector: Boolean = true
    lateinit var program: Program
    lateinit var log: MessageLog

    companion object {
        const val NAME = "Objective-C: Method Analyzer"
        const val DESCRIPTION = "Performs a variety of method-related analyses."
        const val PROPERTY_TAG_GETTER = "OBJC_PROPERTY_GETTER"
        const val PROPERTY_TAG_SETTER = "OBJC_PROPERTY_SETTER"
        val PRIORITY = OCStructureAnalyzer.PRIORITY.after()
        private val OPTION_NAME_RENAME_METHOD_ARGUMENTS_FROM_SELECTOR: String = "Rename Method Arguments from Selector"
        private val OPTION_DESCRIPTION_RENAME_METHOD_ARGUMENTS_FROM_SELECTOR: String =
            "If enabled, rename method arguments based on the selector name."
    }

    init {
        priority = PRIORITY
        setDefaultEnablement(true)
    }

    override fun canAnalyze(program: Program): Boolean {
        this.program = program
        return program.memory.getBlock("__objc_classlist") != null
    }

    override fun added(
        program: Program,
        set: AddressSetView,
        monitor: TaskMonitor,
        log: MessageLog,
    ): Boolean {
        this.log = log

        monitor.message = "Reading classes..."

        val klasses = parseObjCListSection(program, "__objc_classlist") ?: return false

        monitor.maximum = klasses.size.toLong()
        monitor.message = "Parsing class structures..."

        val parser = StructureParsing(program)
        klasses.forEach { klassData ->
            monitor.incrementProgress()

            val model =
                runCatching {
                    parser.parseClass(klassData.address.unsignedOffset)
                }.onFailure { exception ->
                    Msg.error(this, "Could not parse class at ${klassData.address.unsignedOffset.toString(16)}", exception)
                }.getOrNull() ?: return@forEach

            monitor.message = "Propagating signatures for ${model.name}..."
            propagateSignatures(model, monitor)

            monitor.message = "Analyzing properties for ${model.name}..."
            processProperties(model, monitor)
        }

        return true
    }

    private fun propagateSignatures(
        klass: OCClass,
        taskMonitor: TaskMonitor?,
    ) {
        taskMonitor?.message = "Propagating signatures: ${klass.name}"

        val typeResolver = TypeResolver(program)
        val methods = klass.resolvedMethods()

        methods.forEach { resolution ->
            val method = resolution.concrete()

            if (method.implAddress == null) {
                Msg.error(this, "Method ${klass.name}->${method.name} has no implementation address!")
                return@forEach
            }

            if (method.parent != klass) {
                Msg.debug(this, "Method ${klass.name}->${method.name} does not belong to class ${klass.name}! Skipping...")
                return@forEach
            }

            val fcnEntity = program.listing.getFunctionAt(program.address(method.implAddress))
            if (fcnEntity == null) {
                Msg.error(this, "Could not find method ${klass.name}->${method.name} at ${method.implAddress}")
                return@forEach
            }

            val encSignature = resolution.bestSignature().first ?: return@forEach

            // Reconstruct the return type for the method.
            applySignature(typeResolver, encSignature, klass, method, fcnEntity)
            applyMethodInsights(resolution, fcnEntity)
        }
    }

    private fun <T : OCField> definitionChain(
        resolution: ResolvedEntity<T>,
        indent: String,
    ): String {
        // fixme: this is kind of sloppy
        val chain =
            resolution
                .chain()
                .reversed()
                .joinToString(" -> ") {
                    val type =
                        when (it.first) {
                            is OCClass -> "Class"
                            is OCProtocol -> "Protocol"
                            else -> "Category"
                        }

                    "${it.first.name} ($type)"
                }.let {
                    if (resolution.stack.size == 1) "" else "\n${indent}Origin: $it"
                }

        return chain
    }

    private fun applyMethodInsights(
        resolution: ResolvedMethod,
        fcnEntity: Function,
    ) {
        Msg.debug(this, "Applying method insights to ${resolution.concrete().name}...")
        val method = resolution.concrete()
        val chain = definitionChain(resolution, "        ")

        fcnEntity.comment =
            """
            
            Member of: ${method.parent.name}$chain
            
            ${method.prototypeString()}
            
            """.trimIndent()
    }

    private fun applySignature(
        typeResolver: TypeResolver,
        encSignature: EncodedSignature,
        klass: OCClass,
        method: OCMethod,
        fcnEntity: Function,
    ) {
        val returnDT =
            runCatching {
                typeResolver.buildParsed(encSignature.returnType.first)
            }.onFailure { exception ->
                Msg.error(this, "Could not parse return type for ${klass.name}->${method.name}", exception)
            }.getOrNull()

        // starting at 2 to skip `self` and SEL.
        val parameters = mutableListOf<ParameterImpl>()

        val recvType =
            typeResolver.tryResolveDefinedStructPtr(klass.name)
                ?: program.dataTypeManager.getDataType("/_objc2_/ID")!!

        parameters.add(ParameterImpl("self", recvType, 0, program))
//        parameters.add(ParameterImpl("selector", program.dataTypeManager.getDataType("/_objc2_/SEL")!!, 8, program))

        val newNames =
            if (renameFromSelector) {
                parameterNamesForMethod(method.name)
            } else {
                listOf()
        }
        // Reconstruct and apply parameter types.
        encSignature.parameters.forEachIndexed { i, (type, stackOffset, modifiers) ->
            val paramDT =
                runCatching {
                    typeResolver.buildParsed(type)
                }.onFailure { exception ->
                    Msg.error(
                        this,
                        "Could not parse argument ${i + 2} type for ${klass.name}->${method.name}",
                        exception,
                    )
                }.getOrNull() ?: return@forEachIndexed

            Msg.debug(this, "Applying argument ${i + 2} type to function for ${klass.name}->${method.name}...")

            parameters.add(ParameterImpl(newNames.getOrNull(i), paramDT, stackOffset, program))
        }

        val returnVar = fcnEntity.getReturn()
        if (returnDT != null) {
            returnVar.setDataType(returnDT, SourceType.ANALYSIS)
        }

        Msg.debug(this, newNames)

        fcnEntity.updateFunction(
            OBJC_WO_SEL_CC,
            returnVar,
            parameters,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true,
            SourceType.ANALYSIS,
        )
    }

    private fun applyPropertyInsights(
        resolution: ResolvedProperty,
        getter: Function,
        setter: Function?,
    ) {
        val declaration = resolution.concrete().declaration()
        val definitionChain = definitionChain(resolution, "        ")

        Msg.debug(this, "Applying property insights to ${resolution.concrete().name}...")

        getter.addTag(PROPERTY_TAG_GETTER)
        val comment =
            """
            
            Member of: ${resolution.concrete().parent.name}$definitionChain
            
            $declaration
            """.trimIndent()

        getter.comment = comment

        setter?.addTag(PROPERTY_TAG_SETTER)
        setter?.comment = comment
    }

    private fun processProperties(
        klass: OCClass,
        taskMonitor: TaskMonitor?,
    ) {
        val typeResolver = TypeResolver(program)

        val fm = program.functionManager
        if (fm.functionTagManager.getFunctionTag(PROPERTY_TAG_GETTER) == null) {
            fm.functionTagManager.createFunctionTag(PROPERTY_TAG_GETTER, "Objective-C Property Getter Implementation")
        }
        if (fm.functionTagManager.getFunctionTag(PROPERTY_TAG_SETTER) == null) {
            fm.functionTagManager.createFunctionTag(PROPERTY_TAG_SETTER, "Objective-C Property Setter Implementation")
        }

        val baseMethods = klass.baseInstanceMethods?.associateBy { it.name } ?: return

        klass.resolvedProperties().forEach {
            val property = it.concrete()

            taskMonitor?.message = "Analyzing property: ${property.name}"

            val getterName = property.customGetter ?: property.name
            val setterName = property.customSetter ?: "set${property.name.replaceFirstChar { it.uppercase() }}:"

            val methodGetter = baseMethods[getterName] ?: return@forEach
            val methodSetter = baseMethods[setterName]

            val getter = fm.getFunctionAt(program.address(methodGetter.implAddress!!.toLong()))
            val setter = methodSetter?.let { fm.getFunctionAt(program.address(it.implAddress!!.toLong())) }

            applyPropertySignature(typeResolver, property, getter, setter)
            applyPropertyInsights(it, getter, setter)
        }
    }

    private fun applyPropertySignature(
        typeResolver: TypeResolver,
        property: OCProperty,
        getter: Function,
        setter: Function?,
    ) {
        Msg.debug(this, "Applying property signatures for: ${property.name}...")
        val propertyType =
            runCatching {
                typeResolver.buildParsed(property.type!!.first)
            }.onFailure {
                Msg.error(this, "Could not parse property type for ${property.name}", it)
            }.getOrNull() ?: return

        getter.setReturnType(propertyType, SourceType.ANALYSIS)

        val setterParam = setter?.getParameter(2) ?: return
        setterParam.setDataType(propertyType, SourceType.ANALYSIS)
        setterParam.setName("value", SourceType.ANALYSIS)
    }

    override fun registerOptions(options: Options, program: Program) {
        options.registerOption(
            OPTION_NAME_RENAME_METHOD_ARGUMENTS_FROM_SELECTOR, renameFromSelector, null,
            OPTION_DESCRIPTION_RENAME_METHOD_ARGUMENTS_FROM_SELECTOR
        )
    }

    override fun optionsChanged(options: Options, program: Program) {
        renameFromSelector =
            options.getBoolean(OPTION_NAME_RENAME_METHOD_ARGUMENTS_FROM_SELECTOR, renameFromSelector)
    }

}
