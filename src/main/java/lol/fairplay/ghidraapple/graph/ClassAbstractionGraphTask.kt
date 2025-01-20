package lol.fairplay.ghidraapple.graph

import ghidra.app.services.GraphDisplayBroker
import ghidra.framework.plugintool.PluginTool
import ghidra.service.graph.AttributedGraph
import ghidra.service.graph.AttributedVertex
import ghidra.service.graph.DefaultGraphDisplayOptions
import ghidra.service.graph.EmptyGraphType
import ghidra.util.task.Task
import ghidra.util.task.TaskMonitor
import lol.fairplay.ghidraapple.core.objc.modelling.OCClass
import lol.fairplay.ghidraapple.core.objc.modelling.OCFieldContainer
import lol.fairplay.ghidraapple.core.objc.modelling.OCProtocol

// reference code: ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphTask

class ClassAbstractionGraphTask(
    val tool: PluginTool,
    val graphService: GraphDisplayBroker,
    val classModel: OCClass,
) : Task("Graph Objective-C Class Abstraction", true, false, true) {
    lateinit var graph: AttributedGraph

    override fun run(monitor: TaskMonitor?) {
        buildAndDisplayGraph(monitor!!)
    }

    private fun buildAndDisplayGraph(monitor: TaskMonitor) {
        graph = AttributedGraph("Objective-C Class Abstraction", EmptyGraphType())
        buildGraph()

        val description = "Abstraction Graph for ${classModel.name}"
        val display = graphService.getDefaultGraphDisplay(false, monitor)
        val options = DefaultGraphDisplayOptions()
        options.edgeColorOverrideAttributeKey = "color"
        options.vertexColorOverrideAttributeKey = "color"
        display.setGraph(graph, options, description, false, monitor)
    }

    private fun buildGraph() {
        val visited = mutableSetOf<String>()
        val stack = mutableListOf<OCFieldContainer>()
        stack.add(classModel)

        while (stack.isNotEmpty()) {
            val current = stack.removeLast()

            if (current is OCClass) {
                val cVertex = getOrCreateClassVertex(current.name)
                current.baseProtocols?.forEach { protocol ->
                    val protoVertex = getOrCreateProtoVertex(protocol.name)
                    createImplementsEdge(protoVertex, cVertex)
                    if (!visited.contains(protocol.name)) {
                        stack.add(protocol)
                    }
                }
                current.superclass?.let {
                    val superVertex = getOrCreateClassVertex(it.name)
                    createInheritsEdge(superVertex, cVertex)
                    if (!visited.contains(it.name)) {
                        stack.add(it)
                    }
                }
            } else if (current is OCProtocol) {
                val pVertex = getOrCreateProtoVertex(current.name)
                current.protocols?.forEach { protocol ->
                    val protoVertex = getOrCreateProtoVertex(protocol.name)
                    createImplementsEdge(protoVertex, pVertex)
                    if (!visited.contains(protocol.name)) {
                        stack.add(protocol)
                    }
                }
            }

            visited.add(current.name)
        }
    }

    private fun getOrCreateProtoVertex(name: String): AttributedVertex {
        if (graph.getVertex(name) != null) return graph.getVertex(name)!!

        val v = graph.addVertex(name)
        v.setAttribute("color", "blue")
        return v
    }

    private fun getOrCreateClassVertex(name: String): AttributedVertex {
        if (graph.getVertex(name) != null) return graph.getVertex(name)!!

        val v = graph.addVertex(name)
        return v
    }

    private fun createInheritsEdge(
        from: AttributedVertex,
        to: AttributedVertex,
    ) {
        val newEdge = graph.addEdge(from, to)
        newEdge.description = "inherits"
    }

    private fun createImplementsEdge(
        from: AttributedVertex,
        to: AttributedVertex,
    ) {
        val newEdge = graph.addEdge(from, to)
        newEdge.setAttribute("color", "blue")
        newEdge.description = "implements"
    }
}
