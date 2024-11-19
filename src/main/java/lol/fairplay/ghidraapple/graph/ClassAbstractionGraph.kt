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
        var previousVertex: AttributedVertex? = null
        var currentClass: OCClass? = classModel
        var currentVertex = classVertex(classModel.name)

        while (currentClass != null) {
            if (previousVertex != null) createInheritsEdge(currentVertex, previousVertex)
            currentClass.baseProtocols?.forEach {
                val baseProtocol = it.name
                val baseProtocolVertex = protoVertex(baseProtocol)
                createImplementsEdge(baseProtocolVertex, currentVertex)
            }
            previousVertex = currentVertex
            currentClass = currentClass.superclass ?: break
            currentVertex = classVertex(currentClass.name)
        }
    }

    private fun protoVertex(name: String): AttributedVertex {
        val v =  graph.addVertex(name)
        v.setAttribute("color", "blue")
        return v
    }

    private fun classVertex(name: String): AttributedVertex {
        val v = graph.addVertex(name)
        return v
    }

    private fun createInheritsEdge(from: AttributedVertex, to: AttributedVertex) {
        val newEdge = graph.addEdge(from, to)
        newEdge.description = "inherits"
    }

    private fun createImplementsEdge(from: AttributedVertex, to: AttributedVertex) {
        val newEdge = graph.addEdge(from, to)
        newEdge.setAttribute("color", "blue")
        newEdge.description = "implements"
    }

}