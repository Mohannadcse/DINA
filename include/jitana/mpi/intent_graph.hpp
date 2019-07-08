/*
 * intent_graph.hpp
 *
 *  Created on: Aug 24, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_INTENT_GRAPH_HPP_
#define INCLUDE_JITANA_MPI_INTENT_GRAPH_HPP_


#include "jitana/vm_core/class_loader.hpp"
#include "jitana/vm_core/apk_info.hpp"
#include "jitana/vm_graph/graph_common.hpp"

#include <iostream>
#include <vector>

#include <boost/range/iterator_range.hpp>

namespace jitana {
    namespace detail {
        using intent_graph_traits
                = boost::adjacency_list_traits<boost::vecS, boost::vecS,
                                               boost::bidirectionalS>;
    }

    ///intent vertex descriptor.
    using intent_vertex_descriptor
            = detail::intent_graph_traits::vertex_descriptor;

    ///intent edge descriptor.
    using intent_edge_descriptor = detail::intent_graph_traits::edge_descriptor;

    ///intent graph vertex property.
    struct intent_vertex_property {
        std::string componentName;
        std::string methodName_strAction;
        std::string methodName_intentSndng;
        jitana::method_graph::vertex_descriptor md_strAction;
        jitana::method_graph::vertex_descriptor md_intentSndRecAPI;
        jitana::method_graph::vertex_descriptor md_sensAPI;
        std::string appPkgName;
        int loaderID;
        boost::optional<dex_method_hdl> hdl;
        jvm_method_hdl jvm_hdl;
        bool contain_sensitive_method; //indicate if the node contains sensetive APIs
        std::string analysisType; //differentiate nodes that created at static analysis or dynamic analysis
    };

    struct intent_edge_property {
    	enum { explicit_intent, implicit_intent } kind;
    	std::string intentAction;
    };

    /// A loader graph edge property.
    //using intent_edge_property = any_edge_property;

    /// A loader graph property.
    struct intent_graph_property {
    };

    /// New intent graph.
    using intent_graph = boost::adjacency_list<
            boost::vecS, boost::vecS, boost::bidirectionalS,
			intent_vertex_property, intent_edge_property,
			intent_graph_property>;

    inline void print_graphviz_attr(std::ostream& os,
                                    const intent_edge_property& prop)
    {
        os << "label=" << boost::escape_dot_string(prop.intentAction) << ", ";
        switch (prop.kind) {
        case intent_edge_property::explicit_intent:
            os << "fontcolor=red, color=red";
            break;
        case intent_edge_property::implicit_intent:
            os << "fontcolor=darkgreen, color=darkgreen";
            break;
        }
    }

}



#endif /* INCLUDE_JITANA_MPI_INTENT_GRAPH_HPP_ */
