/*
 * Copyright (c) 2015, 2016, Yutaka Tsutano
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef JITANA_CALL_GRAPH_HPP
#define JITANA_CALL_GRAPH_HPP

#include "jitana/jitana.hpp"

/*Reana*/
//#include "jitana/vm_core/virtual_machine.hpp"
/*Reana*/

#include <algorithm>

#include <boost/type_erasure/any_cast.hpp>
#include <boost/range/iterator_range.hpp>

namespace jitana {
    struct method_call_edge_property {
        bool virtual_call;
        insn_vertex_descriptor caller_insn_vertex;
    };

    inline void print_graphviz_attr(std::ostream& os,
                                    const method_call_edge_property& prop)
    {
        os << "color=red, label=";
        os << (prop.virtual_call ? "virtual" : "direct");
        os << ", taillabel=" << prop.caller_insn_vertex;
    }

    inline void add_call_graph_edges(virtual_machine& vm,
                                     const method_vertex_descriptor& v)
    {
        using boost::type_erasure::any_cast;

        auto& mg = vm.methods();

        // Abort if we already have an outgoing call graph edge to avoid
        // creating duplicates. For performacnce, we should have flags
        // indicating if we have already computed the call graph for this edge.
        for (const auto& me : boost::make_iterator_range(out_edges(v, mg))) {
            if (any_cast<method_call_edge_property*>(&mg[me]) != nullptr) {
                return;
            }
        }

        auto ig = mg[v].insns;

        // Iterate over the instruction graph vertices.
        for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
            // Get the vertex property.
            const auto& prop = ig[iv];

            // Ignore if it is a non-DEX instruction.
            if (is_pseudo(prop.insn)) {
                continue;
            }

            // Determine the type of the instruction.
            method_call_edge_property eprop;
            const auto& insn_info = info(op(prop.insn));
            if (insn_info.can_virtually_invoke()) {
                eprop.virtual_call = true;
            }
            else if (insn_info.can_directly_invoke()) {
                eprop.virtual_call = false;
            }
            else {
                // Not an invoke instruction.
                continue;
            }
            eprop.caller_insn_vertex = iv;

            // Get the target method handle.
            dex_method_hdl method_hdl;
            if (insn_info.odex_only()) {
                // Optimized: uses vtable. Unless we know the type of the target
                // method's class, we cannot tell the method handle.
                // auto off =
                // any_cast<code::i_invoke_quick>(prop.insn).const_val;
                continue;
            }
            else {
                method_hdl = *const_val<dex_method_hdl>(prop.insn);
            }

            // Add an edge to the methood graph.
            auto target_v = vm.find_method(method_hdl, false);
            if (target_v) {
                add_edge(v, *target_v, eprop, mg);
            }
        }
    }

    inline void add_call_graph_edges(virtual_machine& vm)
    {
        auto& mg = vm.methods();
        std::for_each(vertices(mg).first, vertices(mg).second,
                      [&](const method_vertex_descriptor& v) {
                          add_call_graph_edges(vm, v);
                      });
    }


    /*Reana*/
//    inline void compute_callgraph(virtual_machine& vm,
//    		const method_vertex_descriptor& v) {
//    	using boost::type_erasure::any_cast;
//
//    	auto& mg = vm.methods();
//    	const auto& ig = mg[v].insns;
//
//    	// Abort if we already have an outgoing call graph edge to avoid
//    	// creating duplicates. For performacnce, we should have flags
//    	// indicating if we have already computed the call graph for this edge.
//    	for (const auto& me : boost::make_iterator_range(out_edges(v, mg))) {
//    		if (any_cast<method_call_edge_property*>(&mg[me]) != nullptr) {
//    			return;
//    		}
//    	}
//
//    	// Iterate over the instruction graph vertices.
//    	for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
//    		// Get the vertex property.
//    		const auto& prop = ig[iv];
//
//    		// Ignore if it is a non-DEX instruction.
//    		if (is_pseudo(prop.insn)) {
//    			continue;
//    		}
//
//    		// Determine the type of the instruction.
//    		method_call_edge_property eprop;
//    		const auto& insn_info = info(op(prop.insn));
//    		if (insn_info.can_virtually_invoke()) {
//    			eprop.virtual_call = true;
//    		} else if (insn_info.can_directly_invoke()) {
//    			eprop.virtual_call = false;
//    		} else {
//    			// Not an invoke instruction.
//    			continue;
//    		}
//    		eprop.caller_insn_vertex = iv;
//
//    		// Get the target method handle.
//    		dex_method_hdl method_hdl;
//    		if (insn_info.odex_only()) {
//    			// Optimized: uses vtable. Unless we know the type of the target
//    			// method's class, we cannot tell the method handle.
//    			// auto off =
//    			// any_cast<code::i_invoke_quick>(prop.insn).const_val;
//    			continue;
//    		} else {
//    			method_hdl = *const_val<dex_method_hdl>(prop.insn);
//    		}
//
//    		// Add an edge to the methood graph.
//    		auto target_v = vm.find_method(method_hdl, false);
//    		if (target_v) {
//    			add_edge(v, *target_v, eprop, mg);
//    		}
//    	}
//    }
//
//    inline void compute_callgraph(virtual_machine& vm) {
//    	auto& mg = vm.methods();
//    	std::for_each(vertices(mg).first, vertices(mg).second,
//    			[&](const method_vertex_descriptor& v) {
//    				compute_callgraph(vm, v);
//    			});
//    }
    /*Reana*/
}

#endif
