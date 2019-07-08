#ifndef JITANA_DATA_FLOW_HPP
#define JITANA_DATA_FLOW_HPP

#include <algorithm>
#include <vector>

#include <boost/graph/filtered_graph.hpp>
#include <boost/graph/properties.hpp>
#include <boost/type_erasure/any_cast.hpp>
#include <boost/range/iterator_range.hpp>
#include "jitana/analysis/monotonic_dataflow.hpp"
#include "jitana/vm_graph/edge_filtered_graph.hpp"
#include "jitana/vm_core/insn_info.hpp"
#include "jitana/vm_core/virtual_machine.hpp"

namespace jitana {
struct insn_data_flow_edge_property {
	register_idx reg_idx;
};

inline void print_graphviz_attr(std::ostream& os,
		const insn_data_flow_edge_property& prop) {
	os << "color=red, fontcolor=red";
	os << ", label=\"" << prop.reg_idx << "\"";
}

void compute_data_flow(virtual_machine& vm, insn_graph& g) {
	if (num_vertices(g) == 0) {
		return;
	}

	using elem = std::pair<insn_vertex_descriptor, register_idx>;
	using set = std::vector<elem>;
	using set_map = std::vector<set>;
	set_map inset_map(num_vertices(g));
	set_map outset_map(num_vertices(g));

	std::vector < std::vector < register_idx >> uses_map(num_vertices(g));
	std::vector < std::vector < register_idx >> defs_map(num_vertices(g));
	for (const auto& v : boost::make_iterator_range(vertices(g))) {
		defs_map[v] = defs(g[v].insn);
		uses_map[v] = uses(g[v].insn);
	}

	auto flow_func = [&](insn_vertex_descriptor v, const set& inset,
			set& outset) {
		outset = inset;

		// Kill.
			for (auto x : defs_map[v]) {
				auto e = std::remove_if(
						begin(outset), end(outset),
						[&](const elem& f) {return f.second == x;});
				outset.erase(e, end(outset));
			}

			// Gen.
			for (auto x : defs_map[v]) {
				outset.emplace_back(v, x);
			}
			std::sort(begin(outset), end(outset));
			outset.erase(std::unique(begin(outset), end(outset)), end(outset));
		};
	auto comb_op = [](set& x, const set& y) {
		set temp;
		std::set_union(begin(x), end(x), begin(y), end(y),
				std::back_inserter(temp));
		x = temp;
	};
	auto cfg = make_edge_filtered_graph<insn_control_flow_edge_property>(g);
	monotonic_dataflow(cfg, inset_map, outset_map, comb_op, flow_func);

	// Update the graph with the data flow information.
	remove_edge_if(make_edge_type_pred<insn_data_flow_edge_property>(g), g);
	for (const auto& v : boost::make_iterator_range(vertices(g))) {
		for (const auto& e : inset_map[v]) {
			if (e.first != v
					&& std::binary_search(begin(uses_map[v]), end(uses_map[v]),
							e.second)) {
				insn_data_flow_edge_property edge_prop;
				edge_prop.reg_idx = e.second;
				add_edge(e.first, v, edge_prop, g);
			}
		}
	}
}
}

#endif
