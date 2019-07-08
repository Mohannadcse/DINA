/*
 * Copyright (c) 2016, Yutaka Tsutano
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

#ifndef JITANA_INTENT_FLOW_STRING_HPP
#define JITANA_INTENT_FLOW_STRING_HPP

#include "intent_flow.hpp"

#include <boost/range/iterator_range.hpp>

// DINA
typedef jitana::method_graph::vertex_descriptor vd_mg;
std::unordered_map <std::string,std::vector <vd_mg>> int_str_method_explicit;
std::unordered_map <std::string,std::vector <vd_mg>> int_str_method_implicit;

namespace jitana {
    inline void add_explicit_intent_flow_edges_string(virtual_machine& vm);
    inline void add_implicit_intent_flow_edges_string(virtual_machine& vm);

    inline void add_intent_flow_edges_string(virtual_machine& vm)
    {
        add_explicit_intent_flow_edges_string(vm);
        add_implicit_intent_flow_edges_string(vm);
    }
}

namespace jitana {
    inline void add_explicit_intent_flow_edges_string(virtual_machine& vm)
    {
        auto intent_handlers = detail::compute_explicit_intent_handlers(vm);

        auto& lg = vm.loaders();
        const auto& mg = vm.methods();

        for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
            const auto& ig = mg[mv].insns;

            for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                const auto* cs_insn = get<insn_const_string>(&ig[iv].insn);
                if (!cs_insn) {
                    continue;
                }

                auto it = intent_handlers.find(cs_insn->const_val);
                if (it != end(intent_handlers)) {
                    intent_flow_edge_property prop;
                    prop.kind = intent_flow_edge_property::explicit_intent;
                    prop.description = cs_insn->const_val;
                    auto lv = *find_loader_vertex(
                            mg[mv].hdl.file_hdl.loader_hdl, lg);
                    for (const auto& target_lv : it->second) {
                        add_edge(lv, target_lv, prop, lg);
                        // DINA
                        int_str_method_explicit[cs_insn->const_val].push_back(mv);
                    }
                }
            }
        }
    }

    inline void add_implicit_intent_flow_edges_string(virtual_machine& vm)
    {
        auto intent_handlers = detail::compute_implicit_intent_handlers(vm);

        auto& lg = vm.loaders();
        const auto& mg = vm.methods();

        for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
            const auto& ig = mg[mv].insns;

            for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                const auto* cs_insn = get<insn_const_string>(&ig[iv].insn);
                if (!cs_insn) {
                    continue;
                }

                auto it = intent_handlers.find(cs_insn->const_val);
                if (it != end(intent_handlers)) {
                    intent_flow_edge_property prop;
                    prop.kind = intent_flow_edge_property::implicit_intent;
                    prop.description = cs_insn->const_val;
                    auto lv = *find_loader_vertex(
                            mg[mv].hdl.file_hdl.loader_hdl, lg);
                    for (const auto& target_lv : it->second) {
                        add_edge(lv, target_lv, prop, lg);
                        // DINA
                        int_str_method_implicit[cs_insn->const_val].push_back(mv);
                    }
                }
            }
        }
    }
}

std::unordered_map <std::string,std::vector <vd_mg>> get_sending_methods(bool edge_type)
{
    if (edge_type)
        return int_str_method_explicit;
    else
        return int_str_method_implicit;
}
/*
void print_sending_methods(bool edge_type, jitana::virtual_machine& vm)
{
    if (edge_type){
        //Explicit
        for (auto& x : int_str_method_explicit) {
            jitana::unique_sort(x.second);
        }
        auto it = int_str_method_explicit.begin();
        std::cout << "\n\nExplicit size::" << int_str_method_explicit.size() << "\n";
        while (it != int_str_method_explicit.end())
        {
            std::cout << it->first << " :: " << (it->second).size()<< std::endl;
            for (auto v_it = (it->second).begin() ; v_it != (it->second).end(); v_it++){
//                std::cout << vm.methods()[*v_it].hdl.file_hdl.loader_hdl <<" :: "
//                          << vm.methods()[*v_it].jvm_hdl.type_hdl.descriptor <<" :: "
//                          << vm.methods()[*v_it].jvm_hdl.unique_name <<std::endl;
                
                const auto& ig = vm.methods()[*v_it].insns;
                std::stringstream ss;
                ss << "output/insn/" << vm.methods()[*v_it].hdl << ".dot";
                std::ofstream ofs(ss.str());
                write_graphviz_insn_graph(ofs, ig);
            }
            it++;
        }
    } else {
        //Implicit
        for (auto& x : int_str_method_implicit) {
            jitana::unique_sort(x.second);
        }
        std::cout << "\n\nImplicit size::" << int_str_method_implicit.size() << "\n";
        auto it = int_str_method_implicit.begin();
        while (it != int_str_method_implicit.end())
        {
            std::cout << it->first << " :: " << (it->second).size()<< std::endl;
//            for (auto v_it = (it->second).begin() ; v_it != (it->second).end(); v_it++){
//                std::cout << vm.methods()[*v_it].hdl.file_hdl.loader_hdl <<" :: "
//                          << vm.methods()[*v_it].jvm_hdl.type_hdl.descriptor <<" :: "
//                          << vm.methods()[*v_it].jvm_hdl.unique_name <<std::endl;
//            }
            it++;
        }
    }
}
 */

#endif
