/*
 * Copyright (c) 2016, Yutaka Tsutano
 * Copyright (c) 2016, Shakthi Bachala
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

#ifndef JITANA_INTENT_FLOW_INTRAPROCEDURAL_HPP
#define JITANA_INTENT_FLOW_INTRAPROCEDURAL_HPP

#include "intent_flow.hpp"

/*DINA*/
std::vector<std::pair <jitana::method_graph::vertex_descriptor,jitana::class_graph::vertex_descriptor>> iac_pair_vd;
/*DINA*/

namespace jitana {
    inline void
    add_explicit_intent_flow_edges_intraprocedural(virtual_machine& vm);
    inline void
    add_implicit_intent_flow_edges_intraprocedural(virtual_machine& vm);

    inline void add_intent_flow_edges_intraprocedural(virtual_machine& vm)
    {
        add_explicit_intent_flow_edges_intraprocedural(vm);
        add_implicit_intent_flow_edges_intraprocedural(vm);
    }
}

namespace jitana {
    inline void
    add_explicit_intent_flow_edges_intraprocedural(virtual_machine& vm)
    {
        // I have fixed most of the logical errors. But there are some
        // fundamental problems from the original code design that are severely
        // affecting the accuracy:
        //
        // 1. It assumes that everyone uses Intent.setClassName(String, String),
        //    and ignore setClass(Context, Class<?>), setClassName(Context,
        //    String), setComponent(ComponentName), etc. This means that we are
        //    not detecting all explicit intents.
        //
        // 2. It assumes that the class name is generated using const-string
        //    instruction within the same class. It can be generated dynamically
        //    or created in other methods. I see only about a half of the
        //    explicit intents that were found by searching for the invoke
        //    instructions calling Intent.setClassName(String, String) use
        //    const-string in a same method, so we are missing the targets of
        //    the other half.

        auto intent_handlers = detail::compute_explicit_intent_handlers(vm);

        jvm_method_hdl intent_mh = {{0, "Landroid/content/Intent;"},
                                    "setClassName(Ljava/lang/String;Ljava/"
                                    "lang/String;)Landroid/content/Intent;"};
        auto intent_mv = vm.find_method(intent_mh, true);

        const auto& mg = vm.methods();
        auto& lg = vm.loaders();
        
        std::pair<jitana::method_graph::vertex_descriptor,jitana::class_graph::vertex_descriptor> iac_pair;
        
        for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
            const auto& ig = mg[mv].insns;
            for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                const auto* invoke_insn = get<insn_invoke>(&ig[iv].insn);
                if (!invoke_insn) {
                    continue;
                }

                auto target_mv = vm.find_method(invoke_insn->const_val, true);
                if (!target_mv || *target_mv != intent_mv) {
                    continue;
                }
                auto class_name_reg = invoke_insn->regs[2];

                for (const auto& e :
                     boost::make_iterator_range(in_edges(iv, ig))) {
                    using boost::type_erasure::any_cast;
                    using df_edge_prop_t = insn_def_use_edge_property;
                    const auto* de = any_cast<const df_edge_prop_t*>(&ig[e]);
                    if (!de || de->reg != class_name_reg) {
                        continue;
                    }

                    const auto& source_insn = ig[source(e, ig)].insn;
                    const auto* cs_insn = get<insn_const_string>(&source_insn);
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
                            iac_pair.first = mv;
                        }
                    }
                }
            }
        }
    }

    inline void
    add_implicit_intent_flow_edges_intraprocedural(virtual_machine& vm)
    {
        // I have fixed most of the logical errors. But there are some
        // fundamental problems from the original code design that are severely
        // affecting the accuracy. The problem is very similar to the explicit
        // version, so read the comment in them.

        std::pair<jitana::method_graph::vertex_descriptor,jitana::class_graph::vertex_descriptor> iac_pair;
        
        auto intent_handlers = detail::compute_implicit_intent_handlers(vm);

        auto& lg = vm.loaders();
        const auto& mg = vm.methods();
        
        jvm_method_hdl intent_mh
                = {{0, "Landroid/content/Intent;"},
                   "setAction(Ljava/lang/String;)Landroid/content/Intent;"};
        auto intent_mv = vm.find_method(intent_mh, true);

        for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
            const auto& ig = mg[mv].insns;

            for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                const auto* invoke_insn = get<insn_invoke>(&ig[iv].insn);
                if (!invoke_insn) {
                    continue;
                }

                auto target_mv = vm.find_method(invoke_insn->const_val, true);
                if (!target_mv || *target_mv != intent_mv) {
                    continue;
                }
                auto action_string_reg = invoke_insn->regs[1];

                for (const auto& e :
                     boost::make_iterator_range(in_edges(iv, ig))) {
                    using boost::type_erasure::any_cast;
                    using df_edge_prop_t = insn_def_use_edge_property;
                    const auto* de = any_cast<const df_edge_prop_t*>(&ig[e]);
                    if (!de || de->reg != action_string_reg) {
                        continue;
                    }

                    const auto& source_insn = ig[source(e, ig)].insn;
                    const auto* cs_insn = get<insn_const_string>(&source_insn);
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
                            iac_pair.first = mv;
                            iac_pair_vd.push_back(iac_pair);
                        }
                    }
                }
            }
        }
    }
}

#endif
