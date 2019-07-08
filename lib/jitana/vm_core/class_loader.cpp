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

#include "jitana/vm_core/class_loader.hpp"
#include "jitana/vm_core/virtual_machine.hpp"
#include "jitana/vm_core/dex_file.hpp"

using namespace jitana;
using namespace jitana::detail;

dex_file_hdl class_loader::add_file(const std::string& filename)
{
    dex_file_hdl file_hdl;
    file_hdl.loader_hdl = hdl_;
    file_hdl.idx = uint8_t(impl_->dex_files.size());
    impl_->dex_files.emplace_back(file_hdl, filename);
    return file_hdl;
}

boost::optional<class_vertex_descriptor>
class_loader::load_class(virtual_machine& vm,
                         const std::string& descriptor) const
{
    // Try to lookup first.
    if (auto v = lookup_class(vm, descriptor)) {
        return v;
    }

    // Load the class from one of the DEX files.
    for (const auto& df : impl_->dex_files) {
        if (auto v = df.load_class(vm, descriptor)) {
            return v;
        }
    }

    return boost::none;
}

boost::optional<class_vertex_descriptor>
class_loader::lookup_class(virtual_machine& vm,
                           const std::string& descriptor) const
{
    return lookup_class_vertex({hdl_, descriptor}, vm.classes());
}

boost::optional<method_vertex_descriptor>
class_loader::lookup_method(virtual_machine& vm, const std::string& descriptor,
                            const std::string& unique_name) const
{
    return lookup_method_vertex({{hdl_, descriptor}, unique_name},
                                vm.methods());
}

boost::optional<field_vertex_descriptor>
class_loader::lookup_field(virtual_machine& vm, const std::string& descriptor,
                           const std::string& name) const
{
    return lookup_field_vertex({{hdl_, descriptor}, name}, vm.fields());
}

bool class_loader::load_all_classes(virtual_machine& vm) const
{
    auto loaded_all_classes = true;

    for (const auto& df : impl_->dex_files) {
        if (!df.load_all_classes(vm)) {
            loaded_all_classes = false;
        }
    }

    return loaded_all_classes;
}

std::string class_loader::descriptor(const dex_type_hdl& hdl) const
{
    const auto& dex_file = dex_files()[hdl.file_hdl.idx];
    return dex_file.ids().descriptor(dex_type_idx(hdl.idx));
}

std::string class_loader::class_descriptor(const dex_method_hdl& hdl) const
{
    const auto& dex_file = dex_files()[hdl.file_hdl.idx];
    return dex_file.ids().class_descriptor(dex_method_idx(hdl.idx));
}

std::string class_loader::unique_name(const dex_method_hdl& hdl) const
{
    const auto& dex_file = dex_files()[hdl.file_hdl.idx];
    return dex_file.ids().unique_name(dex_method_idx(hdl.idx));
}

std::string class_loader::class_descriptor(const dex_field_hdl& hdl) const
{
    const auto& dex_file = dex_files()[hdl.file_hdl.idx];
    return dex_file.ids().class_descriptor(dex_field_idx(hdl.idx));
}

std::string class_loader::name(const dex_field_hdl& hdl) const
{
    const auto& dex_file = dex_files()[hdl.file_hdl.idx];
    return dex_file.ids().name(dex_field_idx(hdl.idx));
}