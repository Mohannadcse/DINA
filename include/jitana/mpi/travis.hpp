/*
 * travis.hpp
 *
 *  Created on: Sep 20, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_TRAVIS_HPP_
#define INCLUDE_JITANA_MPI_TRAVIS_HPP_

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

#include <iostream>
#include <vector>
#include <thread>
#include <fstream>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <jitana/jitana.hpp>
#include <jitana/util/jdwp.hpp>
#include <jitana/analysis/call_graph.hpp>
#include <jitana/analysis/def_use.hpp>

#include <unistd.h>
#include <sys/wait.h>


struct insn_counter {
    long long counter = 0;
    long long delta = 0;
    long long last_accessed = 0;
    boost::optional<std::pair<jitana::method_vertex_descriptor,
                              jitana::insn_vertex_descriptor>>
            vertices;
};

struct dex_file {
    std::string apk_filename;
    std::string odex_filename;
    std::unordered_map<uint32_t, insn_counter> counters;
    boost::optional<jitana::dex_file_hdl> hdl;
};

std::vector<dex_file> dex_files;

static bool periodic_output = false;
static bool should_terminate = false;

static jitana::virtual_machine vm;
static jitana::class_loader_hdl system_loader_hdl = 0;
static jitana::class_loader_hdl app_loader_hdl = 1;


//constexpr int line_length = 128;

//static void update_graphs();

static void update_graphs()
{
    for (auto& dex : dex_files) {
        if (!dex.hdl) {
            continue;
        }

        for (auto& c : dex.counters) {
            auto& offset = c.first;
            auto& ictr = c.second;
            auto& vertices = ictr.vertices;
            if (!vertices) {
                vertices = vm.find_insn(*dex.hdl, offset, true);
            }
            if (vertices) {
                vm.methods()[vertices->first].insns[vertices->second].counter
                        = ictr.counter;
            }
            else {
                std::cerr << "failed to find the vertex: ";
                std::cerr << *dex.hdl << " " << offset << "\n";
            }
        }
    }
}

static void write_graphviz()
{
    std::cout << "adding call graph edges... " << std::flush;
    jitana::add_call_graph_edges(vm);
    std::cout << "done." << std::endl;

    std::cout << "writing the graphs... " << std::flush;

    {
        std::ofstream ofs("output/loader_graph.dot");
        write_graphviz_loader_graph(ofs, vm.loaders());
    }

    {
        std::ofstream ofs("output/class_graph.dot");
        write_graphviz_class_graph(ofs, vm.classes());
    }

    {
        std::ofstream ofs("output/method_graph.dot");
        write_graphviz_method_graph(ofs, vm.methods());
    }

    auto mg = vm.methods();
    for (const auto& v : boost::make_iterator_range(vertices(mg))) {
        const auto& mprop = mg[v];
        const auto& ig = mprop.insns;

        if (mprop.class_hdl.file_hdl.loader_hdl == 0) {
            continue;
        }

        if (num_vertices(ig) == 0) {
            continue;
        }

        std::stringstream ss;
        ss << "output/insn/" << mprop.hdl << ".dot";
        std::ofstream ofs(ss.str());
        write_graphviz_insn_graph(ofs, ig);
    }

    std::cout << "done." << std::endl;
}

static void write_traces()
{
    std::ofstream ofs("output/traces.csv");

    ofs << "loader,dex,class_idx,method_idx,";
    ofs << "offset,counter,line_num,";
    ofs << "class descriptor,method unique name\n";

    const auto& cg = vm.classes();
    const auto& mg = vm.methods();
    for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
        const auto& ig = mg[mv].insns;
        for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
            if (!is_basic_block_head(iv, ig)) {
                continue;
            }

            const auto& cv = vm.find_class(mg[mv].class_hdl, false);
            if (!cv) {
                continue;
            }

            const auto& mprop = mg[mv];
            const auto& cprop = cg[*cv];
            const auto& iprop = ig[iv];

            if (mprop.class_hdl.file_hdl.loader_hdl == 0) {
                continue;
            }

            ofs << unsigned(mprop.class_hdl.file_hdl.loader_hdl) << ",";
            ofs << unsigned(mprop.class_hdl.file_hdl.idx) << ",";
            ofs << unsigned(mprop.class_hdl.idx) << ",";
            ofs << unsigned(mprop.hdl.idx) << ",";
            ofs << iprop.off << ",";
            ofs << iprop.counter << ",";
            ofs << iprop.line_num << ",";
            ofs << cprop.jvm_hdl.descriptor << ",";
            ofs << mprop.jvm_hdl.unique_name << "\n";
        }
    }
}

static void write_vtables()
{
    std::ofstream ofs("output/vtables.csv");

    ofs << "class handle, class descriptor, vtable index, ";
    ofs << "super class handle, super class descriptor, ";
    ofs << "method handle, method unique name\n";

    const auto& cg = vm.classes();
    const auto& mg = vm.methods();
    for (const auto& cv : boost::make_iterator_range(vertices(cg))) {
        const auto& vtable = cg[cv].vtable;
        for (unsigned i = 0; i < vtable.size(); ++i) {
            const auto& mh = vtable[i];
            auto mv = vm.find_method(mh, true);
            if (!mv) {
                throw std::runtime_error("invalid vtable entry");
            }

            auto super_cv = vm.find_class(mg[*mv].class_hdl, true);
            if (!super_cv) {
                throw std::runtime_error("invalid vtable entry");
            }

            ofs << cg[cv].hdl << ",";
            ofs << cg[cv].jvm_hdl.descriptor << ",";
            ofs << i << ",";
            ofs << cg[*super_cv].hdl << ",";
            ofs << cg[*super_cv].jvm_hdl.descriptor << ",";
            ofs << mg[*mv].hdl << ",";
            ofs << mg[*mv].jvm_hdl.unique_name << ",";
            ofs << "\n";
        }
    }
}

static void write_dtables()
{
    std::ofstream ofs("output/dtables.csv");

    ofs << "class handle, class descriptor, dtable index, ";
    ofs << "super class handle, super class descriptor, ";
    ofs << "method handle, method unique name\n";

    const auto& cg = vm.classes();
    const auto& mg = vm.methods();
    for (const auto& cv : boost::make_iterator_range(vertices(cg))) {
        const auto& dtable = cg[cv].dtable;
        for (unsigned i = 0; i < dtable.size(); ++i) {
            const auto& mh = dtable[i];
            auto mv = vm.find_method(mh, true);
            if (!mv) {
                throw std::runtime_error("invalid dtable entry");
            }

            auto super_cv = vm.find_class(mg[*mv].class_hdl, true);
            if (!super_cv) {
                throw std::runtime_error("invalid dtable entry");
            }

            ofs << cg[cv].hdl << ",";
            ofs << cg[cv].jvm_hdl.descriptor << ",";
            ofs << i << ",";
            ofs << cg[*super_cv].hdl << ",";
            ofs << cg[*super_cv].jvm_hdl.descriptor << ",";
            ofs << mg[*mv].hdl << ",";
            ofs << mg[*mv].jvm_hdl.unique_name << ",";
            ofs << "\n";
        }
    }
}

void pull_apk_files()
{
    pid_t pid = ::fork();
    if (pid == 0) {
        // Run the shell script.
        ::execl("pull-apks", "pull-apks", nullptr);
    }
    else if (pid > 0) {
        int status = 0;
        ::waitpid(pid, &status, 0);
    }
    else {
        throw std::runtime_error("failed to pull APK files");
    }
}

std::string make_local_filename(const std::string& apk_filename)
{
    if (apk_filename.size() < 2 || apk_filename[0] != '/') {
        throw std::invalid_argument("invalid APK file name");
    }

    std::string filename = "apks-extracted/";
    std::replace_copy(begin(apk_filename) + 1, end(apk_filename),
                      std::back_inserter(filename), '/', '@');
    if (!boost::ends_with(apk_filename, ".dex")) {
        filename += "/classes.dex";
    }
    return filename;
}

void update_insn_counters()
{
    struct insn_counter_updater {
        std::vector<dex_file>::iterator it;

        void enter_dex_file(const std::string& apk_filename,
                            const std::string& odex_filename)
        {
            it = std::find_if(begin(dex_files), end(dex_files),
                              [&](const auto& x) {
                                  return x.apk_filename == apk_filename;
                              });
            if (it == end(dex_files)) {
                dex_files.emplace_back();
                it = end(dex_files);
                --it;

                it->apk_filename = apk_filename;
                it->odex_filename = odex_filename;
            }

            for (auto& c : it->counters) {
                c.second.delta = 0;
                ++c.second.last_accessed;
            }
        }

        void insn(uint32_t offset, uint16_t counter)
        {
            auto& c = it->counters[offset];
            c.counter += counter;
            c.delta = counter;
            c.last_accessed = 0;
        }

        void exit_dex_file()
        {
        }
    } updater;

    size_t dex_files_size_old = dex_files.size();

    jitana::jdwp_connection conn;
    conn.connect("localhost", "6100");
    conn.receive_insn_counters(updater);
    conn.close();

    if (dex_files_size_old != dex_files.size()) {
        // Pull the APK files on the device.
        pull_apk_files();

        for (auto& dex : dex_files) {
            if (dex.hdl) {
                continue;
            }

            std::string local_filename = make_local_filename(dex.apk_filename);

            auto lv = find_loader_vertex(app_loader_hdl, vm.loaders());
            if (!lv) {
                throw std::runtime_error("application loader not found");
            }

            dex.hdl = vm.loaders()[*lv].loader.add_file(local_filename);

            std::cout << "New DEX file (" << *dex.hdl << ") is added:\n";
            std::cout << "    Original: " << dex.apk_filename << "\n";
            std::cout << "    ODEX:     " << dex.odex_filename << "\n";
            std::cout << "    Local:    " << local_filename << "\n";
        }
    }
}

void update(int /*value*/)
{
    try {
        update_insn_counters();
    }
    catch (std::runtime_error e) {
        std::cerr << "error: " << e.what() << "\n";
    }

    update_graphs();
    if (periodic_output) {
        static int output_cnt = 0;
        if (output_cnt-- == 0) {
            write_graphviz();
//            write_traces();
//            write_vtables();
//            write_dtables();
            output_cnt = 20;
        }
    }

    if (should_terminate) {
        write_graphviz();
        write_traces();
        write_vtables();
        write_dtables();
        std::cout << std::endl;
        exit(0);
    }
}

void on_sigint(int)
{
    std::cout << "\nInterrupted. Terminating the program..." << std::endl;
    should_terminate = true;
}

void run_travis()
{
    try {
        {
            std::vector<std::string> filenames
                    = {"../../../dex/framework/core.dex",
                       "../../../dex/framework/framework.dex",
                       "../../../dex/framework/framework2.dex",
                       "../../../dex/framework/ext.dex",
                       "../../../dex/framework/conscrypt.dex",
                       "../../../dex/framework/okhttp.dex",
                       "../../../dex/framework/core-junit.dex",
                       "../../../dex/framework/android.test.runner.dex",
                       "../../../dex/framework/android.policy.dex"};
            jitana::class_loader loader(system_loader_hdl, "SystemLoader",
                                        begin(filenames), end(filenames));
            vm.add_loader(loader);
        }

        {
            std::vector<std::string> filenames;
            jitana::class_loader loader(app_loader_hdl, "AppLoader",
                                        begin(filenames), end(filenames));
            vm.add_loader(loader, system_loader_hdl);
        }

        update(0);

        signal(SIGINT, on_sigint);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n\n";
        std::cerr << "Please make sure that ";
        std::cerr << "all dependencies are installed correctly, and ";
        std::cerr << "the DEX files exist.\n";
    }
}




#endif /* INCLUDE_JITANA_MPI_TRAVIS_HPP_ */
