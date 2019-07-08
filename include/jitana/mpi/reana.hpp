/*
 * reana.hpp
 *
 *  Created on: Sep 17, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_REANA_HPP_
#define INCLUDE_JITANA_MPI_REANA_HPP_

#include <iostream>
#include <unordered_map>
#include <thread>
#include <fstream>

#include <boost/asio.hpp>

#include <jitana/vm_core/virtual_machine.hpp>
#include <jitana/vm_graph/graphviz.hpp>
#include <jitana/vm_core/dex_file.hpp>
#include <jitana/util/jdwp.hpp>
#include <jitana/analysis/call_graph.hpp>

/* Start ReAna */
#include <jitana/vm_core/access_flags.hpp>
#include <jitana/analysis/data_flow.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
/* End ReAna */

#include <unistd.h>
#include <sys/wait.h>

struct insn_counter {
	long long counter = 0;
	long long delta = 0;
	long long last_accessed = 0;
	boost::optional<
			std::pair<jitana::method_vertex_descriptor,
					jitana::insn_vertex_descriptor>> vertices;
};

struct dex_file {
	std::unordered_map<uint32_t, insn_counter> counters;
	jitana::dex_file_hdl hdl;
	bool valid;
};

static bool periodic_output = true;

static jitana::virtual_machine vm;
static jitana::class_loader_hdl system_loader_hdl = 0;
static jitana::class_loader_hdl app_loader_hdl = 1;

/* Start ReAna */
static std::vector<std::pair<jitana::ref_method, jitana::ref_method> > vRef;
static std::pair<jitana::ref_method, jitana::ref_method> refM;
static std::vector<std::pair<jitana::ref_method, jitana::ref_method> > already_written_ref;
static std::vector<std::pair<jitana::ref_method, jitana::ref_method> > printed_ref;
static std::vector<std::pair<std::string, jitana::dex_file_hdl> > file_name_hdl;
/* End ReAna */

/// Instruction stats. Can be passed as a visitor to
/// jitana::jdwp_connection::receive_insn_counters.
struct insn_stats {
public:
	void enter_dex_file(const std::string& source_filename,
			const std::string& filename) {
		auto it = dex_files_.find(filename);
		if (it != end(dex_files_)) {
			current_dex_file_ = &it->second;
		} else {
			// Get the basename of the ODEX file.
			std::string basename = { std::find_if(filename.rbegin(),
					filename.rend(), [](char c) {return c == '/';}).base(), end(
					filename) };
			std::cout << basename << "\n";

			auto lv = find_loader_vertex(app_loader_hdl, vm.loaders());
			if (!lv) {
				throw std::runtime_error("application loader not found");
			}
			auto& loader = vm.loaders()[*lv].loader;

			// Pull the ODEX file from the device.
			const std::string local_filename = "odex/" + basename;
			pid_t pid = ::fork();
			if (pid == 0) {
				// Run the shell script.
				::execl("pull-odex", "pull-odex", filename.c_str(),
						local_filename.c_str(), nullptr);
			} else if (pid > 0) {
				std::cout << "Executing: pid = " << pid << "\n";
				int status = 0;
				::waitpid(pid, &status, 0);
				std::cout << "Done: status = " << status << "\n";
			} else {
				throw std::runtime_error("failed to pull ODEX");
			}

			std::cout << "Local Filename: " << local_filename << "\n";
			std::cout << "filename:" << filename << "\n";

			current_dex_file_ = &dex_files_[filename];
			try {
				loader.add_file(local_filename);
				current_dex_file_->valid = true;
				current_dex_file_->hdl.loader_hdl = app_loader_hdl;
				current_dex_file_->hdl.idx = loader.dex_files().size() - 1;

				/* Start ReAna */
				std::cout << "current_dex_file_->hdl.loader_hdl: "
						<< current_dex_file_->hdl << "\n";
				std::cout << "current_dex_file_->hdl.idx:" << filename << "\n";
				std::pair<std::string, jitana::dex_file_hdl> file_name_hdl_pair;
				file_name_hdl_pair.first = filename;
				file_name_hdl_pair.second = current_dex_file_->hdl;
				file_name_hdl.push_back(file_name_hdl_pair);
				/* End ReAna */
			}

			catch (...) {
				current_dex_file_->valid = false;
			}
		}

		// std::cout << source_filename << "\n";
		// std::cout << filename << "\n";
		for (auto& c : current_dex_file_->counters) {
			c.second.delta = 0;
			++c.second.last_accessed;
		}
	}

	void insn(uint32_t offset, uint16_t counter) {
		if (current_dex_file_->valid) {
			auto& c = current_dex_file_->counters[offset];
			c.counter += counter;
			c.delta = counter;
			c.last_accessed = 0;
		}
	}

	void exit_dex_file() {
	}

	const std::unordered_map<std::string, dex_file>& dex_files() const {
		return dex_files_;
	}

	std::unordered_map<std::string, dex_file>& dex_files() {
		return dex_files_;
	}

private:
	std::unordered_map<std::string, dex_file> dex_files_;
	dex_file* current_dex_file_;
};

static insn_stats stats;

static void update_graphs() {
	jitana::compute_callgraph(vm);

	for (auto& p : stats.dex_files()) {
		auto& dex = p.second;
		if (!dex.valid) {
			continue;
		}

		for (auto& c : dex.counters) {
			auto& offset = c.first;
			auto& ictr = c.second;
			auto& vertices = ictr.vertices;
			if (!vertices) {
				vertices = vm.find_insn(dex.hdl, offset, true);
			}
			if (vertices) {
				vm.methods()[vertices->first].insns[vertices->second].counter =
						ictr.counter;
			} else {
				std::cerr << "failed to find the vertex: ";
				std::cerr << dex.hdl << " " << offset << "\n";
			}
		}
	}
}

/* Start ReAna */
int add_reflection_edge(
		std::pair<jitana::ref_method, jitana::ref_method> &source_sink) {
	int isValidSource = 0;
	int isValidSink = 0;

	for (auto &i : file_name_hdl) {
		if (source_sink.first.cacheName == i.first) {
			source_sink.first.hdl = i.second;
		}
		if (source_sink.second.cacheName == i.first) {
			source_sink.second.hdl = i.second;
		}
	}

	const auto& cg = vm.classes();
	const auto& mg = vm.methods();

	jitana::method_vertex_descriptor s_v;
	jitana::method_vertex_descriptor t_v;
	for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
		const auto& cv = vm.find_class(mg[mv].class_hdl, false);
		if (!cv) {
			continue;
		}
//              const auto& cprop = cg[*cv];

		if ((mg[mv].hdl.idx == source_sink.first.methodIndex)
				&& (mg[mv].hdl.file_hdl.idx == source_sink.first.hdl.idx)) {
			source_sink.first.methodName = mg[mv].unique_name;
//                  source_sink.first.className = cprop.descriptor;
			isValidSource = isValidSource + 1;
			s_v = mv;

//                  std::cout << "Update Source Method Unique Name 1 : " << source_sink.first.methodName << " isValid: " << isValid << std::endl;
		}
//              else if(source_sink.first.dexName.find("Jitana_Source_DN_NULL") == std::string::npos){
//                  if(mg[mv].class_hdl.file_hdl.loader_hdl == 1 && mg[mv].hdl.idx == source_sink.first.methodIndex){
//                      source_sink.first.methodName = mg[mv].unique_name;
////                      source_sink.first.className = cprop.descriptor;
//                      isValid = isValid + 1;
//                      std::cout << "Update Source Method Unique Name2 : " << source_sink.first.methodName << " isValid: " << isValid << std::endl;
//                  }
//              }

		if ((mg[mv].hdl.idx == source_sink.second.methodIndex)
				&& (mg[mv].hdl.file_hdl.idx == source_sink.second.hdl.idx)) {
			source_sink.second.methodName = mg[mv].unique_name;
//                  source_sink.second.className = cprop.descriptor;
			isValidSink = isValidSink + 1;
			t_v = mv;

//                  std::cout << "Update Target Method Unique Name 1: " << source_sink.second.methodName << " isValid: " << isValid << std::endl;
		}
//              else if(source_sink.second.dexName.find("Jitana_Target_DN_NULL") == std::string::npos){
//                  if(mg[mv].class_hdl.file_hdl.loader_hdl == 1 && mg[mv].hdl.idx == source_sink.second.methodIndex){
//                      source_sink.second.methodName = mg[mv].unique_name;
////                      source_sink.second.className = cprop.descriptor;
////                      isValid = isValid + 1;
//                      std::cout << "Update Target Method Unique Name 2: " << source_sink.second.methodName << " isValid:" << isValid << std::endl;
//                  }
//              }

	}

//    jitana::method_vertex_descriptor s_v;
//    jitana::method_vertex_descriptor t_v;
	if (isValidSink == 1 || isValidSource == 1) {
		jitana::method_reflection_edge_property eprop;
		boost::add_edge(s_v, t_v, eprop, vm.methods());
//        jitana::jvm_method_hdl s_h = {{source_sink.first.hdl.idx, source_sink.first.className}, source_sink.first.methodName};
//        jitana::jvm_method_hdl t_h = {{source_sink.second.hdl.idx, source_sink.second.className}, source_sink.second.methodName};
//        if(auto svo = vm.find_method(s_h, false)){
//            if(auto tvo = vm.find_method(t_h, false)){
//                jitana::method_edge_property eprop;
//                std::cout << "Source:: " << s_h.unique_name << " " ;
//                std::cout << "Target:: " << t_h.unique_name << std::endl;
//                boost::add_edge(*svo, *tvo, eprop, vm.methods());
//            };
//
//        };

////        auto s_v = vm.find_method(s_h, true);
//
//
////        auto t_v = vm.find_method(t_h, true);
//        t_v = lookup_method_vertex(t_h, mg);
//
//
//
//        //
	}
//          auto s = jitana::lookup_method_vertex({{source_sink.first.hdl.idx, source_sink.first.className}, source_sink.first.methodName},
//                                                mg);
//          auto t = jitana::lookup_method_vertex({{source_sink.second.hdl.idx, source_sink.second.className}, source_sink.second.methodName},                                      mg);
//          boost::add_edge(*s, *t, eprop, mg);

	if (isValidSink == 1 && isValidSource == 1) {
		return 2;
	} else {
		return 1;
	}

}

void update_ref_vm() {
	try {

		static std::vector<std::pair<jitana::ref_method, jitana::ref_method> >::iterator iterator_already_written_ref;
//
		for (auto &i : vRef) {
			if ((i.first.dexName.find("Jitana_Source_DN_NULL")
					== std::string::npos)
					&& (i.second.dexName.find("Jitana_Target_DN_NULL")
							== std::string::npos)
					&& (i.first.methodName.find("Jitana_Source_MN_NULL")
							== std::string::npos)
//          && (i.first.className.find("Landroid") == std::string::npos)
					&& (i.second.methodName.find("Jitana_Target_MN_NULL")
							== std::string::npos)
//         &&  (i.second.className.find("Landroid") == std::string::npos)
					) {
				iterator_already_written_ref =
						find_if(already_written_ref.begin(),
								already_written_ref.end(),
								[&] (std::pair<jitana::ref_method ,jitana::ref_method > &s)
								{	return (
											(s.first.methodIndex == i.first.methodIndex)
											&&
											(s.first.className == i.first.className)
											&& (s.first.methodName == i.first.methodName)
											&& (s.first.dexName == i.first.dexName)
											&& (s.first.cacheName == i.first.cacheName)
											&& (s.first.insn_offset == i.first.insn_offset)

											&& (s.second.methodIndex == i.second.methodIndex)
											&& (s.second.className == i.second.className)
											&& (s.second.methodName == i.second.methodName)
											&& (s.second.dexName == i.second.dexName)
											&& (s.second.cacheName == i.second.cacheName)
											&& (s.second.insn_offset == i.second.insn_offset)
									);
								});
			}

			if (iterator_already_written_ref == already_written_ref.end()) {
				printed_ref.push_back(i);
				already_written_ref.push_back(i);

			}
		}
//    std::cout << "************" << std::endl;
//    std::cout << "************" << std::endl;
		std::ofstream ofs1("output/refs.csv");
		for (auto &i : printed_ref) {
//         std::cout << "In loop : S_MI: " << i.first.methodName << "T_MI: " << i.second.methodName << std::endl;
			int isValid = add_reflection_edge(i);
			if (isValid == 2) {
				ofs1 << "S_MI: " << i.first.methodIndex << " ; ";
				ofs1 << "S_MN: " << i.first.methodName << " ; ";
				ofs1 << "S_CN: " << i.first.className << " ; ";
				ofs1 << "S_DN: " << i.first.dexName << " ; ";
				ofs1 << "S_CaN: " << i.first.cacheName << " ; ";
				ofs1 << "S_IO: " << i.first.insn_offset << "; ";
				ofs1 << "T_MI: " << i.second.methodIndex << " ; ";
				ofs1 << "T_MN: " << i.second.methodName << " ; ";
				ofs1 << "T_CN: " << i.second.className << " ; ";
				ofs1 << "T_DN: " << i.second.dexName << " ; ";
				ofs1 << "T_CaN: " << i.second.cacheName << " ; ";
				ofs1 << "T_IO: " << i.second.insn_offset << std::endl;
				std::cout << "In side Valid == 1 : S_MI: " << i.first.methodName
						<< "T_MI: " << i.second.methodName << std::endl;
			}

		}
	} catch (std::runtime_error e) {
		std::cerr << "error: " << e.what() << "\n";
	}
//     std::cout << "************" << std::endl;
//     std::cout << "************" << std::endl;
}

void update_ref(int value) {
	jitana::jdwp_connection conn;
	try {
		conn.connect("localhost", "6100");
		vRef = conn.receive_refl();
		conn.close();
		update_ref_vm();
	} catch (std::runtime_error e) {
		std::cerr << "error: " << e.what() << "\n";
	}
}
/* End ReAna */

void update(int value) {
	jitana::jdwp_connection conn;
	try {
		conn.connect("localhost", "6100");
		conn.receive_insn_counters(stats);
		conn.close();
	} catch (std::runtime_error e) {
		std::cerr << "error: " << e.what() << "\n";
	}
	std::cout << std::flush;

	/* Start ReAna */
	update_ref(0);
//    std::cout << std::flush;
	/* End ReAna */

	update_graphs();
	if (periodic_output) {
		static int output_cnt = 0;
		if (output_cnt-- == 0) {
			//write_graphviz();
			//write_traces();
			//write_vtables();
			//write_dtables();
			output_cnt = 20;
		}
	}

}

void run_reana() {
	{
		std::vector<std::string> filenames = { "../dex/framework/core.dex",
				"../dex/framework/framework.dex",
				"../dex/framework/framework2.dex",
				"../dex/framework/ext.dex",
				"../dex/framework/conscrypt.dex",
				"../dex/framework/okhttp.dex",
				"../dex/framework/core-junit.dex",
				"../dex/framework/android.test.runner.dex",
				"../dex/framework/android.policy.dex" };
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
	// Execute the main loop.
}

#endif /* INCLUDE_JITANA_MPI_REANA_HPP_ */
