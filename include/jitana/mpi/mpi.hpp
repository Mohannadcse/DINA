
#ifndef INCLUDE_JITANA_MPI_MPI_HPP_
#define INCLUDE_JITANA_MPI_MPI_HPP_

#include <iostream>
#include <vector>
#include <regex>
#include <algorithm>
#include <string>
#include <fstream>
#include <unordered_map>
#include <exception>
#include <set>

#include <boost/graph/graphviz.hpp>
#include <jitana/jitana.hpp>
#include <jitana/analysis/call_graph.hpp>
#include <jitana/analysis/def_use.hpp>
#include <jitana/analysis/intent_flow_intraprocedural.hpp>
#include <jitana/analysis/intent_flow_string.hpp>
#include <jitana/analysis/content_provider_flow_string.hpp>
#include <jitana/vm_graph/method_graph.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/type_erasure/any_cast.hpp>
#include <jitana/vm_graph/edge_filtered_graph.hpp>
#include "jitana/algorithm/property_tree.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <jitana/mpi/intent_graph.hpp>
#include <jitana/mpi/parse_source_sink_list.hpp>
#include <jitana/mpi/traverse_branch_node.hpp>
#include "jitana/algorithm/unique_sort.hpp"

//#include <jitana/mpi/reana.hpp>
//#include <jitana/mpi/travis.hpp>

void write_graphs(const jitana::virtual_machine& vm);
typedef std::pair<std::string, std::string> senRecPkgPair;
typedef jitana::method_graph::vertex_descriptor vd_mg;
typedef jitana::method_vertex_property vp;
typedef jitana::intent_graph::vertex_descriptor vd;
//jitana::intent_graph inG;

namespace jitana {
    //Stores all intent action strings in the intent graph (edges labels)
    std::set<std::string> all_intent_actions;
    intent_graph inG;
    std::map <std::string, std::string> apkToPkg;
}

std::vector<vd_mg> iterate_instr_graph(jitana::virtual_machine& vm, int appID,
                                       std::string intentAction/*, std::vector<std::string> pckgNames*/) {
    std::vector<vd_mg> vd;
    const auto& mg = vm.methods();
    
    //Iterate method graph to access the IG of each method
    for (const auto& v : boost::make_iterator_range(vertices(mg))) {
        const auto& ig = mg[v].insns;
        auto gprop = ig[boost::graph_bundle];
        auto classTmp = mg[v].jvm_hdl.type_hdl.descriptor;
        //        std::cout << "classTmp:: "<<classTmp<<"\n";
        //        std::cout << "pkgsNamesVec:: "<<pckgNames.size()<<"\n";
        //        std::cout<< "appID:: "<<appID<<"\n";
        //        std::cout<<"pckgNames[appID]:: "<<pckgNames[appID-1]<<"\n";
        //        std::cout << "match class:: "<< boost::replace_all_copy(pckgNames[appID - 1], ".",
        //                                                                "/")<<"\n";
        
        for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
            //iterate only over instruction graphs that belong to a particular appID, and package name
            if (appID == mg[v].hdl.file_hdl.loader_hdl
                /*&& classTmp.find(
                 boost::replace_all_copy(pckgNames[appID - 1], ".",
                 "/")) != std::string::npos*/) {
                     const auto* cs_insn = get<jitana::insn_const_string>(
                                                                          &ig[iv].insn);
                     if (!cs_insn) {
                         continue;
                     }
                     if (cs_insn->const_val.compare(intentAction) == 0) {
                         //                    sourceV[0] = gprop.jvm_hdl.type_hdl.descriptor; //component name
                         //                    sourceV[1] = gprop.jvm_hdl.unique_name;        //method name
                         //                    //sourceV[2] = mg[v].hdl;
                         //                    //sourceV[3] = mg[v].jvm_hdl;
                         //                    std::cout<< "mg[v].hdl:: " <<mg[v].hdl<<"\n";
                         //                    std::cout<< "mg[v].jvm_hdl:: " <<mg[v].jvm_hdl<<"\n";
                         //                    allSourceVec.push_back(sourceV);
                         //vd.push_back(mg[v]);
                         vd.push_back(v);
                     }
                 }
        }
    }
    jitana::unique_sort(vd);
    return vd;
}

std::vector<std::vector<std::string>> parse_manifest(std::string pkgName, std::string appFolder,
                                                     std::string intentAction) {
    namespace pt = boost::property_tree;
    //the component should be activity, service or receiver
    std::vector<std::string> components = { "activity", "service", "receiver" };
    auto manifestLoacation = appFolder + "/AndroidManifestDecoded.xml";
    std::vector<std::string> targetV(2); // [0]: component, [1]: none
    std::vector<std::vector<std::string>> allTargetVec;
    
    pt::ptree tree;
    pt::read_xml(manifestLoacation, tree);
    
    for (std::vector<std::string>::size_type i = 0; i != components.size();
         i++) {
        for (const auto& x : jitana::child_elements(
                                                    tree.get_child("manifest.application"), components[i])) {
            auto compName = x.second.get_optional < std::string
            > ("<xmlattr>.android:name");
            for (const auto& y : jitana::child_elements(x.second,
                                                        "intent-filter")) {
                for (const auto& z : jitana::child_elements(y.second, "action")) {
                    auto val = z.second.get_optional < std::string
                    > ("<xmlattr>.android:name");
                    //Check if this component contains intent filter matches the intent action string
                    if (*val == intentAction) {
                        std::string st = *compName;
                        if(boost::starts_with(*compName, ".")){
                            //std::cout <<"Component name starts with dot\n";
                            st = pkgName+st.substr(0,1);
                        }
                        targetV[0] = "L"+st+";";
                        targetV[1] = "none";
                        allTargetVec.push_back(targetV);
                    }
                }
            }
        }
    }
    return allTargetVec;
}

int obtain_element_index(std::vector<std::string> vec, std::string element) {
    int index;
    auto it = std::find(vec.begin(), vec.end(), element);
    
    if (it == vec.end()) {
        index = -1;
    } else {
        index = std::distance(vec.begin(), it);
    }
    return index;
}

//This table contains mapping between intent action and sender & receiver apps
bool lookup_table(std::string intentAction, std::string senderPkg,
                  std::string receiverPkg,
                  std::unordered_multimap<std::string, senRecPkgPair> map) {
    auto its = map.equal_range(intentAction);
    for (auto it = its.first; it != its.second; ++it) {
        if (it->first == intentAction && (it->second).first == senderPkg
            && (it->second).second == receiverPkg) {
            return true;
        }
    }
    return false;
}

namespace jitana {
    template<typename IntentGraph>
    inline void write_graphviz_new_intent_graph(std::ostream& os,
                                                const IntentGraph& g) {
        auto prop_writer = [&](std::ostream& os, const auto& v) {
            std::stringstream label_ss;
            label_ss << "{";
            label_ss << unsigned(g[v].loaderID);
            label_ss << "|" << g[v].componentName<< "\\l";
            //label_ss << "|" << g[v].methodName<< "\\l";
            label_ss << "|" << g[v].appPkgName<< "\\l";
            label_ss << "}|";
            
            os << "[";
            os << "label=" << escape_dot_record_string(label_ss.str());
            os << ",";
            os << "shape=record";
            os << ",";
            os << "colorscheme=pastel19, style=filled, ";
            os << "fillcolor=";
            os << ((9 + unsigned(g[v].loaderID) - 3) % 9 + 1);
            os << "]";
        };
        auto eprop_writer = [&](std::ostream& os, const auto& e) {
            os << "[";
            print_graphviz_attr(os, g[e]);
            os << "]";
        };
        auto gprop_writer = [&](std::ostream& os) {os << "rankdir=RL;\n";};
        write_graphviz(os, g, prop_writer, eprop_writer, gprop_writer);
    }
}

void find_sensitive_method_receiver_side(jitana::virtual_machine& vm,
                                         std::string component) {
    vector<vector<string>> sourceSinkList = source_sink_list_vector();
    std::string tmpComponent = "L"
    + boost::replace_all_copy(component, ".", "/") + ";";
    //std::cout << "temp comp:: " << tmpComponent << "\n";
    std::vector<std::string> methodsVec; /*contains methods that belong to a specific component*/
    const auto& mg = vm.methods();
    for (const auto& v : boost::make_iterator_range(vertices(mg))) {
        //select methods that belong to a specific component name
        if (tmpComponent == mg[v].jvm_hdl.type_hdl.descriptor) {
            //search only for onCreate, onStartCommand, onReceive
            auto mn = mg[v].jvm_hdl.unique_name;
            if (mn.find("onCreate(") != string::npos
                || mn.find("onStartCommand(") != string::npos
                || mn.find("onReceive(") != string::npos) {
                if (auto t = jitana::lookup_method_vertex(mg[v].hdl, mg)) {
                    std::cout
                    << "\n\n\n*****Receiver Side ****\n DFS for Vertex::: "
                    << mg[v].jvm_hdl << "\n";
                    MyVisitor vis;
                    boost::depth_first_search(vm.methods(),
                                              boost::visitor(vis).root_vertex(*t));
                    std::vector<vp> vctr = vis.GetVector();
                    std::vector<std::string> total_sensitive_methods;
                    if (vctr.size() > 1) {
                        for (unsigned i = 0; i < vctr.size(); i++) {
                            if (source_Sink_list_check(
                                                       vctr[i].jvm_hdl.type_hdl.descriptor,
                                                       vctr[i].jvm_hdl.unique_name, sourceSinkList)) {
                                std::cout << "\n================\n";
                                std::cout
                                << "Sensitive Mehtod has been found \n ";
                                std::cout << "\t"
                                << vctr[i].jvm_hdl.type_hdl.descriptor
                                << "\n";
                                std::cout << "\t" << vctr[i].jvm_hdl.unique_name
                                << "\n";
                                std::cout << "CalledAt::\n";
                                std::cout << "\t" << vm.methods()[*t].jvm_hdl
                                << "\n";
                                std::cout << "================\n\n\n\n";
                                total_sensitive_methods.push_back(
                                                                  vctr[i].jvm_hdl.type_hdl.descriptor
                                                                  + " "
                                                                  + vctr[i].jvm_hdl.unique_name);
                            }
                        }
                    }
                    std::cout << "Total number of Sensitive methods:: "
                    << total_sensitive_methods.size() << "\n";
                }
            }
        }
    }
}

void find_sensitive_method_sender_side(jitana::virtual_machine& vm, jitana::intent_graph g) {
    //Find sensitive methods on the sender side
    vector<vector<string>> sourceSinkList = source_sink_list_vector();
    for (const auto& v : boost::make_iterator_range(vertices(g))) {
        if (auto t = jitana::lookup_method_vertex(*g[v].hdl, vm.methods())) {
            std::cout << "\n\n\n******Sender Side*******\n DFS for Vertex::: "
            << vm.methods()[*t].jvm_hdl << "\n";
            MyVisitor vis;
            boost::depth_first_search(vm.methods(),
                                      boost::visitor(vis).root_vertex(*t));
            std::vector<vp> vctr = vis.GetVector();
            std::vector<std::string> total_sensitive_methods;
            //std::cout<<"vctr:: "<<vctr.size()<<"\n";
            if (vctr.size() > 1) {
                for (unsigned i = 0; i < vctr.size(); i++) {
                    if (source_Sink_list_check(
                                               vctr[i].jvm_hdl.type_hdl.descriptor,
                                               vctr[i].jvm_hdl.unique_name,sourceSinkList)) {
                        std::cout << "\n================\n";
                        std::cout << "Sensitive Mehtod has been found \n ";
                        std::cout << "\t" << vctr[i].jvm_hdl.type_hdl.descriptor
                        << "\n";
                        std::cout << "\t" << vctr[i].jvm_hdl.unique_name
                        << "\n";
                        std::cout << "at vertex\n";
                        std::cout << "\t" << vm.methods()[*t].jvm_hdl << "\n";
                        std::cout << "================\n\n\n\n";
                        total_sensitive_methods.push_back(
                                                          vctr[i].jvm_hdl.type_hdl.descriptor + " "
                                                          + vctr[i].jvm_hdl.unique_name);
                    }
                }
            }
            std::cout << "Total number of Sensitive methods:: "
            << total_sensitive_methods.size() << "\n";
        }
    }
}

jitana::intent_graph get_intent_graph(){
    return jitana::inG;
}

//Lookup vertex in the new intent graph based on component name, loaderID, and method name
boost::optional<jitana::intent_graph::vertex_descriptor> lookup_vertex_intent_graph(jitana::intent_graph g,
                                                                       std::string componentName
                                                                       , int loaderID/*, std::string methodName, char vert_type*/)
{
    for (const auto& v : boost::make_iterator_range(vertices(g))) {
        if(g[v].componentName == componentName &&
           //g[v].methodName == methodName &&
           g[v].loaderID == loaderID /*&&
                                      vert_type == 's'*/){
                                          return v;
                                      }
    }
    return boost::none;
}

vd creat_new_vertices(jitana::intent_graph& g, std::string appPkgName,
                      std::string componentName, int loaderID)
{
    auto v = boost::add_vertex(g);
    jitana::inG[v].componentName = componentName;
    jitana::inG[v].appPkgName = appPkgName;
    jitana::inG[v].loaderID = loaderID;
    return v;
}

//Parse the original intent graph for generating new intent graph
jitana::intent_graph parse_original_intent_graph(jitana::virtual_machine& vm,
                                        std::vector<std::string> apksList) {
    using boost::type_erasure::any_cast;
    std::vector<std::string> packageNameList;
    int appIndex = 0;
    typedef std::vector<std::vector<std::string>> appDetails;
    appDetails senderAppDetails, receiverAppDetails;
    senRecPkgPair pkgPair;
    std::unordered_multimap<std::string, senRecPkgPair> edgeHistory; //verify if an edge already exists
    jitana::intent_edge_property propE;
    std::set<vd> new_snding_vert, new_recving_vert;
    
    
    //Read intent graph
    const auto g = jitana::make_edge_filtered_graph<
    jitana::intent_flow_edge_property>(vm.loaders());
    
    //Iterate the original Intent Graph to extract the package name
    for (const auto& v : boost::make_iterator_range(vertices(g))) {
        if (g[v].loader.name().compare("SystemLoader") == 0) {
            continue;
        }
        packageNameList.push_back(g[v].loader.name());
        auto apkIndex = obtain_element_index(packageNameList,
                                             g[v].loader.name());
        jitana::apkToPkg[g[v].loader.name()] = apksList[apkIndex];
    }
    //Iterate the original Intent Graph
    for (const auto& v : boost::make_iterator_range(vertices(g))) {
        if (g[v].loader.name().compare("SystemLoader") == 0) {
            continue;
        }
        
        
        //        std::cout << "Node:: "<<g[v].loader.name()<<"\n";
        //        std::cout <<"========================\n";
        
        //Create vertex on the new intent graph for nodes on the original intent graph that don't have
        //neither in-edges nor out-edges.
        if (boost::in_degree(v, g) == 0 && boost::out_degree(v, g) == 0){
            auto s = boost::add_vertex(jitana::inG);
            jitana::inG[s].methodName_strAction = "none";
            jitana::inG[s].componentName = "none";
            jitana::inG[s].appPkgName = g[v].loader.name();
            jitana::inG[s].loaderID = appIndex+1;
            //auto s = creat_new_vertices(inG, g[v].loader.name(), "none", appIndex+1);
        }
        
        //Iterate out edges of each vertex in the intent graph
        for (const auto& e : boost::make_iterator_range(out_edges(v, g))) {
            auto source = boost::source(e, g);
            auto target = boost::target(e, g);
            auto strAction =
            any_cast<jitana::intent_flow_edge_property>(g[e]).description;
            auto apkIndex = obtain_element_index(packageNameList,
                                                 g[target].loader.name());
            jitana::all_intent_actions.insert(strAction);
            
            if (source != target) {
                //Check duplicated edge
                //Handle sender and receiver vertices
                switch (any_cast<jitana::intent_flow_edge_property>(g[e]).kind) {
                    case 0:
                        propE.kind = jitana::intent_edge_property::explicit_intent;
                        break;
                    case 1:
                        propE.kind = jitana::intent_edge_property::implicit_intent;
                        break;
                }
                propE.intentAction = strAction;
                
                bool is_edge_exist = lookup_table(strAction,
                                                  g[source].loader.name(), g[target].loader.name(),
                                                  edgeHistory);
                if (is_edge_exist) {
                    //std::cout << "edge found\n";
                    continue;
                } else {
                    //create the new intent graph vertices and edges should be created here
                    //std::cout << "edge not found\n";
                    pkgPair.first = g[source].loader.name();
                    pkgPair.second = g[target].loader.name();
                    edgeHistory.insert(std::make_pair(strAction, pkgPair));
                }
                receiverAppDetails = parse_manifest(g[target].loader.name(), apksList[apkIndex],
                                                    strAction);
                
                auto found_inst_graph_vec = iterate_instr_graph(vm, appIndex + 1, strAction/*,
                                                                packageNameList*/);
                //std::cout <<"========================\n\n\n\n";
                
                //Iterate the vector that contains the details of IGs that contain the intent string action
                //Then create nodes based on the vector size
                std::string componentName, methodName, appPkgName;
                int loaderID_sen, loaderID_rec;
                jitana::dex_method_hdl hdl;
                jitana::jvm_method_hdl jvm_hdl;
                
                //Creating sending vertices
                for (unsigned ys = 0; ys < found_inst_graph_vec.size(); ys++) {
                    componentName = boost::replace_all_copy(vm.methods()[found_inst_graph_vec[ys]].jvm_hdl.type_hdl.descriptor,
                                                            "/", ".");
                    methodName = boost::replace_all_copy(vm.methods()[found_inst_graph_vec[ys]].jvm_hdl.unique_name, "/",
                                                         ".");
                    appPkgName = g[source].loader.name();
                    loaderID_sen = obtain_element_index(packageNameList,
                                                        g[source].loader.name()) + 1;
                    hdl = vm.methods()[found_inst_graph_vec[ys]].hdl;
                    jvm_hdl = vm.methods()[found_inst_graph_vec[ys]].jvm_hdl;
                    
                    if ( auto cv = lookup_vertex_intent_graph(jitana::inG, componentName, loaderID_sen/*, methodName, 's'*/)){
                        new_snding_vert.insert(cv.get());
                        //std::cout << "existing vertex found Sender\n";
                    }
                    else {
                        auto s = creat_new_vertices(jitana::inG,appPkgName,componentName,loaderID_sen);
                        //                        auto s = boost::add_vertex(inG);
                        //                        inG[s].componentName = componentName;
                        //                        std::cout << "compName:: "<< componentName<< "\n";
                        //                        std::cout << "inG[s].hdl:: " << hdl << "\n";
                        //                        std::cout << "inG[s].jvm_hdl" << jvm_hdl << "\n";
                        //                        std::cout << "methodName" << methodName<< "\n";
                        //inG[s].methodName = methodName;
                        //                        inG[s].appPkgName = appPkgName;
                        //                        inG[s].loaderID = loaderID_sen;
                        //inG[s].hdl = hdl;
                        //inG[s].jvm_hdl = jvm_hdl;
                        new_snding_vert.insert(s);
                    }
                }
                
                //Creating receiving vertices
                loaderID_rec = obtain_element_index(
                                                    packageNameList,
                                                    g[target].loader.name()) + 1;
                for (unsigned yr = 0; yr < receiverAppDetails.size(); yr++) {
                    //if (! is_vertix_exist(inG, receiverAppDetails[yr][0], receiverAppDetails[yr][1]))
                    if ( auto cv = lookup_vertex_intent_graph(jitana::inG, receiverAppDetails[yr][0], loaderID_rec/*, receiverAppDetails[yr][1], 'r'*/)) {
                        //std::cout << "existing vertex found Receiver\n";
                        new_recving_vert.insert(cv.get());
                    }
                    else {
                        auto r = creat_new_vertices(jitana::inG,g[target].loader.name(),receiverAppDetails[yr][0],loaderID_rec);
                        //                        auto r = boost::add_vertex(inG);
                        //                        inG[r].componentName = receiverAppDetails[yr][0];
                        //inG[r].methodName = receiverAppDetails[yr][1];
                        //                        inG[r].appPkgName = g[target].loader.name();
                        //                        inG[r].loaderID = loaderID_rec;
                        new_recving_vert.insert(r);
                    }
                }
                
                //create edges
                for (set<vd>::iterator i_s = new_snding_vert.begin(); i_s != new_snding_vert.end(); i_s++) {
                    //for (unsigned x = 0; x < new_recving_vert.size(); x++) {
                    for (set<vd>::iterator i_r = new_recving_vert.begin(); i_r != new_recving_vert.end(); i_r++) {
                        boost::add_edge(*i_s, *i_r, propE, jitana::inG);
                    }
                }
            }
        }
        appIndex++;
        new_snding_vert.clear();
        new_recving_vert.clear();
    }
    return jitana::inG;
}

void run_iac_analysis() {
    jitana::virtual_machine vm;
    std::vector<std::string> apkNames;
    
    {
        const auto& filenames = { "../../../dex/framework/core.dex",
            "../../../dex/framework/framework.dex",
            "../../../dex/framework/framework2.dex",
            "../../../dex/framework/ext.dex",
            "../../../dex/framework/conscrypt.dex",
            "../../../dex/framework/okhttp.dex",
            "../../../dex/framework/core-junit.dex",
            "../../../dex/framework/android.test.runner.dex",
            "../../../dex/framework/android.policy.dex" };
        jitana::class_loader loader(0, "SystemLoader", begin(filenames),
                                    end(filenames));
        vm.add_loader(loader);
    }
    // Read APK files
    std::ifstream location_ifs("extracted/location.txt");
    std::string name;
    for (int loader_idx = 1; std::getline(location_ifs, name); ++loader_idx) {
        std::cout << "Loading " << loader_idx << " " << name << "..."
        << std::endl;
        vm.add_apk(loader_idx, "extracted/" + name, 0);
        vm.load_all_classes(loader_idx);
        apkNames.push_back("extracted/" + name);
    }
    
    // Compute the call graph.
    std::cout << "Computing the call graph..." << std::endl;
    jitana::add_call_graph_edges(vm);
    
    // Compute the def-use edges.
    std::cout << "Computing the def-use edges..." << std::endl;
    std::for_each(vertices(vm.methods()).first, vertices(vm.methods()).second,
                  [&](const jitana::method_vertex_descriptor& v) {
                      add_def_use_edges(vm.methods()[v].insns);
                  });
    
    // Compute the intent-flow edges.
    std::cout << "Computing the intent-flow..." << std::endl;
#if 0
    jitana::add_intent_flow_edges_intraprocedural(vm);
#else
    jitana::add_intent_flow_edges_string(vm);
#endif
    
    //std::cout << "Writing graphs..." << std::endl;
    write_graphs(vm);
    auto new_int_graph = parse_original_intent_graph(vm, apkNames);
    {
        std::ofstream ofs("output-iac/new_intent_graph.dot");
        jitana::write_graphviz_new_intent_graph(ofs, new_int_graph);
        std::cout << "Size of New Intent Graph::: " << num_vertices(jitana::inG) << "\n";
    }
}

void write_graphs(const jitana::virtual_machine& vm) {
    
    {
        {
            std::ofstream ofs("output-iac/class_graph.dot");
            write_graphviz_class_graph(ofs, vm.classes());
        }
        std::ofstream ofs("output-iac/intent_graph.dot");
        auto g1 = jitana::make_edge_filtered_graph<
        jitana::intent_flow_edge_property>(vm.loaders());
        write_graphviz_loader_graph(ofs, g1);
        std::cout << "Size of Original Intent Graph::: " << num_vertices(g1) << "\n";
    }
    
    {
        std::ofstream ofs("output-iac/method_graph.dot");
        write_graphviz_method_graph(ofs, vm.methods());
    }
    
    //    {
    //        for (const auto& v : boost::make_iterator_range(vertices(vm.methods()))) {
    //            const auto& ig = vm.methods()[v].insns;
    //            if (num_vertices(ig) > 0) {
    //                std::stringstream ss;
    //                ss << "output/insn/" << vm.methods()[v].hdl << ".dot";
    //                std::ofstream ofs(ss.str());
    //                write_graphviz_insn_graph(ofs, ig);
    //            }
    //        }
    //    }
}


#endif /* INCLUDE_JITANA_MPI_MPI_HPP_ */
