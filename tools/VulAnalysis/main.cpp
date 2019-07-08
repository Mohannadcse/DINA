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
#include <boost/algorithm/string/predicate.hpp>
#include <boost/graph/reverse_graph.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/algorithm/string.hpp>


#include <boost/graph/graph_utility.hpp>


jitana::jvm_method_hdl send_bc1 = { { 0, "Landroid/content/Context;" },
    "sendBroadcast(Landroid/content/Intent;)V" };
jitana::jvm_method_hdl send_bc2 = { { 0, "Landroid/content/Context;" },
    "sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V" };
jitana::jvm_method_hdl send_ordered_bc1 = { { 0, "Landroid/content/Context;" },
    "sendOrderedBroadcast(Landroid/content/Intent;Ljava/lang/String;ILandroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V" };
jitana::jvm_method_hdl send_ordered_bc2 = { { 0, "Landroid/content/Context;" },
    "sendOrderedBroadcast(Landroid/content/Intent;Ljava/lang/String;)V" };
jitana::jvm_method_hdl send_sticky_bc = { { 0, "Landroid/content/Context;" },
    "sendStickyBroadcast(Landroid/content/Intent;)V" };
jitana::jvm_method_hdl send_sticky_ordered_bc = { { 0, "Landroid/content/Context;" },
    "sendStickyOrderedBroadcast(Landroid/content/Intent;Landroid/content/BroadcastReceiver;Landroid/os/Handler;ILjava/lang/String;Landroid/os/Bundle;)V" };

jitana::jvm_method_hdl start_activity = { { 0, "Landroid/content/Context;" },
    "startActivity(Landroid/content/Intent;)V" };
jitana::jvm_method_hdl start_activity_for_result = { { 0, "Landroid/content/Context;" },
    "startActivityForResult(Landroid/content/Intent;I)V" };

jitana::jvm_method_hdl start_service = { { 0, "Landroid/content/Context;" },
    "startService(Landroid/content/Intent;)Landroid/content/ComponentName;" };
jitana::jvm_method_hdl bind_service = { { 0, "Landroid/content/Context;" },
    "bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z" };


typedef jitana::method_graph::vertex_descriptor vd_mg;
typedef jitana::intent_graph::vertex_descriptor vd;
std::vector<std::string> apkNames;
std::vector<vd_mg> ref_hdl;
std::vector<std::pair<vd_mg, vd_mg>> ref_hdl_pair;


template <typename Graph, typename VertexDescriptor>
std::vector<VertexDescriptor> find_reachable_nodes(const VertexDescriptor& root_v, const Graph& g)
{
    std::vector<VertexDescriptor> reachable;
    
    // Visitor.
    struct reachable_visitor : boost::default_dfs_visitor {
        void discover_vertex(const VertexDescriptor& v, const Graph&)
        {
            //std::cout << "Visiting " << v << "!\n";
            reachable->push_back(v);
        }
        
        std::vector<VertexDescriptor>* reachable;
    };
    
    // Color map internally used by depth_first_visit().
    boost::vector_property_map<int> color_map(
                                              static_cast<unsigned>(num_vertices(g)));
    
    // Create a visitor.
    reachable_visitor vis;
    vis.reachable = &reachable;
    
    // Run depth first visit.
    boost::depth_first_visit(g, root_v, vis, color_map);
    
    return reachable;
}

//Filter graph based on vertex
template <typename Graph>
struct vertex_app_id_filter
{
    const Graph* g;
    bool operator()(const typename Graph::vertex_descriptor& v) const
    {
        return ((*g)[v].hdl.file_hdl.loader_hdl == loaderID) || ((*g)[v].hdl.file_hdl.loader_hdl == 0); // keep all vertx_descriptors equal to appID
    }
    unsigned int loaderID;
};


std::vector<std::vector<std::string>> parse_ref_csv()
{
    std::vector<std::vector<std::string>> target_ref_methods_CSV;
    std::ifstream ref_methods_pair_File("/media/edrive1/Android/result_dataset_journal/output_G10/output-reana/ref_methods_pair.csv");
    std::string line;
    std::cout << "Reading ref_methods_pair_sorted.csv \n";
    for (int index = 1; std::getline(ref_methods_pair_File, line); ++index) {
        boost::tokenizer<boost::escaped_list_separator<char> > tk(line,
                                                                  boost::escaped_list_separator<char>(';'));
        std::vector<std::string> vec;
        for (boost::tokenizer<boost::escaped_list_separator<char> >::iterator i(
                                                                                tk.begin()); i != tk.end(); ++i) {
            vec.push_back(*i);
        }
        target_ref_methods_CSV.push_back(vec);
    }
    return target_ref_methods_CSV;
}

//Check if the method contains the intent action string is an intent sending API
//if not, then check if the method calls any intent sending API.
boost::optional<vd_mg> find_intent_sending(jitana::virtual_machine& vm, vd_mg ds)
{
    auto& mg = vm.methods();
    vertex_app_id_filter<jitana::method_graph> vfilter;
    vfilter.loaderID = unsigned(mg[ds].hdl.file_hdl.loader_hdl);
    vfilter.g = &mg;
    typedef boost::filtered_graph<jitana::method_graph, boost::keep_all, vertex_app_id_filter<jitana::method_graph> > filtered_MG;
    filtered_MG filteredGraph(mg, boost::keep_all(), vfilter);
    auto vctr_f = find_reachable_nodes(ds, filteredGraph);
    for (auto t : vctr_f){
        auto mn = mg[t].jvm_hdl.unique_name;
        if (mn == send_bc1.unique_name
            || mn == send_bc2.unique_name
            || mn == send_ordered_bc1.unique_name
            || mn == send_ordered_bc2.unique_name
            || mn == send_sticky_bc.unique_name
            || mn == send_sticky_ordered_bc.unique_name
            || mn == start_activity.unique_name
            || mn == start_activity_for_result.unique_name
            || mn == start_service.unique_name
            || mn == bind_service.unique_name) {
            //            std::cout << "Found intent sending API:: "<< mg[t].jvm_hdl << "\n";
            return t;
        }
    }
    return boost::none;
}

std::string trim(string& s)
{
   size_t p = s.find_first_not_of(" \t");
   s.erase(0, p);

   p = s.find_last_not_of(" \t");
   if (string::npos != p)
      s.erase(p+1);

  return s;
}

boost::optional<vd_mg> find_intent_receiving(jitana::virtual_machine& vm, std::string component, int appID)
{
    std::string tmpComponent = boost::replace_all_copy(component, ".", "/")+";";
    auto newtTmpComponent = "L"+trim(tmpComponent);
    const auto& mg = vm.methods();
    vertex_app_id_filter<jitana::method_graph> vfilter;
    vfilter.loaderID = appID;
    vfilter.g = &mg;
    typedef boost::filtered_graph<jitana::method_graph, boost::keep_all, vertex_app_id_filter<jitana::method_graph> > filtered_MG;
    filtered_MG filteredGraph(mg, boost::keep_all(), vfilter);
    
    for (const auto& v : boost::make_iterator_range(vertices(mg))) {
        auto mn = mg[v].jvm_hdl.unique_name;
        if (mg[v].jvm_hdl.type_hdl.descriptor == newtTmpComponent && mg[v].hdl.file_hdl.loader_hdl == appID &&(mn.find("onCreate(Landroid/os/Bundle;)V") != string::npos
                                                                                                                                  || mn.find("onStartCommand(Landroid/content/Intent;II)I") != string::npos
                                                                                                                                  || mn.find("onReceive(Landroid/content/Context;Landroid/content/Intent;)V") != string::npos)) {
            return v;
        }
    }
    return boost::none;
}

//DO reverse DFS to find all potential source methods (based on SUSI list)
//bool find_source(jitana::virtual_machine& vm,boost::optional<jitana::dex_method_hdl> hdl)
boost::optional<vd_mg> find_source(jitana::virtual_machine& vm,boost::optional<jitana::dex_method_hdl> hdl)
{
    auto& mg = vm.methods();
    auto t = vm.find_method(*hdl, true);
    
    vector<vector<string>> sourceSinkList = source_sink_list_vector();
    
    vertex_app_id_filter<jitana::method_graph> vfilter;
    vfilter.loaderID = unsigned(mg[*t].hdl.file_hdl.loader_hdl);
    vfilter.g = &mg;
    typedef boost::filtered_graph<jitana::method_graph, boost::keep_all, vertex_app_id_filter<jitana::method_graph> > filtered_MG;
    filtered_MG filteredGraph(mg, boost::keep_all(), vfilter);
    auto vctr = find_reachable_nodes(*t, mg);

    if (vctr.size() > 1) {
        for (unsigned i = 0; i < vctr.size(); i++) {
            if (find_source_sink(
                                 mg[vctr[i]].jvm_hdl.type_hdl.descriptor,
                                 mg[vctr[i]].jvm_hdl.unique_name, "_SOURCE_", sourceSinkList)) {
                return vctr[i];
            }
        }
    }
    return boost::none;
}

//Identify intent receiving method, then perform DFS to find sink methods.
//Record the path (in MG) if the the sink method has been found
//bool find_sink(jitana::virtual_machine& vm,boost::optional<jitana::dex_method_hdl> hdl)
boost::optional<vd_mg> find_sink(jitana::virtual_machine& vm,boost::optional<jitana::dex_method_hdl> hdl)
{
    vector<vector<string>> sourceSinkList = source_sink_list_vector();
    const auto& mg = vm.methods();
    auto t = vm.find_method(*hdl, true);
    vertex_app_id_filter<jitana::method_graph> vfilter;
    vfilter.loaderID = unsigned(mg[*t].hdl.file_hdl.loader_hdl);
    vfilter.g = &mg;
    typedef boost::filtered_graph<jitana::method_graph, boost::keep_all, vertex_app_id_filter<jitana::method_graph> > filtered_MG;
    filtered_MG filteredGraph(mg, boost::keep_all(), vfilter);
    
    //Find all reachable nodes on the filtered MG
    auto vctr_f = find_reachable_nodes(*t, mg);
    
    if (vctr_f.size() > 1) {
        for (unsigned i = 0; i < vctr_f.size(); i++) {
            if (find_source_sink(mg[vctr_f[i]].jvm_hdl.type_hdl.descriptor,
                                 mg[vctr_f[i]].jvm_hdl.unique_name, "_SINK_", sourceSinkList)){
                return vctr_f[i];
            }
        }
    }
    return boost::none;
}

void update_mg(jitana::virtual_machine& vm, jitana::method_vertex_descriptor v_s, jitana::method_vertex_descriptor v_d)
{
    std::cout << "Inside update_mg\n";
    auto& mg = vm.methods();
    for (const auto& v : boost::make_iterator_range(vertices(mg))){
        if (mg[v].hdl.file_hdl.loader_hdl == mg[v_s].hdl.file_hdl.loader_hdl &&
            mg[v].jvm_hdl.type_hdl.descriptor == mg[v_d].jvm_hdl.type_hdl.descriptor){
            jitana::method_call_edge_property eprop;
            eprop.virtual_call = false;
            if (! boost::edge(v_s, v, mg).second){
                add_edge(v_s, v, eprop, mg);
            }
        }
    }
}


std::vector <std::string> analyzer_target_rec(std::string apkName, std::string compName)
{
      using boost::type_erasure::any_cast;
    jitana::virtual_machine vm;
    std::vector <std::string> rec_app;
    std::cout << "\tInside analyzer_target_rec ...\n";
    {
        const auto& filenames = { "../../../dex/framework/core.dex",
            "../../../dex/framework/framework.dex",
            "../../../dex/framework/framework2.dex",
            "../../../dex/framework/ext.dex",
            "../../../dex/framework/conscrypt.dex",
            "../../../dex/framework/okhttp.dex",
            "../../../dex/framework/core-junit.dex",
            "../../../dex/framework/android.test.runner.dex",
            "../../../dex/framework/android.policy.dex",
            "../../../dex/framework/telephony-common.dex",
            "../../../dex/framework/services.dex" };
        jitana::class_loader loader(10, "SystemLoader", begin(filenames),
                                    end(filenames));
        vm.add_loader(loader);
    }

    {
        //Load sensitive classes that are extracted from SUSI list
        std::ifstream classes("input/classes_sink.txt");
        std::string className;
        for (int cls = 1; std::getline(classes, className); ++cls) {
            vm.find_class({10, className}, true);
        }
    }
    
    auto apkPath = "extracted/"+apkName;
    std::cout << "\tLoading " << " :: " << apkName << "..."
                  << std::endl;
    vm.add_apk(22, apkPath, 10);
    vm.load_all_classes(22);
    
    // Compute the call graph.
    std::cout << "\tComputing the call graph..." << std::endl;
    jitana::add_call_graph_edges(vm);
    
    // Compute the def-use edges.
    std::cout << "\tComputing the def-use edges..." << std::endl;
    std::for_each(vertices(vm.methods()).first, vertices(vm.methods()).second,
                  [&](const jitana::method_vertex_descriptor& v) {
                      add_def_use_edges(vm.methods()[v].insns);
                  });
    // Iterate MG to find intent receiving APIs and whether it's connected to sensitive sink
    auto mg = vm.methods();
    // std::cout << "\trec nodes mg:: " << num_vertices(mg) << "\n";
    std::cout << "\tfind_intent_receiving ...\n";
    if (auto int_rec = find_intent_receiving(vm, compName, 22)){
        std::cout << "\tfind_sink ...\n";
        if (auto sinkAPI = find_sink(vm, mg[*int_rec].hdl)){
            std::cout << "\tint_rec_CN:: " << mg[*int_rec].jvm_hdl.type_hdl.descriptor << "\n";
            std::cout << "\tint_rec_MN:: " << mg[*int_rec].jvm_hdl.unique_name << "\n";
            std::cout << "\tsens_CN:: " << mg[*sinkAPI].jvm_hdl.type_hdl.descriptor << "\n";
            std::cout << "\tsense_MN:: " << mg[*sinkAPI].jvm_hdl.unique_name << "\n";
            rec_app.push_back(mg[*int_rec].jvm_hdl.type_hdl.descriptor); //intent rec CN
            rec_app.push_back(mg[*int_rec].jvm_hdl.unique_name);  //intent rec MN
            rec_app.push_back(mg[*sinkAPI].jvm_hdl.type_hdl.descriptor); //sens sink CN
            rec_app.push_back(mg[*sinkAPI].jvm_hdl.unique_name);    //sens sink MN
        }
    }
    auto command = "rm -rf "+ apkPath;
    std::system(command.c_str());
    return rec_app;
}

bool is_file_exist(const char *fileName)
{
    std::ifstream infile(fileName);
    return infile.good();
}

std::vector<std::vector<std::string>> parse_IF_list() {
    std::vector<std::vector<std::string>> intent_filter_csvV;
    std::ifstream intentFilterFile("input/only_pop_apps_IF.csv");
    std::string line;
    std::cout << "Reading Intent_filters.csv \n";
    for (int index = 1; std::getline(intentFilterFile, line); ++index) {
        boost::tokenizer<boost::escaped_list_separator<char> > tk(line,
                                                                  boost::escaped_list_separator<char>(';'));
        std::vector<std::string> vec;
        for (boost::tokenizer<boost::escaped_list_separator<char> >::iterator i(
                                                                                tk.begin()); i != tk.end(); ++i) {
            vec.push_back(*i);
        }
        intent_filter_csvV.push_back(vec);
    }
    return intent_filter_csvV;
}


void detect_vul_path()
{
     std::vector<std::vector<std::string>> intent_filter_csvV;
    using boost::type_erasure::any_cast;
    jitana::virtual_machine vm;
    std::string nameAPK;
    vector<vector<string>> sourceSinkList = source_sink_list_vector();

    {
        const auto& filenames = { "../../../dex/framework/core.dex",
            "../../../dex/framework/framework.dex",
            "../../../dex/framework/framework2.dex",
            "../../../dex/framework/ext.dex",
            "../../../dex/framework/conscrypt.dex",
            "../../../dex/framework/okhttp.dex",
            "../../../dex/framework/core-junit.dex",
            "../../../dex/framework/android.test.runner.dex",
            "../../../dex/framework/android.policy.dex",
            "../../../dex/framework/telephony-common.dex",
            "../../../dex/framework/services.dex" };
        jitana::class_loader loader(0, "SystemLoader", begin(filenames),
                                    end(filenames));
        vm.add_loader(loader);
    }

    {
        //Load sensitive classes that are extracted from SUSI list
        std::ifstream classes("input/source_classes.txt");
        std::string className;
        for (int cls = 1; std::getline(classes, className); ++cls) {
            vm.find_class({0, className}, true);
        }
    }
    
    // Read APK files
    std::set<std::string> ref_classes;
    std::vector<std::vector<std::string>> ref_info = parse_ref_csv();
    std::ifstream location_ifs("extracted/location.txt");
    std::string name;
    for (int loader_idx = 1; std::getline(location_ifs, name); ++loader_idx) {
        std::cout << "Loading " << loader_idx << " " << name << " ..."
        << std::endl;
        vm.add_apk(loader_idx, "extracted/" + name, 0);
        apkNames.push_back("extracted/" + name);
        nameAPK = name+".apk";
        auto lv = find_loader_vertex(loader_idx, vm.loaders());
        
        std::cout << "Loading additional DEX...\n";
        std::ifstream dex_records("/media/edrive1/Android/result_dataset_journal/output_G10/output-reana/"+name+".apk_dex.txt");     
        
        std::string dex,line2;
        std::getline(dex_records,line2);
        std::cout << "Line:: " << line2 << std::endl;
        while (std::getline(dex_records,line2)){
            dex = line2;
            std::cout << "Load DEX:: ../jitana-reana/"<< dex << "\n";
	       vm.loaders()[*lv].loader.add_file("/media/edrive1/Android/result_dataset_journal/"+dex);
        }
        
        vm.load_all_classes(loader_idx);
        std::cout << "load_all_classes done" << std::endl;
        
        std::cout << "Loading Ref methods\n";
        for (unsigned i = 1; i < ref_info.size(); i++){
            if(ref_info[i][0] == nameAPK){
                jitana::dex_method_hdl s_mh, t_mh;
                s_mh.file_hdl.loader_hdl.idx = 1;
                s_mh.file_hdl.idx = atoi((ref_info[i][1].substr(2,1)).c_str());
                s_mh.idx = atoi((ref_info[i][1].substr(5)).c_str());
                auto v_s = vm.find_method(s_mh, false);
                
                t_mh.file_hdl.loader_hdl.idx = 1;
                t_mh.file_hdl.idx = atoi((ref_info[i][2].substr(2,1)).c_str());
                t_mh.idx = atoi((ref_info[i][2].substr(5)).c_str());
                auto v_t = vm.find_method(t_mh, false);
                
                update_mg(vm, *v_s, *v_t);
                auto mth = vm.find_method(t_mh, true);
                ref_hdl.push_back(*mth);
                ref_hdl_pair.push_back(std::make_pair(*vm.find_method(s_mh, true), *vm.find_method(t_mh, true)));

                if (mth){
                    ref_classes.insert(vm.methods()[*mth].jvm_hdl.type_hdl.descriptor);
                }
            }
        }
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
    
    std::ofstream ofs_sender;
    std::ifstream ofs_int_check("output/vuln_path_journal_G10.csv");
    ofs_sender.open("output/vuln_path_journal_G10.csv",
                            std::ofstream::out | std::ofstream::app);
    if (!ofs_int_check.good()) {
        ofs_sender << "S_App,pkg_name,ref_DCL_CN,ref_DCL_C_Type,CallSiteType,strAction_CN,strAction_C_Type,strAction_MN,";
        ofs_sender << "intentSending_CN,intentSending_C_Typr,intentSending_MN,sens_src_CN,sens_src_C_type,sens_src_MN,";
        ofs_sender << "D_App,D_CN,Intent_Action,";
        ofs_sender << "int_rec_CN,int_rec_MN,sens_sink_CN,sens_sink_MN,Type\n";
    }

    //Get Package name
    const auto& lg = vm.loaders();
    auto package_name = lg[1].loader.name();
  
    //Read IF CSV list
    intent_filter_csvV = parse_IF_list();
    std::cout << "IF size:: " << intent_filter_csvV.size() << "\n";
    // Iterate MG to find intent sending APIs in ref/DCL class
    auto mg = vm.methods();
	auto cg = vm.classes();
    for (const auto& v : boost::make_iterator_range(vertices(mg))) {
        const auto& ig = mg[v].insns;
        auto gprop = ig[boost::graph_bundle];
        
        //check if method is in ref class
        // for (auto& cls : ref_hdl){
        for (auto& p : ref_hdl_pair){
            auto cls = p.second;
            if (mg[v].hdl.file_hdl.loader_hdl == 1 && mg[v].jvm_hdl.type_hdl.descriptor == mg[cls].jvm_hdl.type_hdl.descriptor){
                std::cout << "ref Class:: " << mg[cls].jvm_hdl.type_hdl.descriptor << "\n";
                auto mn = mg[v].jvm_hdl.unique_name;
                //Check String matching
                for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                    const auto* cs_insn = get<jitana::insn_const_string>(
                                                                         &ig[iv].insn);
                    if (!cs_insn) {
                        continue;
                    }
                    for (unsigned long i = 0; i < intent_filter_csvV.size(); i++) {
                        if (cs_insn->const_val != "android.intent.action.MAIN" 
                            && cs_insn->const_val == intent_filter_csvV[i][4]) {
                            std::cout << "\nFound matching IF:: " << cs_insn->const_val << "\n";
                            std::cout << "\tfind_intent_sending ...\n";
                            if (auto int_snd = find_intent_sending(vm, v)){
                                //Find sensitive source based on the method vertex v
                               std::cout << "\tfind_source ...\n";
                               if (auto sens_src = find_source(vm, mg[v].hdl)){
                                //Check if receiver app contains sensitive sink 
                                //Following parameters are required 
                                //1- apk name of receiver app
                                //2- D_CL 
                                //3- Intent action string
			
				auto apkPath = "/media/edrive1/Android/newLoc_Apps_Popular/"+intent_filter_csvV[i][1]+".apk";
                                //auto apkPath = "/media/think/extdrive/Android/analyzed_Apps_Popular/"+intent_filter_csvV[i][1]+".apk";
                                std::cout << "\tAPK path :: "<< apkPath << "\n";
                                if (is_file_exist(apkPath.c_str())){
                                  std::cout <<"file exist.......\n";
                               
                                    std::cout << "\tExtracting:: " << intent_filter_csvV[i][1] << "\n";
                                    auto command = "unzip -q "+apkPath + " -d extracted/"+intent_filter_csvV[i][1];
                                    std::system(command.c_str());
                                    std::cout << "\tAnalyzer_target_rec\n";
                                    auto rec_app = analyzer_target_rec(intent_filter_csvV[i][1], 
                                        intent_filter_csvV[i][3]);
                                    if (rec_app.size() == 4){
                                        std::cout << "Write to CSV file ...\n" ;
                                        std::cout << "file status:: "<< ofs_sender.is_open() << "\n";
										std::cout << "Find the type of Ref/DCL class..." << "\n";
										auto cv_ref = vm.find_class(mg[cls].class_hdl, true);
										std::string compTypeRefDcl = "Unknown";
										for (const auto& e :boost::make_iterator_range(in_edges(*cv_ref, cg))) {
											auto stg_iv = source(e, cg);
											if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Activity;") != std::string::npos){
												compTypeRefDcl = "ActivityComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/content/BroadcastReceiver;") != std::string::npos){
												compTypeRefDcl = "BroadcastReceiverComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Service;") != std::string::npos){
												compTypeRefDcl = "ServiceComponent";
											} 
										}
										
										std::cout << "Find the type of String Action class..." << "\n";
										auto cv_str = vm.find_class(mg[v].class_hdl, true);
										std::string compTypeStrAction = "Unknown";
										for (const auto& e :boost::make_iterator_range(in_edges(*cv_str, cg))) {
											auto stg_iv = source(e, cg);
											if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Activity;") != std::string::npos){
												compTypeStrAction = "ActivityComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/content/BroadcastReceiver;") != std::string::npos){
												compTypeStrAction = "BroadcastReceiverComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Service;") != std::string::npos){
												compTypeStrAction = "ServiceComponent";
											} 
										}
										
										std::cout << "Find the type of Intent Sending class..." << "\n";
										auto cv_snd = vm.find_class(mg[*int_snd].class_hdl, true);
										std::string compTypeIntSnd = "Unknown";
										for (const auto& e :boost::make_iterator_range(in_edges(*cv_snd, cg))) {
											auto stg_iv = source(e, cg);
											if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Activity;") != std::string::npos){
												compTypeIntSnd = "ActivityComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/content/BroadcastReceiver;") != std::string::npos){
												compTypeIntSnd = "BroadcastReceiverComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Service;") != std::string::npos){
												compTypeIntSnd = "ServiceComponent";
											} 
										}
										
										std::cout << "Find the type of Sensitive Source class..." << "\n";
										auto cv_sens = vm.find_class(mg[*sens_src].class_hdl, true);
										std::string compTypeSensSrc = "Unknown";
										for (const auto& e :boost::make_iterator_range(in_edges(*cv_sens, cg))) {
											auto stg_iv = source(e, cg);
											if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Activity;") != std::string::npos){
												compTypeSensSrc = "ActivityComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/content/BroadcastReceiver;") != std::string::npos){
												compTypeSensSrc = "BroadcastReceiverComponent";
											} else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Service;") != std::string::npos){
												compTypeSensSrc = "ServiceComponent";
											} 
										}

                                        std::cout << "Find the type of Ref Call Site..." << "\n";
                                        auto cv_cs = vm.find_class(mg[p.first].class_hdl, true);
                                        std::string compTypeCallSite = "Unknown";
                                        for (const auto& e :boost::make_iterator_range(in_edges(*cv_cs, cg))) {
                                            auto stg_iv = source(e, cg);
                                            if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Activity;") != std::string::npos){
                                                compTypeCallSite = "ActivityComponent";
                                            } else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/content/BroadcastReceiver;") != std::string::npos){
                                                compTypeCallSite = "BroadcastReceiverComponent";
                                            } else if (cg[stg_iv].jvm_hdl.descriptor.find("Landroid/app/Service;") != std::string::npos){
                                                compTypeCallSite = "ServiceComponent";
                                            } 
                                        }

										
                                        ofs_sender << nameAPK << ",";
                                        ofs_sender << package_name << ",";
                                        ofs_sender << mg[cls].jvm_hdl.type_hdl.descriptor << ",";
										ofs_sender << compTypeRefDcl << ",";
                                        ofs_sender << compTypeCallSite << ",";
                                        ofs_sender << mg[v].jvm_hdl.type_hdl.descriptor << ",";
										ofs_sender << compTypeStrAction << ",";
                                        ofs_sender << mg[v].jvm_hdl.unique_name << ",";
                                        ofs_sender << mg[*int_snd].jvm_hdl.type_hdl.descriptor << ",";
										ofs_sender << compTypeIntSnd << ",";
                                        ofs_sender << mg[*int_snd].jvm_hdl.unique_name << ",";
                                        ofs_sender << mg[*sens_src].jvm_hdl.type_hdl.descriptor << ",";
										ofs_sender << compTypeSensSrc << ",";
                                        ofs_sender << mg[*sens_src].jvm_hdl.unique_name << ",";
                                        ofs_sender << intent_filter_csvV[i][2] << ",";
                                        ofs_sender << intent_filter_csvV[i][3] << ",";
                                        ofs_sender << intent_filter_csvV[i][4] << ",";
                                        ofs_sender << rec_app[0] << ",";
                                        ofs_sender << rec_app[1] << ",";
                                        ofs_sender << rec_app[2] << ",";
                                        ofs_sender << rec_app[3] << ",";
                                        if (mg[v].hdl.file_hdl.idx != 0)
                                           ofs_sender << "DCL" << "\n";
                                        else
                                            ofs_sender << "Ref" << "\n";
                                        std::cout << nameAPK << "\n";
                                        std::cout << package_name << "\n";
                                        std::cout << mg[cls].jvm_hdl.type_hdl.descriptor << "\n";
                                        std::cout << mg[v].jvm_hdl.type_hdl.descriptor << "\n";
                                        std::cout << mg[v].jvm_hdl.unique_name << "\n";
                                        std::cout << mg[*int_snd].jvm_hdl.type_hdl.descriptor << "\n";
                                        std::cout << mg[*int_snd].jvm_hdl.unique_name << "\n";
                                        std::cout << mg[*sens_src].jvm_hdl.type_hdl.descriptor << "\n";
                                        std::cout << mg[*sens_src].jvm_hdl.unique_name << "\n";
                                        std::cout << intent_filter_csvV[i][2] << "\n";
                                        std::cout << intent_filter_csvV[i][3] << "\n";
                                        std::cout << intent_filter_csvV[i][4] << "\n";
                                        std::cout << rec_app[0] << "\n";
                                        std::cout << rec_app[1] << "\n";
                                        std::cout << rec_app[2] << "\n";
                                        std::cout << rec_app[3] << "\n";
                                        if (mg[v].hdl.file_hdl.idx != 0)
                                           std::cout << "DCL" << "\n";
                                        else
                                            std::cout << "Ref" << "\n";
                                  }
                               }
                            }
                        }
                        }
                    }
                }
            }
        }
    }
}

int main() {
    detect_vul_path();
}


