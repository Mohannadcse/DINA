/*
 * Copyright (c) 2016, Shakthi Bachala
 * Copyright (c) 2016, Yutaka Tsutano
 * Copyright (c) 2019, Mohannad Alhanahnah
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

#include <boost/graph/graph_utility.hpp>

/*DINA*/
#include <boost/algorithm/string/iter_find.hpp>
/*DINA*/

/*DINA*/
struct ref_method {
    unsigned appID;
    std::string pkgName;
    std::string apkFileName;
    std::vector<std::string> methodName;
    std::vector<std::string> className;
    int invoke_count = 0;
    int newinstance_count = 0;
    int dcl_count = 0;
    
    int newinstance_class_count = 0;
    int newinstance_constructor_count = 0;
    int DexClass_count = 0;
    int DexFile_count = 0;
    int BaseDex_count = 0;
    int PathClass = 0;
};
static std::vector<std::pair<jitana::ref_method, jitana::ref_method> > vRef;


static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_invoke;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_newinstance_class;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_newinstance_constructor;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_dexload;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_dexload2;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_dexload3;
static std::vector<std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> > vRef_dexload4;

std::string apk_name;
std::vector<std::string> apkNames;

jitana::jvm_method_hdl invoke_mh = { { 0, "Ljava/lang/reflect/Method;" },
    "invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;" };

jitana::jvm_method_hdl newinstance_class_mh = { { 0, "Ljava/lang/Class;" },
    "newInstance()Ljava/lang/Object;" };

jitana::jvm_method_hdl newinstance_constructor_mh = { { 0,
    "Ljava/lang/reflect/Constructor;" },
    "newInstance([Ljava/lang/Object;)Ljava/lang/Object;" };

jitana::jvm_method_hdl dexload_mh =
{ { 0, "Ldalvik/system/DexClassLoader;" },
    "<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V" };

jitana::jvm_method_hdl dexload2_mh =
{ { 0, "Ldalvik/system/DexFile;" },
    "loadDex(Ljava/lang/String;Ljava/lang/String;I)Ldalvik/system/DexFile;" };

jitana::jvm_method_hdl dexload3_mh =
{ { 0, "Ldalvik/system/BaseDexClassLoader;" },
    "<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V" };

jitana::jvm_method_hdl dexload4_mh = { { 0, "Ldalvik/system/PathClassLoader;" },
    "<init>(Ljava/lang/String;Ljava/lang/ClassLoader;)V" };
/*DINA*/

void write_graphs(const jitana::virtual_machine& vm);

//Reana
void write_static_reflection_analysis(jitana::virtual_machine& vm);

int invoke_count = 0;
int newinstance_class_count = 0;
int newinstance_constructor_count = 0;
int DexClass_count = 0;
int DexFile_count = 0;
int BaseDex_count = 0;
int PathClass = 0;

void parse_manifest(std::vector<ref_method> all_apps) {
    std::ofstream ofs;
    namespace pt = boost::property_tree;
    std::vector<std::string> components = { "activity", "service", "receiver" };
    pt::ptree tree;
    
    std::ifstream ofs_check("output/Intent_filters.csv");
    ofs.open("output/Intent_filters.csv",
             std::ofstream::out | std::ofstream::app);
    if (!ofs_check.good()) {
        ofs
        << "App_ID,SHA256(APK_Name),PKG_Name,Component_Name,Intent_Action\n";
    }
    
    for (auto a : all_apps) {
        if (a.appID != 0) {
            auto manifestLoacation = "extracted/" + a.apkFileName
            + "/AndroidManifestDecoded.xml";
            pt::read_xml(manifestLoacation, tree);
            for (std::vector<std::string>::size_type i = 0;
                 i != components.size(); i++) {
                for (const auto& x : jitana::child_elements(
                                                            tree.get_child("manifest.application"), components[i])) {
                    auto compName = x.second.get_optional < std::string
                    > ("<xmlattr>.android:name");
                    for (const auto& y : jitana::child_elements(x.second,
                                                                "intent-filter")) {
                        
                        std::vector<std::string> intentActionVec;
                        std::vector<std::string> intentCategoryVec;
                        
                        for (const auto& z : jitana::child_elements(y.second,
                                                                    "action")) {
                            const auto& name = z.second.get < std::string
                            > ("<xmlattr>.android:name");
                            if (    //name != "android.intent.action.MAIN"
                                name != "android.intent.action.VIEW") {
                                
                                ofs << a.appID << ",";
                                ofs << a.apkFileName << ",";
                                ofs << a.pkgName << ",";
                                ofs << compName << ",";
                                ofs << name << "\n";
                            }
                        }
                    }
                }
            }
        }
    }
}

void write_ref_to_csv(jitana::virtual_machine& vm)
{
    std::ofstream wCSV;
    std::ifstream wCSV_check("output/ref_analysis_summary.csv");
    wCSV.open("output/ref_analysis_summary.csv",
              std::ofstream::out | std::ofstream::app);
    
    if (!wCSV_check.good()) {
        
        wCSV << "APK_Name,PKG_Name,Invoke_Count,newinstance_class_count,";
        wCSV << "newinstance_constructor_count,DexClass_count,DexFile_count,BaseDex_count,PathClass,";
        wCSV << "Implement_Reflection,Implement_DCL\n";
    }
    
        wCSV << apk_name << ",";
        wCSV << vm.loaders()[1].loader.name() << ",";
        wCSV << invoke_count << ",";
        wCSV << newinstance_class_count << ",";
        wCSV << newinstance_constructor_count << ",";
        wCSV << DexClass_count << ",";
        wCSV << DexFile_count << ",";
        wCSV << BaseDex_count << ",";
        wCSV << PathClass << ",";
        if (invoke_count + newinstance_class_count + newinstance_constructor_count == 0)
            wCSV << "No" << ",";
        else
            wCSV << "YES" << ",";
        if (DexClass_count + DexFile_count + PathClass + BaseDex_count == 0)
            wCSV << "No" << "\n";
        else
            wCSV << "YES" << "\n";
}


bool excluded_classes (std::string cls)
{
    if (cls == "Landroid/support/v4/view/ViewPager;" || cls == "Landroid/support/v4/app/Fragment;"
        || cls == "Landroid/support/v4/app/ActionBarDrawerToggleHoneycomb;" || cls == "Landroid/support/v4/app/ActionBarDrawerToggleHoneycomb;"
        || cls == "Landroid/support/v4/text/ICUCompatIcs;" || cls == "Landroid/support/v4/text/ICUCompatIcs;"
        || cls == "Landroid/support/v7/internal/view/SupportMenuInflater$InflatedOnMenuItemClickListener;"
        || cls == "Landroid/support/v7/internal/view/menu/MenuItemWrapperICS;" || cls == "Landroid/support/v7/widget/SearchView$AutoCompleteTextViewReflector;" || cls == "Landroid/support/v7/internal/view/SupportMenuInflater$MenuState;" || cls == "Landroid/support/v4/view/ViewPager;" || cls == "Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;" || cls == "Landroid/support/v4/view/ViewCompatEclairMr1;"
        || cls == "Landroid/support/v4/view/ViewCompat$BaseViewCompatImpl;"  || cls == "Landroid/support/v4/app/BundleCompatDonut;" || cls == "Landroid/support/v4/graphics/drawable/DrawableCompatJellybeanMr1;" || cls == "Landroid/support/v4/graphics/drawable/DrawableCompatJellybeanMr1;" || cls == "Landroid/support/v4/media/ParceledListSliceAdapterApi21;" || cls == "Landroid/support/v4/app/BundleCompatGingerbread;" || cls == "Landroid/support/v4/widget/PopupWindowCompat$BasePopupWindowImpl;"
        || cls.find("Landroid/support/v4/") != std::string::npos){
        return true;
    }
    return false;
}

void capture_ref_dcl(jitana::virtual_machine& vm)
{
    int invoke_ct = 0;
    int newinstance_class_ct = 0;
    int newinstance_constructor_ct = 0;
    int dexload_ct = 0;
    int dexload2_ct = 0;
    int dexload3_ct = 0;
    int dexload4_ct = 0;
    
    auto& mg = vm.methods();
    //iterate MG
    for (const auto& v_mg : boost::make_iterator_range(vertices(mg))){
        //Check if the vertex belong to the app
        if (mg[v_mg].hdl.file_hdl.loader_hdl == 1){
            auto ig = mg[v_mg].insns;
            
            //Iterate IG of the intended method
            //check if this method invokes any of the reflection of DCL APIs
            for (const auto& iv : boost::make_iterator_range(vertices(ig))) {
                const auto& prop = ig[iv];
                const auto& insn_info = info(op(prop.insn));
                if (insn_info.can_virtually_invoke() ||insn_info.can_directly_invoke ()) {
                    auto method_hdl = *jitana::const_val<jitana::dex_method_hdl>(prop.insn);
                    if (auto imm = vm.find_method(method_hdl, true) ) {
                        if ((mg[*imm].jvm_hdl.unique_name == invoke_mh.unique_name)
                            && (mg[*imm].jvm_hdl.type_hdl.descriptor == invoke_mh.type_hdl.descriptor)
                            && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            invoke_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_invoke.push_back(actual_api);
                            
                        }else if ((mg[*imm].jvm_hdl.unique_name == newinstance_class_mh.unique_name)
                                  &&(mg[*imm].jvm_hdl.type_hdl.descriptor == newinstance_class_mh.type_hdl.descriptor)
                                  && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            newinstance_class_ct++;
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_newinstance_class.push_back(actual_api);
                            
                        }else if ((mg[*imm].jvm_hdl.unique_name == newinstance_constructor_mh.unique_name)
                                  &&(mg[*imm].jvm_hdl.type_hdl.descriptor == newinstance_constructor_mh.type_hdl.descriptor)
                                  && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            newinstance_constructor_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_newinstance_constructor.push_back(actual_api);
                            
                        }else if((mg[*imm].jvm_hdl.unique_name == dexload_mh.unique_name)
                                 &&(mg[*imm].jvm_hdl.type_hdl.descriptor == dexload_mh.type_hdl.descriptor)
                                 && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            dexload_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_dexload.push_back(actual_api);
                            
                        }else if((mg[*imm].jvm_hdl.unique_name == dexload2_mh.unique_name)
                                 &&(mg[*imm].jvm_hdl.type_hdl.descriptor == dexload2_mh.type_hdl.descriptor)
                                 && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            dexload2_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_dexload2.push_back(actual_api);
                            
                        }else if((mg[*imm].jvm_hdl.unique_name == dexload3_mh.unique_name)
                                 &&(mg[*imm].jvm_hdl.type_hdl.descriptor == dexload3_mh.type_hdl.descriptor)
                                 && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            dexload3_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_dexload3.push_back(actual_api);
                            
                        } else if((mg[*imm].jvm_hdl.unique_name == dexload4_mh.unique_name)
                                  &&(mg[*imm].jvm_hdl.type_hdl.descriptor == dexload4_mh.type_hdl.descriptor)
                                  && !excluded_classes(mg[v_mg].jvm_hdl.type_hdl.descriptor)){
                            dexload4_ct++;
                            
                            std::pair<jitana::method_vertex_descriptor, jitana::method_vertex_descriptor> actual_api;
                            actual_api.first = v_mg;
                            actual_api.second = *imm;
                            vRef_dexload4.push_back(actual_api);
                        }
                    }
                }
            }
        }
    }
    
    invoke_count = invoke_ct;
    newinstance_class_count = newinstance_class_ct;
    newinstance_constructor_count = newinstance_constructor_ct;
    DexFile_count = dexload_ct;
    DexClass_count = dexload2_ct;
    BaseDex_count = dexload3_ct;
    PathClass = dexload4_ct;
}


void run_iac_analysis() {
    jitana::virtual_machine vm;
    
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
    
    std::ifstream location_ifs("extracted/location.txt");
    std::string name;
    for (int loader_idx = 1; std::getline(location_ifs, name); ++loader_idx) {
        std::cout << "Loading " << loader_idx << " " << name << "..."
        << std::endl;
        vm.add_apk(loader_idx, "extracted/" + name, 0);
        //add additional dex files
        vm.load_all_classes(loader_idx);
        apkNames.push_back(name);
        apk_name = name;
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
   
    capture_ref_dcl(vm);
    std::ofstream ofs("output/"+apk_name+"_static_refs.txt");
    ofs << "Invoke: " << invoke_count << "\n";
    ofs << "newinstance_class_count: " << newinstance_class_count << "\n";
    ofs << "newinstance_constructor_count: " << newinstance_constructor_count << "\n";
    ofs << "DexFile_count: " << DexFile_count << "\n";
    ofs << "DexClass_count: " << DexClass_count << "\n";
    ofs << "BaseDex_count: " << BaseDex_count << "\n";
    ofs << "PathClass: " << PathClass << "\n";
    
    std::ofstream ofs_ref;
    std::ifstream ofs_ref_check("output/static_ref_cls_cat.csv");
    ofs_ref.open("output/static_ref_cls_cat.csv",
                            std::ofstream::out | std::ofstream::app);
    if (!ofs_ref_check.good()) {
        ofs_ref << "App,pkg_name,actual_class,api_class\n";
    }


   
    ofs << "\nInvoke Details: \n";

    auto&mg = vm.methods();
    auto& lg = vm.loaders();
    for (auto i : vRef_invoke) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\nnewinstance_class Details: \n";
    for (auto &i : vRef_newinstance_class) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\nnewinstance_constructor Details: \n";
    for (auto &i : vRef_newinstance_constructor) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\ndexload Details: \n";
    for (auto &i : vRef_dexload) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\ndexload2 Details: \n";
    for (auto &i : vRef_dexload2) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\ndexload3 Details: \n";
    for (auto &i : vRef_dexload3) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    
    ofs << "\ndexload4 Details: \n";
    for (auto &i : vRef_dexload4) {
        ofs << "{{ actual_class: " << mg[i.first].jvm_hdl << ","
        << "{api_class: " << mg[i.second].jvm_hdl << "}}\n ";
        ofs_ref << apk_name << ",";
        ofs_ref << lg[1].loader.name() << ",";
        ofs_ref << mg[i.first].jvm_hdl.type_hdl.descriptor << ",";
        ofs_ref << mg[i.second].jvm_hdl.type_hdl.descriptor << "\n";
    }
    write_ref_to_csv(vm);

    std::vector<ref_method> all_apps;
    for (const auto& lv : boost::make_iterator_range(vertices(lg))) {
        ref_method ref;
        ref.appID = unsigned(lg[lv].loader.hdl());
        if (ref.appID == 0)
            ref.apkFileName = "LoaderClass";
        else{
            ref.apkFileName = apkNames[ref.appID - 1];
            ref.pkgName = lg[lv].loader.name();
        }
        all_apps.push_back(ref);
    }
    parse_manifest(all_apps);
}


int main() {
    run_iac_analysis();
}   