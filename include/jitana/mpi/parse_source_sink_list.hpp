/*
 * parse_source_sink_list.hpp
 *
 *  Created on: Sep 9, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_PARSE_SOURCE_SINK_LIST_HPP_
#define INCLUDE_JITANA_MPI_PARSE_SOURCE_SINK_LIST_HPP_

#include <iostream>
#include <string>
#include <vector>

#include <boost/tokenizer.hpp>

using namespace std;

//Converts the format of the class name and method name in the method graph into the format that is used by SuSi
vector<string> prepare_class_method_names(string className, string methodName) {
	vector<string> class_method(2);
	string c = boost::replace_all_copy(className, "/", ".");
	string m = boost::replace_all_copy(methodName, "/", ".");
	class_method[0] = c.substr(1, c.size() - 2);
	auto methodTemp = boost::replace_all_copy(
			boost::replace_all_copy(m, "L", ""), ";", ",");
    //size_t loc = methodTemp.find(",)");
    size_t loc = methodTemp.find("(");
    class_method[1] = methodTemp.substr(0, loc);
    //class_method[1] = methodTemp.substr(0, loc) + ")";

	return class_method;
}

vector<vector<string>> source_sink_list_vector() {
	vector<string> lineVector(3); // 0==className,1==methodName
	vector<vector<string>> sourceSinkList;
	typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
	boost::char_separator<char> sep { " " };

	ifstream bl;
    bl.open("input/SourcesAndSinks.txt");
    
//    bl.open("input/SourceSinkFilter_Org.txt");
    
	while (!bl.eof()) {
		string line;
		getline(bl, line);
		if (line.size() > 1) {
			tokenizer tok { line, sep };
			int i = 0;
			for (const auto &t : tok) {
				if (i == 0) {
					lineVector[0] = t.substr(1, t.size() - 2);
                    //std::cout << "CN:: "<< lineVector[0]<<"\n";
				} else if (i == 2) {
					lineVector[1] = t.substr(0, t.size() - 1);
                    //std::cout << "MN:: "<< lineVector[1] << "\n";
                } else if (i == 4){
                    lineVector[2] = t;
//                  std::cout << "Type:: " << lineVector[2] << "\n\n";
                }
				i++;
			}
			sourceSinkList.push_back(lineVector);
		}
	}
	bl.close();
	return sourceSinkList;
}
/*
 * input vector contains the class name and method node of a vertex in the method graph
 * index 0 = class name
 * index 1 = method name
 * This method does the following:
 * - Converts the elements of the input vector into the approporiate format
 * - Compaire the class name and method names with all entires in the
 */
bool source_Sink_list_check(string className, string methodName, vector<vector<string>> sourceSinkList) {
	//vector<vector<string>> sourceSinkList = source_sink_list_vector();
    std::string cn;
    size_t loc;
    std::string mn;
	vector<string> class_method_formated = prepare_class_method_names(className,
			methodName);
	bool chk = false;
   
	for (unsigned i = 0; i < sourceSinkList.size(); i++) {
        cn = sourceSinkList[i][0];
        loc = sourceSinkList[i][1].find("(");
        mn = sourceSinkList[i][1].substr(0, loc);
        
        if (i == 0){
            std::cout << "Susi CN:: " << cn << "\n";
            std::cout << "Susi MN:: " << mn << "\n";
            std::cout << "class_method_formated[0]:: " << class_method_formated[0] << "\n";
            std::cout << " class_method_formated[1]:: " << class_method_formated[1] << "\n";
        }
        
		if (class_method_formated[0] == cn
				&& class_method_formated[1] == mn) {
			chk = true;
			break;
		}
	}
	return chk;
}

bool find_source_sink(string className, string methodName, string api_type, vector<vector<string>> sourceSinkList) {
    std::string cn;
    size_t loc;
    std::string mn;
    vector<string> class_method_formated = prepare_class_method_names(className,
                                                                      methodName);
    bool chk = false;
    for (unsigned i = 0; i < sourceSinkList.size(); i++) {
        cn = sourceSinkList[i][0];
        loc = sourceSinkList[i][1].find("(");
        mn = sourceSinkList[i][1].substr(0, loc);
        if (class_method_formated[0] == cn
            && class_method_formated[1] == mn && sourceSinkList[i][2] == api_type) {
            chk = true;
            break;
        }
    }
    return chk;
}


//std::vector<jitana::method_graph::vertex_descriptor> get_source_sink_api(std::string api_type)
//{
//    std::vector<jitana::method_graph::vertex_descriptor> apis;
//
//    vector<string> lineVector(3);
//    typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
//    boost::char_separator<char> sep { " " };
//
//    ifstream bl;
//    bl.open(
//            "input/SourceSinkFilter.txt");
//    while (!bl.eof()) {
//        string line;
//        getline(bl, line);
//        if (line.size() > 1) {
//            tokenizer tok { line, sep };
//            int i = 0;
//            for (const auto &t : tok) {
//                if (i == 0) {
//                    lineVector[0] = t.substr(1, t.size() - 2);
//                    string c = boost::replace_all_copy(lineVector[0], ".", "/");
//                    std::string className = "L"+c.substr(1, c.size() - 2)+";";
//                } else if (i == 2) {
//                    lineVector[1] = t.substr(0, t.size() - 1);
//                    string m = boost::replace_all_copy(lineVector[1], ".", "/");
//                } else if (i == 4){
//                    lineVector[2] = t;
//                }
//                i++;
//            }
//            //sourceSinkList.push_back(lineVector);
//        }
//    }
//    bl.close();
//
//
//    if (api_type == "_SINK_"){
//
//    }else if (api_type == "_SOURCE_"){
//
//    }
//    vector<vector<string>> sourceSinkList = source_sink_list_vector();
//
//    return apis;
//}

void parse_test_file()
{
    vector<string> lineVector(3);
    typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
    boost::char_separator<char> sep { " " };
    
    ifstream bl;
    bl.open(
            "input/SourceSinkFilter.txt");
    while (!bl.eof()) {
        string line;
        getline(bl, line);
        if (line.size() > 1) {
            tokenizer tok { line, sep };
            int i = 0;
            for (const auto &t : tok) {
                if (i == 0) {
                    lineVector[0] = t.substr(1, t.size() - 2);
                    string c = boost::replace_all_copy(lineVector[0], ".", "/");
                    std::string className = "L"+c+";";
                    std::cout << "Class:: "<< className<<"\n";
                } else if (i == 1){
                    std::cout << "t:: "<< t <<"\n";
                } else if (i == 2) {
                    lineVector[1] = t.substr(0, t.size() - 1);
                    string m = boost::replace_all_copy(lineVector[1], ".", "/");
                    size_t loc = m.find("(");
                    m = m.insert(loc+1,"L");
                    boost::replace_all_copy(lineVector[1], ".", "/");
                    loc = m.find(")");
                    m = m.insert(loc,";");
                    std::cout << "Method:: "<< m <<"\n";
                } else if (i == 4){
                    lineVector[2] = t;
                }
                i++;
            }
            //sourceSinkList.push_back(lineVector);
        }
    }
    bl.close();
}



#endif /* INCLUDE_JITANA_MPI_PARSE_SOURCE_SINK_LIST_HPP_ */
