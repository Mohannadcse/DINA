/*
 * parse_COVERT.hpp
 *
 *  Created on: Aug 28, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_PARSE_COVERT_HPP_
#define INCLUDE_JITANA_MPI_PARSE_COVERT_HPP_

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <string>
#include <set>
#include <exception>
#include <iostream>
namespace pt = boost::property_tree;


struct covertXML
{
    std::string appName;
    std::string componentName;

    void load(const std::string &filename);
};
//]
//[debug_settings_load
void covertXML::load(const std::string &filename)
{
    // Create empty property tree object
    pt::ptree tree;

    // Parse the XML into the property tree.
    pt::read_xml(filename, tree);

    // Use the throwing version of get to find the debug filename.
    // If the path cannot be resolved, an exception is thrown.
    //m_file = tree.get<std::string>("debug.filename");
    //m_file = tree.get<std::string>("application.components.Component");

    // Use the default-value version of get to find the debug level.
    // Note that the default value is used to deduce the target type.
    //m_level = tree.get("debug.level", 0);

    // Use get_child to find the node containing the modules, and iterate over
    // its children. If the path cannot be resolved, get_child throws.
    // A C++11 for-range loop would also work.
    BOOST_FOREACH(pt::ptree::value_type &v, tree.get_child("application.components")) {
        // The data function is used to access the data stored in a node.
    	std::cout << "First data: " << v.first.data() << '\n';
    	boost::property_tree::ptree subtree = (boost::property_tree::ptree) v.second ;
    	BOOST_FOREACH(boost::property_tree::ptree::value_type &vs,subtree) {
    		std::cout << "\tSub data: " << vs.first.data() <<"\t"<< vs.second.data() << std::endl;
            //std::cout << v.second.data() << std::endl;

    		boost::property_tree::ptree flow = (boost::property_tree::ptree) vs.second ;
    		if (vs.first=="sensitiveFlows"){
    			BOOST_FOREACH(boost::property_tree::ptree::value_type &vs2,flow) {
    				std::cout << "\tSub data: " << vs2.first.data() <<"\t"<< vs2.second.data() << std::endl;
    			}
    		}
        }

    }
}



#endif /* INCLUDE_JITANA_MPI_PARSE_COVERT_HPP_ */
