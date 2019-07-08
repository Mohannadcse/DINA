/*
 * traverse_branch_node.hpp
 *
 *  Created on: Sep 11, 2017
 *      Author: jit
 */

#ifndef INCLUDE_JITANA_MPI_TRAVERSE_BRANCH_NODE_HPP_
#define INCLUDE_JITANA_MPI_TRAVERSE_BRANCH_NODE_HPP_

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/visitors.hpp>
#include <iterator>
#include <jitana/vm_graph/method_graph.hpp>

using Graph = jitana::method_graph;
using VertexPair = std::pair<Graph::vertex_descriptor, Graph::vertex_descriptor>;
using V = Graph::vertex_descriptor;
using vp = jitana::method_vertex_property;
using vd = jitana::method_graph::vertex_descriptor;


// struct Visitor : boost::default_dfs_visitor {
//
//
//
//	 std::vector<V> discover_vertex(V v, const Graph& g) {
//         if (!root) {
//             root = v;
//             branch.push_back(v);
//         }
//         if (!done) {
//        	 //std::cerr << g[v].access_flags << "\n";
//        	 std::cerr << v <<"\n";
//
//         }
//         return branch;
//     }
//
//     void finish_vertex(V v, const Graph& g) {
//         done |= (root == v);
//     }
//
//     bool operator()(V, Graph const&) const { return done; }
//
//     std::vector<V> getBranch(){
//     	return branch;
//     }
//
//     std::vector<V> branch;
//   private:
//     bool done = false;
//     boost::optional<V> root;
// };


//struct class_visitor : boost::default_dfs_visitor {
//    const jitana::method_vertex_descriptor& superclass;
//
//    class_visitor(const jitana::method_vertex_descriptor& superclass)
//    : superclass(superclass)
//    {
//    }
//
//    void discover_vertex(const jitana::method_vertex_descriptor& v,
//                         const jitana::method_graph&)
//    {
//        if (v == superclass) {
//            throw v;
//        }
//    }
//} vis(superclass);


class MyVisitor : public boost::default_dfs_visitor {
public:
    MyVisitor(): vv(new std::vector<vp>()){}

    void discover_vertex(V v, const Graph& g)  { //note the lack of const
        if(boost::in_degree(v,g)!=0){ //only print the vertices in the connected component
        	if (!root) {
        		root = v;
        	}if (!done) {
        		//std::cout <<v << " -> ";
        		vv->push_back(g[v]);
        	}
        }
    }

         void finish_vertex(V v, const Graph& /*g*/) {
             done |= (root == v);
         }

         bool operator()(V, Graph const&) const { return done; }


    std::vector<vp>& GetVector() const  { return *vv; }
private:
    boost::shared_ptr< std::vector<vp> > vv;
    bool done = false;
    boost::optional<V> root;
};

//struct MyVisitor_vd : boost::default_dfs_visitor {
//    template <typename Graph>
//    void discover_vertex(vd v, const Graph& /*g*/)  {
//        vv.push_back(v);
//    }

//    std::vector<vd> vv;
//};

//template <typename Graph, typename VertexDescriptor>
//std::vector<vd>
//find_reachable_nodes(vd& root_v, const Graph& g)
//{
//    std::vector<vd> reachable;
//
//    // Visitor.
//    struct reachable_visitor : boost::default_dfs_visitor {
//        void discover_vertex(vd& v, const Graph&)
//        {
//            //std::cout << "Visiting " << v << "!\n";
//            reachable->push_back(v);
//        }
//
//        std::vector<vd>* reachable;
//    };
//
//    // Color map internally used by depth_first_visit().
//    boost::vector_property_map<int> color_map(
//                                              static_cast<unsigned>(num_vertices(g)));
//
//    // Create a visitor.
//    reachable_visitor vis;
//    vis.reachable = &reachable;
//
//    // Run depth first visit.
//    boost::depth_first_visit(g, root_v, vis, color_map);
//
//    return reachable;
//}

//class MyVisitor_vd : public boost::default_dfs_visitor {
//public:
//    MyVisitor_vd(): vv(new std::vector<vd>()){}
//
//    template <typename Graph>
//    void discover_vertex(vd v, const Graph& g)  {
//        if(boost::in_degree(v,g)!=0){ //only print the vertices in the connected component
//            if (!root) {
//                root = v;
//            }if (!done) {
//                //std::cout <<v << " -> ";
//                vv->push_back(v);
//            }
//        }
//    }
//
//    template <typename Graph>
//    void finish_vertex(vd v, const Graph& /*g*/) {
//        done |= (root == v);
//    }
//
//    template <typename Graph>
//    bool operator()(vd, Graph const&) const { return done; }
//
//    std::vector<vd>& GetVector() const  { return *vv; }
//
//private:
//    boost::shared_ptr< std::vector<vd> > vv;
//    bool done = false;
//    boost::optional<vd> root;
//};

//class MyVisitor : public boost::default_dfs_visitor
//{
//  public:
//  void discover_vertex(V v, const Graph& g) const
// {
//    cerr << v << endl;
//    vv.push_back(v);
//    return;
// }
//
//  std::vector<V> GetVector() const {return vv; }
//
// private:
// std::vector<V> vv;
//
//};

#endif /* INCLUDE_JITANA_MPI_TRAVERSE_BRANCH_NODE_HPP_ */
