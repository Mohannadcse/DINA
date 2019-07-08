/*
 * Copyright (c) 2015, 2016, Yutaka Tsutano
 * Copyright (c) 2019, Mohannad Alhanahnah
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

/* Begin ReAna */
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include "jitana/vm_core/hdl.hpp"
/* End ReAna */

/*DINA*/
#include <jitana/mpi/mpi.hpp>
#include <boost/algorithm/string/iter_find.hpp>
#include <boost/algorithm/string.hpp>
#include <stdlib.h>
/*DINA*/

#include <unistd.h>
#include <sys/wait.h>

#ifdef __APPLE__
#include <OpenGL/gl.h>
#include <GLUT/glut.h>
#else
#include <GL/gl.h>
#include <GL/glut.h>
#endif

/*
 The format of method handler
 (classLoader)_(dex_num)_(method_num)
 set 2nd argument in the find method function should be set to true
 in order to load the method
 
 to get className
 m.methods()[s_v].jvm_hdl.type_hdl.descriptor
 */

std::vector< std::vector<jitana::dex_method_hdl> > mh_ref_pair;

struct insn_counter {
    long long counter = 0;
    long long delta = 0;
    long long last_accessed = 0;
    boost::optional<
    std::pair<jitana::method_vertex_descriptor,
    jitana::insn_vertex_descriptor>> vertices;
};

struct dex_file {
    std::string apk_filename;
    std::string odex_filename;
    std::unordered_map<uint32_t, insn_counter> counters;
    boost::optional<jitana::dex_file_hdl> hdl;
    //jitana::dex_file_hdl hdl;
};

std::vector<dex_file> dex_files;

static bool periodic_output = false;
static bool should_terminate = false;

static jitana::virtual_machine vm;
static jitana::class_loader_hdl system_loader_hdl = 0;
static jitana::class_loader_hdl app_loader_hdl = 1;

/* Begin ReAna */
struct ref_method {
    uint32_t methodIndex;
    std::string methodName;
    std::string className;
    std::string dexName;
    std::string cacheName;
    uint32_t insn_offset;
    jitana::dex_file_hdl hdl;
};
static std::vector<std::pair<ref_method, ref_method> > vRef;
static std::pair<ref_method, ref_method> refM;
static std::vector<std::pair<ref_method, ref_method> > already_written_ref;
static std::vector<std::pair<ref_method, ref_method> > printed_ref;
static std::vector<std::pair<std::string, jitana::dex_file_hdl> > file_name_hdl;
/* End ReAna */

/*DINA*/
int ref_flag = 0;
std::string ref_class_name;
std::string appPkgName;
std::set<std::string> found_intents; /*records all intents matching intents in the intent graph*/
std::vector<std::vector<std::string>> intent_filter_csvV;
std::vector<std::vector<std::string>> detailed_report_csvV;

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
/*DINA*/

// Lighting parameters.
static constexpr GLfloat light0_position[] = { 500.0f, 200.0f, 500.0f, 1.0f };
static constexpr GLfloat light0_ambient_color[] = { 0.5f, 0.5f, 0.5f, 1.0f };
static constexpr GLfloat light0_diffuse_color[] = { 0.8f, 0.8f, 0.8f, 1.0f };

constexpr int line_length = 128;

static int width = 0.0;
static int height = 0.0;
static int window_x = 100;
static int window_y = 100;
static int window_width = 1024;
static int window_height = 700;
static std::string title = "Jitana-TraVis";
static int window;

static double view_angle = -M_PI / 3.0 + M_PI / 2.0;
static double view_altitude = 0.5;
static double view_angle_offset = 0.0;
static double view_altitude_offset = 0.0;
static double view_center_x = 128.0;
static double view_center_x_offset = 0.0;
static double view_center_y = -line_length * 2.0;
static double view_center_y_offset = 0.0;
static double view_zoom = 0.17 * line_length / 128.0;
static double view_zoom_offset = 0.0;

static int drag_start_x = 0;
static int drag_start_y = 0;
static bool dragging = false;
static bool zooming = false;
static bool shifting = false;
static bool full_screen = false;

static void init_opengl();
static void reshape(int width, int height);
static void display();
static void handle_mouse_event(int button, int state, int x, int y);
static void handle_motion_event(int x, int y);
static void handle_keyboard_event(unsigned char c, int x, int y);
static void update_graphs();

void draw_instruction(int index, uint32_t /*address*/,
                      const insn_counter& counter) {
    float x = 14.0f * (index / line_length);
    float y = 4.0f * (index % line_length);
    float z = 0.2;
    
    // Draw a Red 1x1 Square centered at origin
    glBegin(GL_QUADS);
    {
        if (counter.counter > 0) {
            auto r = 0.8f * std::min(counter.counter + 1, 1000ll) / 1000.0f
            + 0.2f;
            auto d = 0.8f * std::min(counter.delta, 5ll) / 5.0f + 0.2f;
            // glColor3f(d, 0.2f, r);
            z += std::min(counter.counter + 1, 1000ll) / 400.0f + 1.0f;
            
            GLfloat color[] = { d, 0.2f, r, 1.0f };
            glMaterialfv(GL_FRONT_AND_BACK, GL_AMBIENT_AND_DIFFUSE, color);
        } else {
            // glColor3f(0.2f, 0.2f, 0.2f);
            // glColor3f(1.0f, 1.0f, 0.2f);
            
            GLfloat color[] = { 1.0f, 1.0f, 0.2f, 1.0f };
            glMaterialfv(GL_FRONT_AND_BACK, GL_AMBIENT_AND_DIFFUSE, color);
        }
        constexpr auto w = 10.0f;
        constexpr auto h = 2.0f;
        
        glNormal3f(0, 1, 0);
        glVertex3f(x + w / 2, z, y + h / 2);
        glVertex3f(x - w / 2, z, y + h / 2);
        glVertex3f(x - w / 2, z, y - h / 2);
        glVertex3f(x + w / 2, z, y - h / 2);
        
        glNormal3f(0, 0, 1);
        glVertex3f(x + w / 2, z, y + h / 2);
        glVertex3f(x - w / 2, z, y + h / 2);
        glVertex3f(x - w / 2, 0, y + h / 2);
        glVertex3f(x + w / 2, 0, y + h / 2);
        
        glNormal3f(0, 0, -1);
        glVertex3f(x + w / 2, z, y - h / 2);
        glVertex3f(x - w / 2, z, y - h / 2);
        glVertex3f(x - w / 2, 0, y - h / 2);
        glVertex3f(x + w / 2, 0, y - h / 2);
        
        glNormal3f(1, 0, 0);
        glVertex3f(x + w / 2, z, y + h / 2);
        glVertex3f(x + w / 2, z, y - h / 2);
        glVertex3f(x + w / 2, 0, y - h / 2);
        glVertex3f(x + w / 2, 0, y + h / 2);
        
        glNormal3f(-1, 0, 0);
        glVertex3f(x - w / 2, z, y + h / 2);
        glVertex3f(x - w / 2, z, y - h / 2);
        glVertex3f(x - w / 2, 0, y - h / 2);
        glVertex3f(x - w / 2, 0, y + h / 2);
    }
    glEnd();
}

void init_opengl() {
    // Set the clear color.
    constexpr GLfloat clearColor[] = { 0.0, 0.0, 0.0, 1.0 };
    glClearColor(clearColor[0], clearColor[1], clearColor[2], clearColor[3]);
    
    // Set the lights.
    glEnable(GL_LIGHT0);
    glLightfv(GL_LIGHT0, GL_POSITION, light0_position);
    glLightfv(GL_LIGHT0, GL_AMBIENT, light0_ambient_color);
    glLightfv(GL_LIGHT0, GL_DIFFUSE, light0_diffuse_color);
    
    // Set the shade model.
    glShadeModel(GL_SMOOTH);
    
    // Enable lighting.
    glEnable(GL_LIGHTING);
    
    // Enable automatic normalization after transformations.
    glEnable(GL_NORMALIZE);
    
    // Enable antialiasing.
    glEnable(GL_POLYGON_SMOOTH);
}

void display() {
    // Clear the screen.
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    
    // Enable the depth buffer.
    glEnable(GL_DEPTH_TEST);
    
    // Compute the view matrix.
    {
        glMatrixMode(GL_MODELVIEW);
        glLoadIdentity();
        auto angle = view_angle + view_angle_offset;
        auto altitude = std::max(view_altitude + view_altitude_offset, 0.0);
        gluLookAt(1000.0 * cos(angle) + view_center_x + view_center_x_offset,
                  1000.0 * altitude,
                  1000.0 * sin(angle) - (view_center_y + view_center_y_offset),
                  view_center_x + view_center_x_offset, 0,
                  -(view_center_y + view_center_y_offset), 0.0, 1.0, 0.0);
    }
    
    int i = 0;
    for (auto& dex : dex_files) {
        glPushMatrix();
        {
            // Disable lighting.
            glDisable(GL_LIGHTING);
            
            float x = 14.0f * (i / line_length);
            float y = 4.0f * (i % line_length);
            glColor3f(1.0f, 1.0f, 1.0f);
            glRasterPos3d(x, 3.0, y - 4.0);
            for (const auto& c : dex.apk_filename) {
                glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, c);
            }
            
            // Enable lighting.
            glEnable(GL_LIGHTING);
        }
        glPopMatrix();
        
        // Draw the instructions.
        const auto& cg = vm.classes();
        const auto& mg = vm.methods();
        for (const auto& cv : boost::make_iterator_range(vertices(cg))) {
            // Ignore a class implemented in a different DEX file.
            if (cg[cv].hdl.file_hdl != *dex.hdl) {
                continue;
            }
            
            auto draw_method = [&](jitana::method_vertex_descriptor mv) {
                const auto& ig = mg[mv].insns;
                auto insns_off = ig[boost::graph_bundle].insns_off;
                if (insns_off == 0) {
                    return;
                }
                
                // A method should be defined in the same class.
                if (mg[mv].class_hdl != cg[cv].hdl) {
                    return;
                }
                
                for (const auto& iv :
                     boost::make_iterator_range(vertices(ig))) {
                    if (!is_basic_block_head(iv, ig)) {
                        continue;
                    }
                    
                    auto addr = insns_off + ig[iv].off * 2;
                    draw_instruction(i++, addr, dex.counters[addr]);
                    
                    // Checking
                    auto p = vm.find_insn(*dex.hdl, addr, false);
                    if (!p) {
                        std::cerr << "method=" << mg[mv].hdl << " ";
                        std::cerr << "insns_off=" << insns_off << " ";
                        std::cerr << "ig[iv].off=" << ig[iv].off << " ";
                        std::cerr << ig[iv].insn << " " << addr << "\n";
                    }
                    else {
                        if (mg[mv].hdl != mg[p->first].hdl) {
                            std::cerr << "************* Bad! ";
                            std::cerr << "method=" << mg[mv].hdl << " ";
                            std::cerr << "ig[iv].off=" << ig[iv].off << " ";
                            std::cerr << "found_method=" << p->first << " ";
                            std::cerr << "found_insn=" << p->second << "\n";
                        }
                    }
                }
            };
            
            for (const auto& mh : cg[cv].vtable) {
                auto mv = vm.find_method(mh, false);
                if (mv) {
                    draw_method(*mv);
                }
            }
            
            for (const auto& mh : cg[cv].dtable) {
                auto mv = vm.find_method(mh, false);
                if (mv) {
                    draw_method(*mv);
                }
            }
        }
        
        i += line_length * 4;
        i -= (i % line_length);
    }
    
    // Update the screen by swapping the buffers.
    glutSwapBuffers();
}

static void handle_mouse_event(int button, int state, int x, int y) {
    switch (state) {
        case GLUT_DOWN:
            drag_start_x = x;
            drag_start_y = y;
            if (glutGetModifiers() == GLUT_ACTIVE_SHIFT) {
                shifting = true;
            } else {
                if (button == GLUT_RIGHT_BUTTON) {
                    zooming = true;
                } else {
                    dragging = true;
                }
            }
            break;
        case GLUT_UP:
            if (dragging) {
                view_angle += view_angle_offset;
                view_altitude += view_altitude_offset;
                view_altitude = std::max(view_altitude, 0.0);
                dragging = false;
            } else if (shifting) {
                view_center_x += view_center_x_offset;
                view_center_y += view_center_y_offset;
                view_center_x_offset = 0.0;
                view_center_y_offset = 0.0;
                shifting = false;
                reshape(width, height);
            } else if (zooming) {
                view_zoom += view_zoom_offset;
                view_zoom = std::min(std::max(view_zoom, 0.01), 10000.0);
                zooming = false;
            }
            break;
    }
    view_angle_offset = 0.0;
    view_altitude_offset = 0.0;
    view_zoom_offset = 0.0;
    
    glutPostRedisplay();
}

static void handle_motion_event(int x, int y) {
    if (dragging) {
        view_angle_offset = 4.0 * (x - drag_start_x) / width;
        view_altitude_offset = 4.0 * (y - drag_start_y) / height;
        glutPostRedisplay();
    }
    
    if (zooming) {
        view_zoom_offset = static_cast<double>(y - drag_start_y) / height;
        reshape(width, height);
        glutPostRedisplay();
    }
    
    if (shifting) {
        const double a = -2000 * view_zoom * (x - drag_start_x) / width;
        const double b = -2000 * view_zoom * (y - drag_start_y) / height;
        view_center_x_offset = a * std::sin(view_angle)
        + b * std::cos(view_angle);
        view_center_y_offset = a * std::cos(view_angle)
        - b * std::sin(view_angle);
        reshape(width, height);
        glutPostRedisplay();
    }
}

static void update_graphs() {
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
                vm.methods()[vertices->first].insns[vertices->second].counter =
                ictr.counter;
            } else {
                std::cerr << "failed to find the vertex: ";
                std::cerr << *dex.hdl << " " << offset << "\n";
            }
        }
    }
}


static void handle_keyboard_event(unsigned char c, int /*x*/, int /*y*/) {
    switch (c) {
        case 'a':
        case 'A':
            std::cout << "loading all classes... " << std::flush;
            vm.load_all_classes(app_loader_hdl);
            std::cout << " done." << std::endl;
            break;
        case 'f':
        case 'F':
            if (full_screen) {
                glutPositionWindow(window_x, window_y);
                glutReshapeWindow(window_width, window_height);
                full_screen = false;
            } else {
                window_x = glutGet(GLUT_WINDOW_X);
                window_y = glutGet(GLUT_WINDOW_Y);
                window_width = glutGet(GLUT_WINDOW_WIDTH);
                window_height = glutGet(GLUT_WINDOW_HEIGHT);
                glutFullScreen();
                full_screen = true;
            }
            break;
        case 'g':
        case 'G':
            update_graphs();
            break;
        case 'p':
        case 'P':
            periodic_output = !periodic_output;
            std::cout << "periodic_output = " << periodic_output << "\n";
            break;
        case 'd':
        case 'D':
            // Compute the def-use edges.
            std::for_each(vertices(vm.methods()).first,
                          vertices(vm.methods()).second,
                          [&](const jitana::method_vertex_descriptor & v) {
                              add_def_use_edges(vm.methods()[v].insns);
                          });
            break;
    }
    glutPostRedisplay();
}

static void reshape(int width, int height) {
    ::width = width;
    ::height = height;
    
    // Compute the aspect ratio.
    const double aspectRatio = static_cast<double>(width) / height;
    
    // Compute the projection matrix.
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    double z = std::min(std::max(view_zoom + view_zoom_offset, 0.01), 10000.0);
    glOrtho(-1000.0 * aspectRatio * z, 1000.0 * aspectRatio * z, -1000.0 * z,
            1000.0 * z, -1400.0, 10000.0);
    
    // Set the viewport.
    glViewport(0, 0, width, height);
}

void pull_apk_files() {
    pid_t pid = ::fork();
    if (pid == 0) {
        // Run the shell script.
        ::execl("pull-apks", "pull-apks", nullptr);
        std::cout << "Command executed successfully\n";
    } else if (pid > 0) {
        int status = 0;
        ::waitpid(pid, &status, 0);
    } else {
        throw std::runtime_error("failed to pull APK files");
    }
}

std::string make_local_filename(const std::string& apk_filename) {
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

void update_insn_counters() {
    struct insn_counter_updater {
        std::vector<dex_file>::iterator it;
        
        void enter_dex_file(const std::string& apk_filename,
                            const std::string& odex_filename) {
            //Travis code
            it = std::find_if(begin(dex_files), end(dex_files),
                              [&](const auto & x) {
                                  return x.apk_filename == apk_filename;
                              });
            if (it == end(dex_files)) {
                dex_files.emplace_back();
                it = end(dex_files);
                --it;
                
                it->apk_filename = apk_filename;
                it->odex_filename = odex_filename;
            }
            
            /* Start ReAna */
            std::pair<std::string, jitana::dex_file_hdl> file_name_hdl_pair;
            file_name_hdl_pair.first = odex_filename;
            file_name_hdl_pair.second = *(it->hdl);
            file_name_hdl.push_back(file_name_hdl_pair);
            /* End ReAna */
            
            for (auto& c : it->counters) {
                c.second.delta = 0;
                ++c.second.last_accessed;
            }
        }
        
        void insn(uint32_t offset, uint16_t counter) {
            auto& c = it->counters[offset];
            c.counter += counter;
            c.delta = counter;
            c.last_accessed = 0;
        }
        void exit_dex_file() {
        }
    } updater;
    
    size_t dex_files_size_old = dex_files.size();
    
    jitana::jdwp_connection conn;
    conn.connect("localhost", "6100");
    conn.receive_insn_counters(updater);
    conn.close();
    
    if (dex_files_size_old != dex_files.size()) {
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
            
            std::ifstream pkg("output/pkgName.txt");
            std::string pkgName,line;
            while (std::getline(pkg,line))
                pkgName = line;
            
            std::ofstream ofs("output/output-reana/"+pkgName+"_dex.txt",std::ofstream::app);
            ofs << local_filename<<"\n";
        }
    }
}

void on_sigint(int) {
    std::cout << "\nInterrupted. Terminating the program..." << std::endl;
    should_terminate = true;
}

/* Start ReAna */
int add_reflection_edge(std::pair<ref_method, ref_method> &source_sink) {
    
    std::ofstream ofs;
    std::ifstream ofs_check("output/output-reana/ref_methods_pair.csv");
    std::vector<jitana::dex_method_hdl> v = std::vector<jitana::dex_method_hdl>(2);
    std::vector<bool> dup_flag;
    
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
    
    const auto& mg = vm.methods();
    
    jitana::method_vertex_descriptor s_v = 0;
    jitana::method_vertex_descriptor t_v = 0;
    for (const auto& mv : boost::make_iterator_range(vertices(mg))) {
        const auto& cv = vm.find_class(mg[mv].class_hdl, false);
        if (!cv) {
            continue;
        }
        
        if ((mg[mv].hdl.idx == source_sink.first.methodIndex)
            && (mg[mv].hdl.file_hdl.idx == source_sink.first.hdl.idx)) {
            source_sink.first.methodName = mg[mv].jvm_hdl.unique_name;
            isValidSource = isValidSource + 1;
            s_v = mv;
            //std::cout << "s_mh= "<< mg[mv].hdl <<"\n";
        }
        
        if ((mg[mv].hdl.idx == source_sink.second.methodIndex)
            && (mg[mv].hdl.file_hdl.idx == source_sink.second.hdl.idx)) {
            source_sink.second.methodName = mg[mv].jvm_hdl.unique_name;
            isValidSink = isValidSink + 1;
            t_v = mv;
            //std::cout << "t_mh= "<< mg[mv].hdl <<"\n";
        }
    }
    
    if (isValidSink == 1 && isValidSource == 1) {
        jitana::method_reflection_edge_property eprop;
        boost::add_edge(s_v, t_v, eprop, vm.methods());
        
        ofs.open("output/output-reana/ref_methods_pair.csv",
                 std::ofstream::out | std::ofstream::app);
        if (!ofs_check.good()) {
            ofs << "Package_Name,S_MH,T_MH\n";
        }
        std::ifstream pkg("output/pkgName.txt");
        std::string pkgName,line;
        while (std::getline(pkg,line))
            pkgName = line;
        
        ofs << pkgName << ",";
        ofs << vm.methods()[s_v].hdl <<",";
        ofs << vm.methods()[t_v].hdl <<"\n";
    }
    if (isValidSink == 1 && isValidSource == 1) {
        /*DINA*/
        ref_flag = 1;
        /*DINA*/
        return 2;
    } else {
        return 1;
    }
}



void update_ref_vm() {
    std::ofstream ofs2;
    std::ifstream ofs_check2("output/output-reana/All_refs.csv");
    ofs2.open("output/output-reana/All_refs.csv",
              std::ofstream::out | std::ofstream::app);
    if (!ofs_check2.good()) {
        ofs2 << "App,S_MN,S_CN,T_MN,T_CN\n";
    }
    
    try {
        static std::vector<std::pair<ref_method, ref_method> >::iterator iterator_already_written_ref;
        
        for (auto &i : vRef) {
            if ((i.first.dexName.find("Jitana_Source_DN_NULL")
                 == std::string::npos)
                && (i.second.dexName.find("Jitana_Target_DN_NULL")
                    == std::string::npos)
                && (i.first.methodName.find("Jitana_Source_MN_NULL")
                    == std::string::npos)
                && (i.second.methodName.find("Jitana_Target_MN_NULL")
                    == std::string::npos)) {
                    iterator_already_written_ref =
                    find_if(already_written_ref.begin(),
                            already_written_ref.end(),
                            [&] (std::pair<ref_method, ref_method > &s)
                            {
                                /*DINA*/
                                ref_class_name = i.second.className;
                                //appPkgName = i.first.className;
                                //std::string refClassName = i.first.className;
                                //std::string refMethodsName = i.first.methodName;
                                
                                /*DINA*/
                                return (
                                        (s.first.methodIndex == i.first.methodIndex)
                                        && (s.first.className == i.first.className)
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
        
        std::ifstream pkg("output/pkgName.txt");
        std::string pkgName,line;
        while (std::getline(pkg,line))
            pkgName = line;
        
        
        //std::ofstream ofs1("output/output-reana/"+counter+"_"+pkgName+"_refs.csv");
        std::ofstream ofs1("output/output-reana/"+pkgName+"_refs.csv");
        
        for (auto &i : printed_ref) {
            
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
                
                //check method graph, then find instruction graph
                /*DINA*/
                ofs2 << pkgName << ",";
                ofs2 << i.first.methodIndex << ",";
                ofs2 << i.first.methodName << ",";
                ofs2 << i.first.className << ",";
                ofs2 << i.first.dexName << ",";
                ofs2 << i.first.cacheName << ",";
                ofs2 << i.first.insn_offset << ",";
                ofs2 << i.second.methodIndex << ",";
                ofs2 << i.second.methodName << ",";
                ofs2 << i.second.className << "\n";
                ofs2 << i.second.dexName << ",";
                ofs2 << i.second.cacheName << ",";
                ofs2 << i.second.insn_offset << std::endl;
                /*DINA*/
            }
        }
    } catch (std::runtime_error e) {
        std::cerr << "error_update_ref_vm: " << e.what() << "\n";
    }
}

void update_ref() {
    jitana::jdwp_connection conn;
    try {
        conn.connect("localhost", "6100");
        auto id = conn.send_command(226, 1);
        jitana::jdwp_reply_header reply_header;
        conn.receive_reply_header(reply_header, id);
        
        auto count = conn.read_uint16();
        for (int i = 0; i < count; i++) {
            std::pair<ref_method, ref_method> refm;
            
            refm.first.methodIndex = conn.read_uint32();
            uint32_t s_mn_sz = conn.read_uint32();
            refm.first.methodName = conn.read_string(s_mn_sz);
            uint32_t s_cn_sz = conn.read_uint32();
            refm.first.className = conn.read_string(s_cn_sz);
            
            uint32_t s_dn_sz = conn.read_uint32();
            refm.first.dexName = conn.read_string(s_dn_sz);
            uint32_t s_cache_n_sz = conn.read_uint32();
            refm.first.cacheName = conn.read_string(s_cache_n_sz);
            
            refm.first.insn_offset = conn.read_uint16();
            
            refm.second.methodIndex = conn.read_uint32();
            uint32_t t_mn_sz = conn.read_uint32();
            refm.second.methodName = conn.read_string(t_mn_sz);
            uint32_t t_cn_sz = conn.read_uint32();
            refm.second.className = conn.read_string(t_cn_sz);
            
            uint32_t t_dn_sz = conn.read_uint32();
            refm.second.dexName = conn.read_string(t_dn_sz);
            uint32_t t_cache_n_sz = conn.read_uint32();
            refm.second.cacheName = conn.read_string(t_cache_n_sz);
            
            refm.second.insn_offset = conn.read_uint16();
            
            vRef.push_back(refm);
        }
        conn.close();
        update_ref_vm();
    } catch (std::runtime_error e) {
        std::cerr << "error_update_ref: " << e.what() << "\n";
        //signal(SIGINT, on_sigint);
    }
}
/* End ReAna */

void update(int /*value*/) {
    try {
        update_insn_counters();
    } catch (std::runtime_error e) {
        std::cerr << "error_update: " << e.what() << "\n";
    }
    
    /* Start ReAna */
    update_ref();
    /* End ReAna */
    
    update_graphs();
    if (periodic_output) {
        static int output_cnt = 0;
        if (output_cnt-- == 0) {
            output_cnt = 20;
        }
    }
    
    if (should_terminate) {
        std::cout << std::endl;
        exit(0);
    }
    
    glutPostRedisplay();
    glutTimerFunc(50, update, 0);
}

void run_reana(int argc, char** argv) {
    // Create a GLUT window.
    glutInit(&argc, argv);
    glutInitWindowPosition(window_x, window_y);
    glutInitWindowSize(window_width, window_height);
    glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGBA | GLUT_DEPTH);
    window = glutCreateWindow(
                              title.empty() ? "Trace Visualizer" : title.c_str());
    glutMouseFunc(handle_mouse_event);
    glutMotionFunc(handle_motion_event);
    glutKeyboardFunc(handle_keyboard_event);
    glutReshapeFunc(reshape);
    glutDisplayFunc(display);
    
    // Initialize OpenGL.
    init_opengl();
    
    try {
        {
            std::vector<std::string> filenames = {
                "../../../dex/framework/core.dex",
                "../../../dex/framework/framework.dex",
                "../../../dex/framework/framework2.dex",
                "../../../dex/framework/ext.dex",
                "../../../dex/framework/conscrypt.dex",
                "../../../dex/framework/okhttp.dex",
                "../../../dex/framework/core-junit.dex",
                "../../../dex/framework/android.test.runner.dex",
                "../../../dex/framework/android.policy.dex" };
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
        
        // Execute the main loop.
        glutMainLoop();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n\n";
        std::cerr << "Please make sure that ";
        std::cerr << "all dependencies are installed correctly, and ";
        std::cerr << "the DEX files exist.\n";
    }
}

void dina_dynamic(int argc, char** argv)
{
    run_reana(argc, argv);
}

int main(int argc, char** argv) {
    std::ifstream pkg("output/pkgName.txt");
    std::string pkgName,line;
    while (std::getline(pkg,line))
        pkgName = line;
    
    appPkgName= line;

    dina_dynamic(argc, argv);
    
    return 1;
}
