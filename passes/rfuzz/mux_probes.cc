/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2022  Tobias Kovats <tkovats@student.ethz.ch> & Flavien Solt <flsolt@ethz.ch>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  This pass identifies multiplexers and wires their select signals to top. Wires that were identified by the previous mark_resets
 *  pass to be directly connected to global reset are skipped. If a wire is the select input to multiple multiplexers, it is only
 *  wired to top once. If the -shallow option is selected, it is only checked whether the exact same instance of a wire is already
 *  wired to top, whereas when omitted all wires within the module that are directly connected (sigmap) are considered.
 */

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"
#include "kernel/sigtools.h"

#include <algorithm>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

std::string sanitize_wire_name(std::string wire_name) {
		std::string ret;
		ret.reserve(wire_name.size());
		for(size_t char_id = 0; char_id < wire_name.size(); char_id++) {
			char curr_char = wire_name[char_id];
			if(curr_char != '$' && curr_char != ':' && curr_char != '.' && curr_char != '\\' && curr_char != '[' && curr_char != ']')
				ret += wire_name[char_id];
		}
		return '\\'+ret;
	}


struct MuxProbesWorker {
private:
	// Command line arguments.
	bool opt_verbose;
	bool opt_shallow;
	SigMap sigmap;
	RTLIL::Module *module;
	std::vector<RTLIL::Wire *> wired_to_top;


	int skip(RTLIL::Wire *new_wire){
		if(new_wire->has_attribute(ID(reset_wire))){ // is reset?
			if (opt_verbose)
				log("Skipping reset wire %s in module %s\n",new_wire->name.c_str(), this->module->name.c_str());
			this->n_skip ++;
			return 1;
		};

		if(opt_shallow){
			for(auto &wire: this->wired_to_top){
				if(wire==new_wire){ // already wired to top?
					if (opt_verbose)
						log("Skipping wire %s in module %s: connected to already probed wire %s\n",new_wire->name.c_str(), this->module->name.c_str(), wire->name.c_str());
					this->n_skip ++;
					return 1; 
				} 
			}
		}
		else{
			for(auto &wire: this->wired_to_top){
				if(this->sigmap(wire)== this->sigmap(new_wire)){ // already wired to top?
					if (opt_verbose)
						log("Skipping wire %s in module %s: connected to already probed wire %s\n",new_wire->name.c_str(), this->module->name.c_str(), wire->name.c_str());
					this->n_skip ++;
					return 1; 
				} 
		}


		}
		this->wired_to_top.push_back(new_wire);
		return 0;
	}


	void create_mux_probes() {
		if (opt_verbose)
			log("Creating mux probes for module %s.\n", module->name.c_str());

		if (module->processes.size())
			log("Multiplexers generated by process are ignored! Execute 'proc' pass to include them.\n");

		for(std::pair<RTLIL::IdString, RTLIL::Cell*> cell_pair : module->cells_) {
			RTLIL::IdString cell_name = cell_pair.first;
			RTLIL::Cell *cell = cell_pair.second;

			if(cell->type.in(ID($mux), ID($_MUX_), ID($_NMUX_))) { // checks if the cell is a mux
				RTLIL::SigSpec port_q(cell->getPort(ID::S));
				for (auto &chunk_it: port_q.chunks()) {

					if (!chunk_it.is_wire()) continue; // skip constants
					if(skip(chunk_it.wire)) continue; // skip if connected wire already wired to top or is reset

					std::string wire_name = "__MUX_"+cell->name.str()+"__WIRE_"+chunk_it.wire->name.str();
					wire_name = sanitize_wire_name(wire_name);
					if (opt_verbose)
						log("Adding wire %s from mux %s in module %s: %s\n", chunk_it.wire->name.c_str(), cell->name.c_str(), module->name.c_str(), wire_name.c_str());

					Wire *new_wire = module->addWire(wire_name, chunk_it.width);
					module->connect(new_wire, chunk_it);

					new_wire->port_output = true;
					new_wire->set_bool_attribute(ID(mux_wire));
					new_wire->set_bool_attribute(module->name.c_str());
					this->n_mux++;
				}
			}

			else if (module->design->module(cell->type) != nullptr) { // is the cell itself a module?
				RTLIL::Module *submodule = module->design->module(cell->type);
				for (Wire *submodule_wire: submodule->wires()) { // iterate through all wires of submodule
					if (submodule_wire->has_attribute(ID(mux_wire))) { // find the ones previously identified as mux selects
						std::string wire_name;
						wire_name = submodule->name.c_str() + std::string("-") + cell->name.c_str() + "_" +submodule_wire->name.str();
						wire_name = sanitize_wire_name(wire_name);
						if (opt_verbose)
							log("Adding wire to module %s from submodule %s: %s\n", module->name.c_str(), submodule->name.c_str(), wire_name.c_str());
						Wire *new_wire = module->addWire(wire_name, submodule_wire->width);
						cell->setPort(submodule_wire->name.str(), new_wire); // connect the new wire to the mux wire in the submodule
						new_wire->port_output = true; // set it as output of the current module
						new_wire->set_bool_attribute(ID(mux_wire));
						for(auto m: module->design->modules()){ // mark the wires with string attributes according to the modules traversed
							if(submodule_wire->has_attribute(m->name.c_str())){
								new_wire->set_bool_attribute(m->name.c_str());
								break;
							}
						}
					}
				}
				submodule->fixup_ports();
			}
		}
		module->fixup_ports();
		log("Probed %i multiplexers in module %s (skipped %i).\n", this->n_mux, RTLIL::id2cstr(module->name), this->n_skip);
	}

public:
	int n_mux = 0;	
	int n_skip = 0;

	MuxProbesWorker(RTLIL::Module *module, bool opt_verbose, bool opt_shallow) {
		this->opt_verbose = opt_verbose;
		this->opt_shallow = opt_shallow;
		this->module = module;
		create_mux_probes();
		this->sigmap = SigMap(module);
	}
};

struct MuxProbesPass : public Pass {
	MuxProbesPass() : Pass("mux_probes", "create probe wires to all MUX") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    mux_probes <command> [options] [selection]\n");
		log("\n");
		log("Creates mux probes reaching the design toplevel.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		bool opt_verbose = false;
		bool opt_shallow = false;

		std::vector<std::string>::size_type argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
			if (args[argidx] == "-shallow") {
				opt_shallow = true;
				continue;
			}
		}

		log_header(design, "Executing mux_probes pass.\n");

		if (GetSize(design->selected_modules()) == 0){
			log_cmd_error("Can't operate on an empty selection!\n");
		}

		if(design->top_module() == NULL){
			log_cmd_error("Can't operate without top module selected! Run hierarchy -top [top_module]!\n");
		}

		// Modules must be taken in inverted topological order to instrument the deepest modules first.
		// Taken from passes/techmap/flatten.cc
		TopoSort<RTLIL::Module*, IdString::compare_ptr_by_name<RTLIL::Module>> topo_modules;
		auto worklist = design->selected_modules();
		while (!worklist.empty()) {
			RTLIL::Module *module = *(worklist.begin());
			worklist.erase(worklist.begin());
			topo_modules.node(module);

			for (auto cell : module->selected_cells()) {
				RTLIL::Module *tpl = design->module(cell->type);
				if (tpl != nullptr) {
					if (topo_modules.database.count(tpl) == 0)
						worklist.push_back(tpl);
					topo_modules.edge(tpl, module);
				}
			}
		}
		if (!topo_modules.sort())
			log_cmd_error("Recursive modules are not supported by mux_probes.\n");

		int total_count = 0;
		int total_skip = 0;
		for (auto i = 0; i < GetSize(topo_modules.sorted); ++i) {
			RTLIL::Module *module = topo_modules.sorted[i];
			MuxProbesWorker worker = MuxProbesWorker(module, opt_verbose, opt_shallow);
			total_count += worker.n_mux;
			total_skip += worker.n_skip;
		}
		log("Probed %i multiplexers in total (skipped %i). Multiple module cells are counted only once.\n", total_count, total_skip);

		
		

	}
} MuxProbesPass;

PRIVATE_NAMESPACE_END
