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
 *  This pass concatenates all inputs to a single fuzzing port to be additionally exposed from the top level for fuzzing.
 */

#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

static void gen_fuzz_port( RTLIL::Design *design, bool opt_verbose, std::vector<std::string> excluded_signals){
	RTLIL::Module *module = design->top_module();
	RTLIL::SigSpec fuzz_wires = SigSpec();
    for (auto &wire_iter : module->wires_){
		RTLIL::Wire *wire = wire_iter.second;

		for(auto &exclude: excluded_signals){
            if(!strcmp(RTLIL::id2cstr(wire->name),exclude.c_str())) goto SKIP;
        }

		if (!design->selected(module, wire))
			continue;

        if(wire->port_input && !wire->has_attribute(ID(cellift_in))){
            if(opt_verbose) log("Adding input %s to fuzzing port\n", RTLIL::id2cstr(wire->name));
			fuzz_wires.append(wire);
			wire->port_input = false;
        }

		SKIP: continue;
    }
	RTLIL::Wire *fuzz_port = module->addWire("\\fuzz_in", fuzz_wires.size());
	fuzz_port->set_bool_attribute(ID(fuzz_wire));
	module->connect(fuzz_wires, fuzz_port);
	fuzz_port->port_input = true;
	fuzz_port->set_bool_attribute(ID(port));
	module->fixup_ports();

}
struct PortMuxProbesPass : public Pass {
	PortMuxProbesPass() : Pass("port_fuzz_inputs") { }

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    port_fuzz_inputs [-verbose] <exdluded_signals>\n");
		log("\n");
		log("Creates port for fuzz inputs.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
	}
	
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{

		bool opt_verbose = false;
		log_header(design, "Executing port_fuzz_inputs pass (Concat inputs to form fuzzing port).\n");

		std::vector<std::string>::size_type argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
		}

		std::vector<std::string> excluded_signals;
        if(args.size()>2){
            std::stringstream ss(args[2].c_str());
            log("Excluding signals %s\n", args[2].c_str());
            while(ss.good()){
                    std::string substr;
                    std::getline(ss,substr, ',' );
                    excluded_signals.push_back(substr);
                }

        }

		gen_fuzz_port(design, opt_verbose,excluded_signals);           
				
	}
} PortMuxProbesPass;

PRIVATE_NAMESPACE_END
