
#include "BifMetadata.h"
#include "Net.h"
#include "LuajitFunctions.h"

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <iostream>

#define MAX_LINE_SIZE 2048

#ifdef ENABLE_LUAJIT

template<typename T>vector<T> split(const T & str, const T & delimiters) {
    vector<T> v;
    typename T::size_type start = 0;
    auto pos = str.find_first_of(delimiters, start);
    while(pos != T::npos) {
        if(pos != start) // ignore empty tokens
            v.emplace_back(str, start, pos - start);
        start = pos + 1;
        pos = str.find_first_of(delimiters, start);
    }
    if(start < str.length()) // ignore trailing delimiter
        v.emplace_back(str, start, str.length() - start); // add what's left of the string
    return v;
}

BifMeta::BifMeta()
{
	//std::string table_path = std::string(bro_root) + "/spool/tmp/";

	// Parse all loaded scripts
	for ( std::list<ScannedFile>::iterator i = files_scanned.begin(); i != files_scanned.end(); i++ )
	{
		if ( i->skipped )
			continue;

		const char *bif_suffix = ".bif.bro";
		const char *function_suffix = ".bro"; //to provide access to bro script functions
		const char *file_name = (i->name).c_str();

		if (strlen(file_name) >= strlen(bif_suffix)) {
			const char *bif_suffix_ptr = file_name + strlen(file_name)*sizeof(char) - strlen(bif_suffix);
			const char *function_suffix_ptr = file_name + strlen(file_name)*sizeof(char) - strlen(function_suffix);

			// If this is a bif.bro file -- we want to parse it for definitions
			if (strcmp(bif_suffix, bif_suffix_ptr) == 0) {
				// Append all parsed BIF's to bifs/events maps
				if (LoadBifsFromFile(file_name, "function", bifs_map) == -1) {
					reporter->InternalError("Unable to parse BIF's");
				}
				// Events of interest are only declared as BIF's
				if (LoadBifsFromFile(file_name, "event", events_map) == -1) {
					reporter->InternalError("Unable to parse BIF's");
				}
			}
			else if (strcmp(function_suffix, function_suffix_ptr) == 0) {
				// Function
				if (LoadBifsFromFile(file_name, "function", bifs_map) == -1) {
					reporter->InternalError("Unable to parse functions");
				}
			}
		}
	}

#ifdef LUA_DEBUG
	PrintBifs(bifs_map);
	PrintBifs(events_map);
#endif
}

BifMeta::~BifMeta()
{
	bifs_map.clear();
	events_map.clear();
}

void BifMeta::PrintBifs(BifArgMap &bif_args)
{
	BifArgMap::iterator it_map;
	std::vector<string>::iterator it_vec;

	for ( it_map = bif_args.begin(); it_map != bif_args.end(); it_map++ )
	{
		bool first_arg = true;
		int count = 0;
		printf("Bif name:  %s (", (it_map->first).c_str());
		std::vector<string> v = it_map->second;
	    for ( it_vec = v.begin(); it_vec < v.end(); it_vec++ ) 
	    {
	    	if (strcmp("va_args", (it_map->first).c_str()) == 0)
	    	{
	    		count = VA_ARGS;
	    	}
	    	count++;
	    	if (first_arg)
	    	{
				printf("%s", (*it_vec).c_str());
				first_arg = false;
			}
			else
			{
				printf(", %s", (*it_vec).c_str());
			}
		}
		printf(")   - %d args, vector size: %lu\n", count, bif_args[it_map->first].size() );
	}
}

int BifMeta::LoadBifsFromFile(const char *file_name, const char* search_string, BifArgMap &bif_args_map)
{
	int line_count = 0;
	bool va_args;
    size_t found;
    size_t args_start, args_end, arg_split_index;
    size_t count, count_left, count_right;
    bool global_module;

    std::string buf_string;
    std::string bif_name;
    std::string arg_name, arg_type;
	std::vector<std::string> v;
	std::vector<std::string>::iterator it;
	std::string last_module;

	ifstream fp(file_name);

    if (!fp) {
    	reporter->Error("Unable to open file in BifMetadata.cc: %s", file_name);
        return -1;
    }

    // Note: there are plenty of limitations to this parser -- for 
    // example, compound types like 'table[string] of count', and also it
    // requires standard formatting (no spreading function declaration over
    // multiple lines or declaring multiple functions in one line separated
    // by semicolons)

    while ( !fp.eof() ) {
        std::getline(fp, buf_string);
        line_count++;

        va_args = false;

        v = split<std::string>(buf_string, " \t\n\r");

        // Determine last declared module (must adhere to standard format, e.g. 'module LOG;')
        if ((v.size() == 2) && (v[0] == (std::string("module"))) && (v[1].back() == ';')) {
        	if (v[1].size() >= 2) {
        		last_module = v[1].substr(0, v[1].size() - 1);
        		//printf("Found new module: %s  in file: %s  on line: %d\n", last_module.c_str(), file_name, line_count);
				continue;
        	}
        }

        if (v.size() < 3) {
        	continue;
        }

        // Ignore any lines starting with non-alphabetic characters (comments, etc.)
        if (!std::isalpha(v[0].at(0))) {
        	continue; 
        }
        
		if (v[0] != std::string("global")) {
			if (last_module == std::string("GLOBAL")) {
				global_module = true;
			}
			else {
				global_module = false;
			}
			if (v[0] != std::string(search_string)) {
				//we expect 'function', 'event', or 'global' to lead each function declaration
				continue;
			}
		}
		else {
			global_module = false;
		}

		if ((v[1].size() < 2) || (v[1].back() != ':')) {
			continue;
		}

		bif_name = v[1].substr(0, v[1].size() - 1);

		found = v[2].find(std::string(search_string) + std::string("("));
		if (found == std::string::npos) {
			continue;
		}

		args_start = buf_string.find('(');
		args_end = buf_string.find(')');

		if ((args_start == std::string::npos) || (args_end == std::string::npos)) {
			continue;
		}

		if (args_start > args_end) {
			continue;
		}

		/*
		//TODO -- handle multiline declarations
		char term = buf_string.back();
		if (buf_string.find(';') != std::string::npos) {
		//if (term == ';' || term == ',') {
			printf("%c", buf_string.back());
        	continue; //skip declarations and multilines
        }
        else {
        	printf("buf_string:  %s\n", buf_string.c_str());
        }*/

        //TODO: Realized functions can have the same name and different arguments
        // Will address that one later, using a concatenated arg type string as an 
        // addition to the key value, separated by a delimiter

        if (bif_args_map.count(bif_name) == 1) {
			// Note: Bro supports separate function declaration and implementation, but
			// we ignore declarations (that end with a semicolon)
			printf("WARNING: Duplicate entry for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
			continue;
		}

		count_left = std::count(buf_string.begin(), buf_string.end(), '(');
		count_right = std::count(buf_string.begin(), buf_string.end(), ')');

		if (count_left != 1 || count_right != 1) {
			continue;
		}

		if ((!global_module) && (bif_name.find(std::string("::")) == std::string::npos)) {
			if (!last_module.empty()) {
				bif_name = last_module + std::string("::") + bif_name;
				//printf("NOTE: Module name prepended for bif: %s  in file: %s  on line: %d\n", bif_name.c_str(), file_name, line_count);
			}
			/*
			else {
				printf("WARNING: No module for non-global-module bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				continue;
			}*/
		}

		std::vector<std::string> arg_type_list;
		std::string args = buf_string.substr(args_start + 1, args_end - args_start -1);
		std::vector<std::string> split_vector = split<std::string>(args, " \t\n\r");
		std::string tmp;
		for ( it = split_vector.begin(); it < split_vector.end(); it++ ) {
			tmp += *it;
		}
		args = tmp;

		//printf("Args:  %s\n", args.c_str());
		//printf("args_start: %d  args_end: %d  end: %d", args_start, args_end, std::string::npos);

		// TODO: we will not try to parse compound table types, just check that it's a table
		// and skip to the end of the brackets
		int lbracket_count; //finding rbracket subtracts this by one

		found = args.find("va_args");
		if (found != std::string::npos) {
			
			/* // Not true of compound types, however rare (or multiline function definitions)
			count = std::count(args.begin(), args.end(), ',');
			if (count > 0) {
				printf("WARNING: Unexpected format for va_args for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				continue;
			}*/

			arg_split_index = args.find(':');
			if (arg_split_index == std::string::npos) {
				printf("WARNING: No colon in va_args argument set for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				continue;
			}

			if ((arg_split_index + 1) >= (args_end - args_start)) {
				printf("WARNING: invalid argument set -- no type after colon found for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				continue;
			}

			arg_name = args.substr(0, arg_split_index);
			arg_type = args.substr(arg_split_index + 1, args.size() - arg_split_index);
			va_args = true;

			found = arg_name.find("va_args");
			if (found == std::string::npos) {
				printf("WARNING: Unexpected va_args format for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				continue;
			}

			// FIXME: For now, if arg_type starts with table/set/opaque, we just call it a table
			// and bypass the indextype checks
			if (StringToTypeTag(arg_type.c_str(), true)) {
				arg_type_list.push_back(arg_type);
			}
			else if (arg_type.size() > strlen("opaque")) {
				if (strncmp(arg_type.c_str(), "table", strlen("table"))) {
					arg_type_list.push_back(std::string("table"));
				}
				else if (strncmp(arg_type.c_str(), "set", strlen("set"))) {
					arg_type_list.push_back(std::string("table"));
				}
				else if (strncmp(arg_type.c_str(), "opaque", strlen("opaque"))) {
					arg_type_list.push_back(std::string("opaque"));
				}
			}
			else {
				printf("WARNING: Invalid va_args type: %s  for bif: %s  in file: %s  on line: %d\n", \
						arg_type.c_str(), bif_name.c_str(), file_name, line_count);
				continue;
			}
		}
		else if (args.size() > 0) {
			v = split<string>(args, ",");

			for ( it = v.begin(); it < v.end(); it++ ) {
				std::string arg_set = *it;

				arg_split_index = arg_set.find(':');
				if (arg_split_index == std::string::npos) {
					printf("WARNING: No colon in argument set: %s   for bif named: %s  \
						in file: %s  on line: %d\n", arg_set.c_str(), bif_name.c_str(), file_name, line_count);
					continue;
				}

				if ((arg_split_index + 1) >= arg_set.size()) {
					printf("WARNING: invalid argument set -- no type after colon found for bif named: %s  \
						in file: %s  on line: %d\n", bif_name.c_str(), file_name, line_count);
					continue;
				}

				arg_name = arg_set.substr(0, arg_split_index);
				arg_type = arg_set.substr(arg_split_index + 1, arg_set.size() - arg_split_index);

				lbracket_count = 0;
				found = arg_type.find('[');
				if (found != std::string::npos) {
					//printf("WARNING: Found compound arg type:  %s  for bif: %s  in file: %s  on line: %d\n", arg_type.c_str(), bif_name.c_str(), file_name, line_count);
					lbracket_count++;
				}
				
				bool valid = true;
				while (lbracket_count > 0) {
					found = arg_type.find('[');
					while (found != std::string::npos && lbracket_count != 0) {
						found = arg_type.find('[', found+1);
						if (found != std::string::npos) {
							lbracket_count++;
						}
					}
					found = arg_type.find(']');
					if (found != std::string::npos) {
						lbracket_count--;
					}
					while (found != std::string::npos && lbracket_count != 0) {
						found = arg_type.find(']', found+1);
						if (found != std::string::npos) {
							lbracket_count--;
						}
					}
					if (lbracket_count != 0) {
						it++;
						if (it < v.end()) {
							arg_type += *it;
						}
						else {
							valid = false;
							break;
						}
					}
				}
				if (!valid) {
					printf("WARNING: Invalid compound type for bif: %s  in file: %s  on line: %d\n", \
						bif_name.c_str(), file_name, line_count);
					continue;
				}

				// Skip attributes
				found = arg_type.find('&');
				if (found != std::string::npos ) {
					arg_type = arg_type.substr(0, found);
				}

				// FIXME: For now, if arg_type starts with table/set, we just call it a table
				// and bypass the indextype checks. "args" is stripped of all whitespace
				// TODO: also need to prepend module names to capture module types (like Log::ID)
				if (StringToTypeTag(arg_type.c_str(), true)) {
					arg_type_list.push_back(arg_type);
				}
				else if (!last_module.empty() && (last_module != std::string("GLOBAL")) && \
				 StringToTypeTag( (last_module + std::string("::") + arg_type).c_str(), true)) {
				 	arg_type = (last_module + std::string("::") + arg_type);
					arg_type_list.push_back(arg_type);
				}
				else if (arg_type.size() > strlen("opaque")) {
					if (strncmp(arg_type.c_str(), "table", strlen("table"))) {
						arg_type_list.push_back(std::string("table"));
					}
					else if (strncmp(arg_type.c_str(), "set", strlen("set"))) {
						arg_type_list.push_back(std::string("table"));
					}
					else if (strncmp(arg_type.c_str(), "opaque", strlen("opaque"))) {
						arg_type_list.push_back(std::string("opaque"));
					}
				}
				else {
					printf("WARNING: Invalid type:  %s  for bif: %s  in file: %s  on line: %d\n", \
						arg_type.c_str(), bif_name.c_str(), file_name, line_count);
					continue;
				}
			}
		}

		if (va_args) {
			bif_args_map[bif_name].push_back(std::string("va_args"));
			bif_args_map[bif_name].push_back(arg_type_list[0]);
			if (arg_type_list.size() > 1) {
				printf("INTERNAL ERROR: Multiple types for va_args argument for bif named: %s  in file: %s  on line: %d\n", \
				bif_name.c_str(), file_name, line_count);
				return -1;
			}
		}
		else {
			bif_args_map[bif_name] = arg_type_list;
		}
    }

    fp.close();
    
	return 1;
}

int BifMeta::BIFArgCount(std::string bif)
{
	if (bifs_map.count(bif) != 1) {
		reporter->Warning("Entry count for bif: %s is %lu", bif.c_str(), bifs_map.count(bif));
		return -1;
	}
	if ((bifs_map[bif].size() == 2) && \
		(strcmp(bifs_map[bif][0].c_str(), "va_args") == 0)) {
		return VA_ARGS;
	}
	return bifs_map[bif].size();
}

int BifMeta::EventArgCount(std::string event)
{
	if (events_map.count(event) != 1) {
		reporter->Warning("Entry count for event: %s is %lu", event.c_str(), events_map.count(event));
		return -1;
	}
	if ((events_map[event].size() == 2) && \
		(strcmp(events_map[event][0].c_str(), "va_args") == 0)) {
		return VA_ARGS;
	}

	return events_map[event].size();
}

TypeTag BifMeta::BIFArgType(std::string bif, int arg_index)
{
	int index = arg_index;
	if (bifs_map.count(bif) != 1) {
		reporter->Error("Unable to find BIF: %s  in BIFArgType", bif.c_str());
		return TYPE_VOID;
	}
	else if ((bifs_map[bif].size() == 2) && \
		(strcmp(bifs_map[bif][0].c_str(), "va_args") == 0)) {
		index = 1;
	}
	else if ((int)bifs_map[bif].size() <= arg_index)
	{
		reporter->Error("Argument index out of range for BIF: %s  index: %d  size: %lu", \
			bif.c_str(), arg_index, bifs_map[bif].size());
		return TYPE_VOID;
	}

	const char *type = bifs_map[bif][index].c_str();

	return (TypeTag) StringToTypeTag(type);
}

TypeTag BifMeta::EventArgType(std::string event, int arg_index)
{
	int index = arg_index;
	if (events_map.count(event) != 1) {
		reporter->Error("Unable to find BIF: %s  in BIFArgType", event.c_str());
		return TYPE_VOID;
	}
	else if ((events_map[event].size() == 2) && \
		(strcmp(events_map[event][0].c_str(), "va_args") == 0)) {
		index = 1;
	}
	else if ((int)events_map[event].size() <= arg_index)
	{
		reporter->Error("Argument index out of range for BIF: %s  index: %d  size: %lu", \
			event.c_str(), arg_index, events_map[event].size());
		return TYPE_VOID;
	}

	const char *type = events_map[event][index].c_str();

	return (TypeTag) StringToTypeTag(type);
}

#endif //ifdef ENABLE_LUAJIT








