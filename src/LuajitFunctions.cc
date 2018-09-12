//Developed by Leo Linsky for Packetsled. Copyright 2016-17.

#include "bro-config.h"

#include "LuajitFunctions.h"
#include "LuajitMgr.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include "Attr.h"
#include "Stmt.h"
#include "EventRegistry.h"
#include "RE.h"

#include "Scope.h"
#include "Func.h"
#include "File.h"
#include "broxygen/Manager.h"

#ifdef ENABLE_LUAJIT

#include <set>
#include <string.h>


//Used for redef record, taken from parse.y
static type_decl_list* copy_type_decl_list(type_decl_list* tdl)
{
	if ( ! tdl ) {
		return 0;
	}

	type_decl_list* rval = new type_decl_list();

	loop_over_list(*tdl, i)
	{
		TypeDecl* td = (*tdl)[i];
		rval->append(new TypeDecl(*td));
	}

	return rval;
}

//Used for redef record, taken from parse.y
static attr_list* copy_attr_list(attr_list* al)
{
	if ( ! al ) {
		return 0;
	}

	attr_list* rval = new attr_list();

	loop_over_list(*al, i)
	{
		Attr* a = (*al)[i];
		::Ref(a);
		rval->append(a);
	}

	return rval;
}

//Used to redef
static bool extend_record(ID* id, type_decl_list* fields, attr_list* attrs, lua_State *L)
{

	if (id) {
		set<BroType*> types = BroType::GetAliases(id->Name());

		if ( types.empty() )
		{
			reporter->Error("failed to redef record: no types found in alias map");
			LuajitManager::SetFaultyScript(L);
			//id->Error("failed to redef record: no types found in alias map");
			return true;
		}

		for ( set<BroType*>::const_iterator it = types.begin(); it != types.end(); )
		{
			RecordType* add_to = (*it)->AsRecordType();
			const char* error = 0;
			++it;

			if ( it == types.end() ) {
				error = add_to->AddFields(fields, attrs);
			}
			else {
				error = add_to->AddFields(copy_type_decl_list(fields),
										  copy_attr_list(attrs));
			}

			if ( error )
			{
				reporter->Error(fmt("error in LuajitFunction's extend_record: %s",error));
				LuajitManager::SetFaultyScript(L);
				//id->Error(error);
				return true;
			}
		}
	}

	return false;
}


typedef enum {
	STATE_NAME,
	STATE_TYPE,
	STATE_ATTRS
} ParseState;

/* Custom BIF's */

//Converts the userdata var args to a val_list, and does a Bro print. If given non userdata
//	args, we will attempt to interpret these as Vals
int function_BroPrintVals(lua_State *L)
{
	int argc = lua_gettop(L);

	val_list* vals = new val_list(argc);
	Val *arg;

	bool userdata[argc];

	int i = 0;
	while (i < argc)
	{
		userdata[i] = false;
		arg = lua_mgr->PullLuaValFromGenericArg(L, (i+1), &userdata[i]);
		if (likely(arg))
		{
			vals->append(arg);
		}
		else
		{
			reporter->Error("In BroPrint: Unable to generate pull argument as Val");
			lua_mgr->SetFaultyScript(L);
			delete vals;
			return false;
		}
		i++;
	}

	if ((*vals)[0])
	{
		BroFile* f;
		bool is_stdout = true;
		int offset = 0;

		if ( vals->length() > 0 && (*vals)[0]->Type()->Tag() == TYPE_FILE )
		{
			is_stdout = false;
			f = (*vals)[0]->AsFile();
			if ( ! f->IsOpen() )
			{
				reporter->Error("Unable to open Lua File Val for printing");
				return LUA_FAILURE;
			}

			++offset;
		}
		else
		{
			f = new BroFile(stdout);
		}

		desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;

		if ( f->IsRawOutput() )
		{
			ODesc d(DESC_READABLE);
			d.SetFlush(0);
			d.SetStyle(style);

			describe_vals(vals, &d, offset);
			f->Write(d.Description(), d.Len());
		}
		else
		{
			ODesc d(DESC_READABLE, f);
			d.SetFlush(0);
			d.SetStyle(style);

			describe_vals(vals, &d, offset);
			f->Write("\n", 1);
		}

		if (is_stdout)
		{
			delete f;
		}
	}

	while (i > 0)
	{
		i--;
		Unref((*vals)[i]);
	}
	delete vals;
	return 0;
}


// Note: We can pass arbitrary arguments this way and it can be a hacky form of 
//  inter-script communication
// Note2: This only generates events for other Lua scripts (and itself), by design.
//  Lua should not mess up other Bro scripts.
int function_GenerateEvent(lua_State *L)
{
	int args_stack = lua_gettop(L);

	if (unlikely(args_stack < 1))
	{
		reporter->Error("Insufficient arguments for generate_event()");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	const char *event_name;
	if (likely(lua_isstring(L, 1)))
	{
		event_name = luaL_checkstring(L, 1);
	}
	else
	{
		reporter->Error("Expecting string for first argument of function_GenerateEvent");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	int argc = args_stack-1;
	val_list *args = new val_list(argc);
	bool *userdata_args = new bool[argc];

	if (unlikely(populate_list(L, 2, argc, args, userdata_args) != LUA_SUCCESS))
	{
		reporter->Error("Insufficient arguments for generate_event()");
		LuajitManager::SetFaultyScript(L);
		delete args;
		delete[] userdata_args;
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Generating event  `%s` . . .", event_name);
#endif

	if (unlikely(!ValidateArgs(event_name, true, args))) {
		reporter->Error("Invalid args for event: %s", event_name);
		LuajitManager::SetFaultyScript(L);
		delete args;
		delete[] userdata_args;
		return LUA_FAILURE;
	}

	//Check there is a Lua script registered to the event
	if (unlikely( ! (lua_mgr->EventResponders())[event_name].size()) ) {
		reporter->Warning("No Lua scripts registered for %s in generate_event(), \
		 aborting...", event_name);
		return 0; //Not a failure condition necessarily
	}

	//Note: this is an acceptable usage of remove -- the string is already used
	lua_remove(L, 1);


	//TODO: this is where it would be useful to have a registry of how many expected args for 
	//	a value, although probably better to trust the user than take more performance hits 
	//	since it shouldn't cause explicit errors

	//Note: Arguments passed here will be LuaRef'd again, even if they're moving to the same
	//	script. That means every single arg needs to be Un-LuaRef'd (if not allocated, 
	//	otherwise just UnRef'd). It should generate a separate userdata for the same object
	//	so the Ref counts should balance out as is.
	lua_mgr->LuajitTryEvent(event_name, args, false);

#ifdef LUA_DEBUG
	reporter->Info("Generated event  `%s` . . .", event_name);
#endif


	//TODO: What about generating the event for non-Lua scripts? That would probably be better, 
	//	but then we need to be careful about how Bro script treats the Ref count when an event 
	//	is called
	

	//Unref anything allocated
	//TODO: What if we created a port from a table and that portval was now referenced in the 
	//	script(s) we generated an event for. I can't Unref it without creating a segfault. 
	//	How to Ref in this situation? Current thinking is it will be in the scope of the new 
	//	function and garbage collection will be called, so removing this is BAD... UNLESS 
	//	Unreffing it would bring the Ref count to one, which I think it does, because 
	//	LuajitTryEvent Ref's it (via PushLuaVal)
	if (argc > 0)
	{
		loop_over_list(*args, k)
		{
			//If it was a userdata (it will be garbage collected by both entities)
			//If not, it will only be garbage collected by the event, but its Lua Ref count
			//	is only one anyway, so just a normal unref in any case to counter
			//	PullLuaValGeneric
			if (!userdata_args[k]) {
				Unref((*args)[k]);
			}
		}
		delete args;
		delete[] userdata_args;
	}

	return 0;
}


//Given RecordType: bro.redefRecord("recordname", "fieldname", "field type", 
//	<attributes> (0-2), "fieldname", ...)

//Only attribute currently supported is "&log" -- &optional is included by default.

//Only used for RecordTypes 
int function_RedefRecord(lua_State *L)
{
	int argc = lua_gettop(L);
	ID *record = NULL;
	if (unlikely(argc < 3))
	{
		reporter->Error("Expecting >=3 arguments for function_RedefRecord(), saw %d", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Redef'ing Record, given %d args", argc);
#endif

	val_list *args = NULL;
	bool *userdata_args;

	args = new val_list(argc-1);
	userdata_args = new bool[argc-1];

	if (unlikely(populate_list(L, 1, argc, args, userdata_args) != LUA_SUCCESS))
	{
		reporter->Error("Error populating argument list for redefRecord");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	RecordType *add_to;

	const char *recordname;
	if (((*args)[0])->Type()->Tag() == TYPE_STRING)
	{
		recordname = ((*args)[0])->CoerceToCString();

		//check first argument to determine the RecordType to redef
		record = lookup_ID(extract_var_name(recordname).c_str(), \
			extract_module_name(recordname).c_str());
		if (!record)
		{
			reporter->Error("Unable to look up record type to redef");
			LuajitManager::SetFaultyScript(L);
			loop_over_list(*args, l)
			{
				if (!userdata_args[l]) {
					Unref((*args)[l]);
				}
			}
			delete args;
			delete[] userdata_args;

			return LUA_FAILURE;
		}

		Unref(record);

#ifdef LUA_DEBUG
			reporter->Info("Redef'ing Record type %s", record->AsType()->GetName().c_str());
#endif

		add_to = record->AsType()->AsRecordType();
	}

	//TODO: May delete this, redef should occur before messing with instances
	else if (((*args)[0])->Type()->Tag() == TYPE_RECORD)
	{
		//check first argument to determine the RecordType to redef
		recordname = ((*args)[0])->Type()->GetName().c_str();
		record = lookup_ID(extract_var_name(recordname).c_str(), \
			extract_module_name(recordname).c_str());
		if (!record)
		{
			reporter->Error("Weird -- Unable to look up record type to redef given record");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}

		Unref(record);

#ifdef LUA_DEBUG
			reporter->Info("Redef'ing Record type %s -- derived from RECORDVAL", \
				record->AsType()->GetName().c_str());
#endif

		//Q: Is the ID's RecordType different than the instance's?
		add_to = record->AsType()->AsRecordType();
	}
	else
	{
		reporter->Error("First argument for redefRecord must be a string or record");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}


	type_decl_list *type_list = new type_decl_list();

	args->remove_nth(0);
	int h;
	for(h=0; h<argc-1; h++)
	{
		//TODO: WTF
	    userdata_args[h] = userdata_args[h+1];
	}

	attr_list *attrs = NULL;

	bool failed = ParseRecordArgs(L, type_list, args, argc, attrs);


	if (likely(!failed))
	{
		failed = extend_record(record, type_list, attrs, L);
	}

	/* //just curious: TODO: Add back in
	loop_over_list(*args, l)
	{
		Unref((*args)[l]);
	}
	delete args;
	*/
	delete[] userdata_args;
	

	/*
	if (failed)
	{
		loop_over_list(*type_list, m)
		{
			delete (*type_list)[m];
		}
		delete type_list;
	}
	*/

	return (failed ? LUA_FAILURE : 0);

}

//For Enum: use bro.redefEnum("enum's global id", "new_enum")
//Takes either EnumVal or string for the first argument, and the new enumerator for the second
int function_RedefEnum(lua_State *L)
{
	int argc = lua_gettop(L);
	if (unlikely(argc != 2))
	{
		reporter->Error("Expecting 2 arguments for function_RedefEnum(), saw %d", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	//lookup global
	const char *enum_name;
	const char *enum_base;
	if (likely(lua_type(L, 1) == LUA_TSTRING))
	{
		enum_base = luaL_checkstring(L, 1);
	}
	else
	{
		reporter->Error("Expecting string for first argument of function_RedefEnum");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	ID *enum_id = lookup_ID(extract_var_name(enum_base).c_str(), \
		extract_module_name(enum_base).c_str());
	if (!enum_id)
	{
		reporter->Error("Unknown identifier in redefEnum");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	Unref(enum_id);

	BroType *et = (BroType *) enum_id->AsType();

	if (unlikely(!et || et->Tag() != TYPE_ENUM))
	{
		reporter->Error("Unable to get EnumType from %s in function_RedefEnum", enum_base);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
#ifdef DEBUG_LUA
		reporter->Info("Enum name  %s  found", et->GetName());
#endif

	int i;
	for (i=2; i<=argc; ++i)
	{
#ifdef DEBUG_LUA
		reporter->Info("Adding enum value module: %s name: %s  to module: %s name: %s", \
			extract_module_name(enum_name).c_str(), extract_var_name(enum_name).c_str(), \
			extract_module_name(enum_base).c_str(), extract_var_name(enum_base).c_str() );
#endif
		if (likely(lua_type(L, 1) == LUA_TSTRING))
		{
			enum_name = luaL_checkstring(L, i);
		}
		else
		{
			reporter->Error("Expecting all string arguments for redeffing Enum values of %s", \
				enum_base);
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}

		if ( et->AsEnumType()->Lookup(extract_module_name(enum_name), \
			extract_var_name(enum_name).c_str()) != -1 )
		{
			Unref(enum_id);
			reporter->Info("Ignoring duplicate Bro-enum definition in Lua: %s , %s", \
				enum_base, enum_name);
			return 0;
		}
		
		et->AsEnumType()->AddName(extract_module_name(enum_name), extract_var_name(enum_name).c_str(), \
			true, false);
	}

	//TODO: Don't throw error if already defined, also for RecordTypes, even if this requires
	//Lua override. BECAUSE of dynamic loading, it's very possible a script will redef something
	//then get unloaded then fixed and reloaded.
	//can still throw error for other things of course

	//Note: Also, for creating new ones: new EnumType(module + "::" + local_id);

	Unref(enum_id);
	return 0;
}



int function_LookupBroVal(lua_State *L)
{
	int args_stack = lua_gettop(L);

	if (unlikely(args_stack < 1))
	{
		reporter->Error("Insufficient arguments for function_LookupBroVal()");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	const char *var_name;
	if (likely(lua_isstring(L, 1)))
	{
		var_name = luaL_checkstring(L, 1);
	}
	else
	{
		reporter->Error("Expecting string for first argument of function_LookupBroVal");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	ID *val_token = lookup_ID(extract_var_name(var_name).c_str(), \
		extract_module_name(var_name).c_str());
	Unref(val_token);
	Val *idval;
	bool ref=true;

	if (!val_token)
	{
		reporter->Error("Unable to find Bro var by name %s", var_name);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (val_token->HasVal())
	{
#ifdef DEBUG_LUA
		reporter->Info("Interpreting lookup of module: %s  name: %s as Val", \
			extract_module_name(var_name).c_str(), extract_var_name(var_name).c_str() );
#endif
		idval = val_token->ID_Val();
		if (!idval)
		{
			reporter->Error("Unable to obtain Val for %s in function_LookupBroVal", var_name);
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}
	else if (val_token->AsType())
	{
#ifdef DEBUG_LUA
		reporter->Info("Interpreting lookup of module: %s  name: %s as Val", \
			extract_module_name(var_name).c_str(), extract_var_name(var_name).c_str() );
#endif
		BroType *et = val_token->AsType();
		if (unlikely(!et->Tag() == TYPE_ENUM))
		{
			reporter->Error("Lookup can only be used for Vals and Enum Types");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
#ifdef DEBUG_LUA
		reporter->Info("Enum name  %s  found", et->GetName());
#endif
		if (likely(args_stack==2))
		{
			const char *enum_name;
			if (likely(lua_isstring(L, 2)))
			{
				enum_name = luaL_checkstring(L, 2);
			}
			else
			{
				reporter->Error("Expecting enum string for second argument of \
					function_LookupBroVal");
				LuajitManager::SetFaultyScript(L);
				return LUA_FAILURE;
			}
			int enum_num = ((EnumType *)et)->Lookup(extract_module_name(enum_name), \
				extract_var_name(enum_name).c_str());
#ifdef LUA_DEBUG
			reporter->Info("Enum number: %d selected in lookup", enum_num);
#endif
			idval = new EnumVal(enum_num, ((EnumType *)et));
			ref = false;
		}
		else
		{
			reporter->Error("Expecting 2 args for enum type lookup in function_LookupBroVal");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}
	else
	{
		reporter->Error("Strange error, value not initialized in function_LookupBroVal");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(!lua_mgr->PushLuaVal(L, idval, ref)))
	{
		reporter->Error("Unable to push resultant Val in function_LookupBroVal");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	return 1;
}


/* Userdata/Val Constructors */

int function_NewPort(lua_State *L)
{
	//Expecting port (number) and type (string)
	int port;
	const char *type;

	int argc = lua_gettop(L);
	if (unlikely(argc != 2))
	{
		reporter->Error("Lua called newPort with incorrect number of arguments:  %d ; \
			expected 2", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	if (unlikely(!lua_isnumber(L, 1)))
	{
		reporter->Error("Lua unable to resolve newPort arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	port = lua_tonumber(L, 1);

	if (unlikely(lua_type(L, 2) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newPort arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	
	type = luaL_checkstring(L, 2);
	Val *v = (Val *)(new PortVal(port, StringToTransportProto(type)));

	lua_mgr->PushLuaVal(L, v, false);

	return 1; 
}


//Takes prefix (string), width (number)
int function_NewSubnet(lua_State *L)
{
	int width;
	const char *prefix;

	int argc = lua_gettop(L);
	if (unlikely(argc != 2))
	{
		reporter->Error("Lua called newSubnet with incorrect number of arguments:  %d ; \
			expected 2", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}


	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newSubnet arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	
	prefix = luaL_checkstring(L, 1);

	if (unlikely(!lua_isnumber(L, 2)))
	{
		reporter->Error("Lua unable to resolve newSubnet arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	
	width = lua_tonumber(L, 2);
	if (unlikely(!width)) {
		reporter->Error("Lua unable to resolve newSubnet width argument");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	
	//TODO: check prefix and width validity:
	if (unlikely(width > 128)) {
		reporter->Error("Invalid width for IP addr in newSubnet: %d", width);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	

	Val *v = (Val *)(new SubNetVal(prefix, width));

	lua_mgr->PushLuaVal(L, v, false);

	return 1; 
}

int function_NewAddr(lua_State *L)
{
	const char *prefix;

	int argc = lua_gettop(L);
	if (unlikely(argc != 1))
	{
		reporter->Error("Lua called newAddr with incorrect number of arguments:  %d ; \
			expected 1", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Running newAddr");
#endif

	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newAddr arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	prefix = luaL_checkstring(L, 1);
	Val *v = (Val *)(new AddrVal(prefix));

	lua_mgr->PushLuaVal(L, v, false);

	return 1; 
}


int function_NewInterval(lua_State *L)
{
	double time;
	int argc = lua_gettop(L);
	if (unlikely(argc != 1))
	{
		reporter->Error("Lua called newInterval with incorrect number of arguments:  %d ; \
			expected 1", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}


	if (unlikely(!lua_isnumber(L, 1)))
	{
		reporter->Error("Lua unable to resolve newInterval arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	time = lua_tonumber(L, 1);
	Val *v = new Val(time, TYPE_INTERVAL);

	lua_mgr->PushLuaVal(L, v, false);

	return 1; 
}

//This creates a new, only-default-initialized recordval for an existing type
int function_NewRecord(lua_State *L)
{
	Val *v;
	const char *recordname;

	int argc = lua_gettop(L);
	if (unlikely(argc != 1))
	{
		reporter->Error("Lua called newRecord with incorrect number of arguments:  %d ; \
			expected 1", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newRecord arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	recordname = luaL_checkstring(L, 1);

	//look up global Record name, see if it exists and is a valid record TYPE

	ID *type_id = lookup_ID(extract_var_name(recordname).c_str(), \
		extract_module_name(recordname).c_str());

#ifdef LUA_DEBUG
	reporter->Info("Preventing optimization in new Record");
#endif

	if (unlikely(!type_id))
	{
		reporter->Error("Unable to find Bro record type by name %s", recordname);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Unref(type_id);

	BroType *idtype = (BroType *)type_id->AsType();

	if (unlikely(!idtype))
	{
		reporter->Error("%s exists, but is not a declared BroType", recordname);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(idtype->Tag() != TYPE_RECORD)) {
		reporter->Error("%s is not a record type", recordname);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Number of fields in new recordtype: %d", ((RecordType*)idtype)->NumFields());
#endif

	v = (Val *) new RecordVal(idtype->AsRecordType());

	if (unlikely(!v)) {
		reporter->Error("Unable to create new RecordVal for type: %s", recordname);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(lua_mgr->PushLuaVal(L, v, false) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push new RecordVal");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
#ifdef LUA_DEBUG
	reporter->Info("The new record type was pushed");
#endif

	return 1; 
}

int function_NewRecordType(lua_State *L)
{
	//declare new type
	//can only be global, no modules in lua
	//OR automatically assign everything in Lua to the Lua:: module
	//in the second case, everywhere we do a lookup we have to check appending Lua::
	//	if it fails (or first?)

	Val *v;
	const char *recordname;

	int argc = lua_gettop(L);
	if (unlikely((argc < 2) ))
	{
		reporter->Error("Lua called newRecordType with incorrect number of arguments:  %d ; \
			expected >1", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newRecordType arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	recordname = luaL_checkstring(L, 1);

	if (unlikely(!recordname)) {
		reporter->Error("Lua: unable to resolve first newRecordType argument as a string");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	// Do not throw error if it fails because the type is already declared, because
	//	of the possibility of dynamically loading the same script multiple times and 
	//	making live edits.
	ID *existing = lookup_ID(extract_var_name(recordname).c_str(), \
			extract_module_name(recordname).c_str(), false, true);
	
	if (unlikely(existing)) {
		reporter->Info("Redefing existing type -- ignoring");
		return 0;
	}
	Unref(existing);

	//take variable number of fieldname, fieldtype pairs? if they want to default values, pass nil
	//what about attributes? reserved keywords? _log and _optional strings for now

	val_list *args = NULL;
	bool *userdata_args;

	args = new val_list(argc-1);
	userdata_args = new bool[argc-1];

	if (unlikely(populate_list(L, 2, argc-1, args, userdata_args) != LUA_SUCCESS))
	{
		reporter->Error("Error populating argument list for new record type");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	type_decl_list *type_list = new type_decl_list();

	attr_list *attrs = NULL;

	bool failed = ParseRecordArgs(L, type_list, args, argc-1, attrs);

	if (likely(!failed))
	{
		RecordType *idtype = new RecordType(type_list);

		
		//TODO: may change is_global (currently false in install_ID) -- does this require a 
		// module name is given?
		// May also choose not to export it
		ID *newrec = install_ID(extract_var_name(recordname).c_str(), \
			extract_module_name(recordname).c_str(), false, true);

		// this appears to be the preferred way to initialize a type in parse.y
		add_type(newrec, idtype, attrs);

		broxygen_mgr->Identifier(newrec);

	}

	//TODO
	/*
	loop_over_list(*args, l)
	{
		Unref((*args)[l]);
	}
	delete args;
	delete userdata_args;
	*/

	/* // this is now owned by the new type ID
	loop_over_list(*type_list, m)
	{
		delete (*type_list)[m];
	}
	delete type_list;
	*/

	return (failed ? LUA_FAILURE : 0);
}

//TODO, to set attr's, use normal setter on record and __log or something? Or have custom 
//	BIF for that?
//TODO: This works for all the wrong reasons
//TODO: Stop memory leaks

//Specialized function for logs that takes $path, $columns, and $ev (optional), in that order
//Returns a Bro record with the appropriate values?
int function_NewLogRecord(lua_State *L)
{
	//creates new recordtype (only locally) to be used to create RecordVal
	//manually assign fields -- TODO: unless there is an existing type

	//Note: this would be used as follows: bro.call("Log::create_stream", bro.lookup("LOG::SMB"),
	//	bro.newRecord("smb_auth", smb_state, "event_name"))

	RecordVal *v;
	const char *event;

	int argc = lua_gettop(L);
	if (unlikely((argc < 2) || (argc > 3)))
	{
		reporter->Error("Lua called newLogRecord with incorrect number of arguments:  %d ; \
			expected 2-3", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Lua unable to resolve newLogRecord arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	val_list *args = NULL;
	bool *userdata_args;

	args = new val_list(argc);

	userdata_args = new bool[argc];

	if (unlikely(populate_list(L, 1, argc, args, userdata_args) != LUA_SUCCESS))
	{
		reporter->Error("Error populating argument list for new record type");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Populated list for function_NewLogRecord");
#endif

	if (unlikely( (((*args)[1])->Type()->Tag() != TYPE_STRING) && (((*args)[1])->Type()->Tag() \
		!= TYPE_RECORD) ))
	{
		reporter->Error("Expecting all string arguments, or record for $columns");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	else if (unlikely((argc == 3) && (((*args)[2])->Type()->Tag() != TYPE_STRING)))
	{
		reporter->Error("Expecting all string arguments");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	RecordType *idtype;
	type_decl_list *decls;
	BroType *log_path;
	BroType *log_columns;

	TypeDecl *type_path;
	TypeDecl *type_columns;

	BroType *log_event;
	TypeDecl *type_event;

	attr_list *attrs = NULL;
	Attr *attr_entry = NULL;

	RecordVal *info = NULL;

	bool delete_info = false;
	if (((*args)[1])->Type()->Tag() == TYPE_STRING)
	{
		idtype = internal_type(((*args)[1])->CoerceToCString())->AsRecordType();
		if (!idtype)
		{
			reporter->Error("Could not find record type for function_NewLogRecord");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}

		// Yes, this is a real line of code in the Bro source, and it's not uncommon:
		//RecordType* columns = sval->Lookup("columns")
		//	->AsType()->AsTypeType()->Type()->AsRecordType();

		info = new RecordVal(idtype);
		delete_info = true;
	}
	else if (((*args)[1])->Type()->Tag() == TYPE_RECORD)
	{
		info = ((*args)[1])->AsRecordVal();
	}
	else {
		reporter->Error("Expecting string or record for first arg in function_NewLogRecord");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	/*
	//decls = new type_decl_list();

	log_path = new BroType(TYPE_ENUM);
	log_columns = new BroType(TYPE_RECORD);

	type_path = new TypeDecl(log_path, "path");
	type_columns = new TypeDecl(log_columns, "columns");

	//Maintaining 'standard' order
	decls->append(type_columns);

	if (argc == 3)
	{
		log_event = new BroType(TYPE_FUNC);
		type_event = new TypeDecl(log_event, "event");
		decls->append(type_event);
	}
	decls->append(type_path);

	//TODO: memory leaks everywhere
	idtype = new RecordType(decls);
	*/
	
	//For now, make it out of this existing type: BifType::Record::Log::Stream
	//The home-made type is not checking out. This limits us to one column at a time
	idtype = internal_type("Log::Stream")->AsRecordType();
	if (unlikely(!idtype))
	{
		reporter->Error("Could not find Log::Stream id in function_NewLogRecord");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}
	

	v = new RecordVal(idtype);

	//TODO: this will be a field of a userdata wrapped Val -- should its userdata Unref it?? 
	//^This is a more general issue of knowing whether sub-objects need to be unreffed, because
	// in this example, there is nowhere else to Unref it
	Val *typeofrecord = new Val(info->LuaRecordType(), true);

	v->Assign(idtype->FieldOffset("path"), ((*args)[0]));
	v->Assign(idtype->FieldOffset("columns"), typeofrecord);

	if (argc == 3)
	{
		v->Assign(idtype->FieldOffset("ev"), ((*args)[2]));
	}

	if (unlikely(lua_mgr->PushLuaVal(L, ((Val *)v)) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push new Log record");
		LuajitManager::SetFaultyScript(L);
		loop_over_list(*args, l)
		{
			if (!userdata_args[l]) {
				Unref((*args)[l]);
			}
		}
		/*
		delete args;
		delete userdata_args;
		delete idtype;
		delete log_path;
		delete type_path;
		delete log_columns;
		delete type_columns;
		if (argc == 3)
		{
			delete log_event;
			delete type_event;
		}
		//TODO: loop over decls? 
		delete decls;
		if (delete_info)
			delete info;
		*/
		Unref(v);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Pushed new log record");
#endif
	
	//Note: do not free the actual Val memory yet

	//TODO: When are these freed then?
	delete args;
	delete[] userdata_args;
	//delete idtype;
	//delete log_path;
	//delete type_path;
	//delete log_columns;
	//delete type_columns;
	//TODO: loop over decls? 
	// delete decls;
	//Push record
	//if (delete_info)
	//	delete info;
	
	return 1; 
}

//Takes in a variable number of set members, which should be unique (although convertToSet 
//	probably deletes extras)
int function_NewSet(lua_State *L)
{
	// Creates a userdata set from variable arguments of the same type (not necessarily all 
	//	userdata, if a non userdata can be forced to a type), or error

	// Note: always interpret numbers as doubles? and always default the total list type to 
	//	that of the first userdata. This can cause issues if we pass to a BIF expecting a 
	//	different type... hence the AddNumber override

	//take variable list, add to ListType, convert to set, done
	int argc = lua_gettop(L);
	val_list *args = NULL;
	bool *userdata_args;

	if (unlikely(argc < 1))
	{
		reporter->Error("Lua newSet requires at least one argument");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Running newSet");
#endif

	bool type_as_string = false;
	const char *typestring = NULL;

	//Note: First argument is used to determine the type of the Set as a string, if it's a string
	if ((lua_type(L, 1) == LUA_TSTRING))
	{
		typestring = luaL_checkstring(L, 1);
		type_as_string = true;
	}

	argc = argc - (type_as_string ? 1 : 0);
	args = new val_list(argc);
	userdata_args = new bool[argc];

	// TODO: support coercing number types to TYPE_DOUBLE
	if (argc > 1 || !type_as_string)
	{
		if (unlikely(populate_list(L, (type_as_string ? 2 : 1), argc, args, userdata_args) != \
			LUA_SUCCESS))
		{
			reporter->Error("Error populating argument list for new record type");
			delete args;
			delete[] userdata_args;
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}

	BroType *basetype;
	bool type_alloced = false;
	SetType *type;

	//Now determine type based on first argument
	if (type_as_string)
	{
		//lookup typename
		int rawtype = StringToTypeTag(typestring);
		if (rawtype)
		{
			basetype = new BroType((TypeTag)rawtype, true);
			type_alloced = true;
		}
		else
		{
			ID *type_id = lookup_ID(extract_var_name(typestring).c_str(), \
				extract_module_name(typestring).c_str());

			if (!type_id)
			{
				delete args;
				delete[] userdata_args;
				reporter->Error("Unable to look up newSet arguments");
				LuajitManager::SetFaultyScript(L);
				return LUA_FAILURE;
			}
			else
			{
				basetype = type_id->AsType();
				Unref(type_id);
			}

		}
	}
	else
	{
		basetype = ((*args)[0])->Type();
	}

	//Now check that all args are of the base type
	loop_over_list(*args, k)
	{
		if ((((*args)[k])->Type()->Tag() != basetype->Tag()) || \
			(((*args)[k])->Type()->GetName() != basetype->GetName()))
		{
			delete args;
			delete[] userdata_args;
			if (type_alloced)
				delete basetype;
			//Error
			reporter->Error("Type mismatch is newSet arguments");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}


	//If that all checks out, create a new set and add the arguments ConvertToSet
	//Note: again, only supporting one type, not a list of types for the index type
	//We would have to further limit syntax to do that.

	TypeList *tlist = new TypeList(basetype);
	//TODO: need to confirm this Ref is needed
	Ref(basetype);
	tlist->Append(basetype);

	type = new SetType(tlist, 0);

	TableVal* t = new TableVal(type->AsTableType());

	int retval = 1;

	if (unlikely(lua_mgr->PushLuaVal(L, ((Val *)t)) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push new set");
		LuajitManager::SetFaultyScript(L);
		Unref(t);
		retval = LUA_FAILURE;
	}

	loop_over_list(*args, l)
	{
		if (!userdata_args[l]) {
			Unref((*args)[l]);
		}
	}

	delete args;
	delete[] userdata_args;
	//if (type_alloced)
		//delete basetype;
	//delete type;

	return retval; 
}


int function_NewTable(lua_State *L)
{
	//New table takes index type (string) (or sample index) and value type (string) (or sample 
	//	value). As of now does not support multidimensional types for value type, or a list of 
	//	types for index
	int argc = lua_gettop(L);
	if (unlikely(argc != 2))
	{
		reporter->Warning("Lua called newTable takes only one argument (type string or a \
			variable of the desired type (not added to table). Received: %d. Proceeding.", argc);
	}

	Val *table = NULL;
	Val *index = NULL;
	bool userdata_index = false;
	const char *indextype = NULL;
	Val *value = NULL;
	bool userdata_value = false;
	const char *valuetype = NULL;

	if (lua_type(L, 1) == LUA_TSTRING)
	{
		indextype = luaL_checkstring(L, 1);
	}
	else
	{
		index = lua_mgr->PullLuaValFromGenericArg(L, 1, &userdata_index);
		if (unlikely(!index))
		{
			reporter->Error("In newTable() -- not a valid userdata");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}

	if (lua_type(L, 2) == LUA_TSTRING)
	{
		valuetype = luaL_checkstring(L, 2);
	}
	else
	{
		value = lua_mgr->PullLuaValFromGenericArg(L, 2, &userdata_value);
		if (unlikely(!value))
		{
			reporter->Error("In newTable() -- not a valid userdata");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}


	TableType *type;

	BroType *ytype;
	BroType *itype;
	
	if (index)
	{
		itype = index->Type();
	}
	else
	{
		//if string, lookup type
		ID *type_id = lookup_ID(extract_var_name(indextype).c_str(), \
			extract_module_name(indextype).c_str());

		if (unlikely(!type_id))
		{
			//Try basic types:
			int type = StringToTypeTag(indextype);
			if (likely(type > 0))
			{
				itype = new BroType((TypeTag)type);
			}
			else
			{
#ifdef LUA_DEBUG
				reporter->Info("Assuming type string for new TableVal index");
#endif
				itype = new BroType(TYPE_STRING);
			}
		}
		else
		{
			itype = type_id->AsType();
			Unref(type_id);
		}
	}

	if (value)
	{
		ytype = value->Type();
	}
	else
	{
		//if string, lookup type
		ID *type_id = lookup_ID(extract_var_name(valuetype).c_str(), \
			extract_module_name(valuetype).c_str());

		if (unlikely(!type_id))
		{
			//Try basic types:
			int type = StringToTypeTag(valuetype);
			if (likely(type > 0))
			{
				ytype = new BroType((TypeTag)type);
			}
			else
			{
#ifdef LUA_DEBUG
				reporter->Info("Assuming type string for new TableVal yield");
#endif
				ytype = new BroType(TYPE_STRING);
			}
		}
		else
		{
			ytype = type_id->AsType();
			Unref(type_id);
		}
		
	}

	//TODO: Or use TYPE_ANY for table index for flexibility?
	TypeList *tl = new TypeList();
	tl->Append(itype);
	type = new TableType(tl, ytype);

	table = (Val *) new TableVal(type);
	
	if (unlikely(lua_mgr->PushLuaVal(L, table) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push new tableval");
		LuajitManager::SetFaultyScript(L);
		Unref(table);
		return LUA_FAILURE;
	}

	return 1; 
}


int function_NewList(lua_State *L)
{
	//TODO ? I guess lists are internal types only so I can delete this
	return 0;
}

//Just populate with arguments directly, not type
int function_NewVector(lua_State *L)
{
	int argc = lua_gettop(L);
	if (unlikely(argc < 1))
	{
		reporter->Error("Lua called newVector requires at least 1 argument, only \
			received: %d", argc);
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	Val *retval;

	val_list *args = NULL;
	bool *userdata_args;


	args = new val_list(argc);

	userdata_args = new bool[argc];

	//TODO: Assume double?
	if (unlikely(populate_list(L, 1, argc, args, userdata_args, TYPE_DOUBLE) != LUA_SUCCESS))
	{
		reporter->Error("Error populating argument list for new vector");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	//TODO: How to support complex types. It will definitely require that one of the args is 
	//	a userdata which already has that type for this application. Do Vectors even support 
	//	infinite type complexity with VectorType? Should we limit to simple element types? TODO
	//TODO: Can we create a string like "Table of counts" and resolve it to a BroType via 
	//	lookup? unlikely
	VectorType *vectype = NULL;
	loop_over_list(*args, i)
	{
		if (userdata_args[i-1])
		{
			if (vectype && (vectype->YieldType() != ((*args)[i])->Type()))
			{
				char s1[100];
				char s2[100];
				TypeTagToString(vectype->YieldType()->Tag(), s1);
				TypeTagToString(((*args)[i])->Type()->Tag(), s2);

				reporter->Error("Inconsistent userdatum types in newVector:  yield  %s  and \
					type %d  %s", s1, i, s2);
				LuajitManager::SetFaultyScript(L);
				return LUA_FAILURE;
			}
			vectype = new VectorType( ((*args)[i])->Type() );
		}
	}

	if (!vectype)
	{
		//now we need to figure out the type of the first item and make sure everything else 
		//	matches
		vectype = new VectorType( ((*args)[0])->Type() );
	}

	loop_over_list(*args, j)
	{
		//TODO: change condition / need better comparisons to identify empty strings 
		//	(which currently do not compare as equal)
		if ((((*args)[j])->Type()->Tag() != vectype->Tag()) && \
			((vectype->YieldType()->GetName() != ((*args)[j])->Type()->GetName())))
		{
			char s1[100];
			char s2[100];
			TypeTagToString(vectype->YieldType()->Tag(), s1);
			TypeTagToString(((*args)[j])->Type()->Tag(), s2);

			reporter->Error("Inconsistent non-userdatum types in newVector; base type: %s / %s \
				compared type: %s / %s", s1, vectype->YieldType()->GetName().c_str(), \
				s2, ((*args)[j])->Type()->GetName().c_str());
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}

	retval = (Val *) new VectorVal(vectype);
	if (unlikely(!retval))
	{
		reporter->FatalError("Unable to allocate vectorval");
		return LUA_FAILURE;
	}

	loop_over_list(*args, k)
	{
#ifdef DEBUG_LUA
		reporter->Info("New vector starting index is %d", k);
#endif
		if (!(((VectorVal *)retval)->Assign(k, (*args)[k])))
		{
			reporter->Error("Unable to assign Val to Vector in newVector");
			LuajitManager::SetFaultyScript(L);
			return LUA_FAILURE;
		}
	}

	if (unlikely(lua_mgr->PushLuaVal(L, retval) != LUA_SUCCESS))
	{
		reporter->Error("Unable to push new vectorval");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	if (argc > 0)
	{
		loop_over_list(*args, l)
		{
			if (!userdata_args[l]) {
				Unref((*args)[l]);
			}
		}
		delete args;
		delete[] userdata_args;
	}
	Unref(retval);
	Unref(vectype);
	return 1; 
}



/* Generic BIF's */


//Function / preprocessor that creates, wraps, and declares all existing BIF's (non-events) such 
//	that they can be accessed by Lua
int function_CallAnyBif(lua_State *L)
{
	int args_stack = lua_gettop(L);
#ifdef LUA_DEBUG
	reporter->Info("Calling BIF with %d args on stack", args_stack);
#endif

	if (unlikely(args_stack < 1))
	{
		reporter->Error("Insufficient arguments for call(): %d", args_stack);
		return LUA_FAILURE;
	}

	const char *bif_name;
	if (unlikely(lua_type(L, 1) != LUA_TSTRING))
	{
		reporter->Error("Expecting string for first argument of function_CallAnyBif");
		LuajitManager::SetFaultyScript(L);
		return LUA_FAILURE;
	}

	bif_name = luaL_checkstring(L, 1);

	int argc = 0;
	int retc = 0;
	Val *retval;

	val_list *args = NULL;
	bool *userdata_args;

	argc = args_stack-1;
	args = new val_list(argc);

	userdata_args = new bool[argc];

#ifdef LUA_DEBUG
	reporter->Info("Num args on stack: %d  for BIF: %s", args_stack, bif_name);
#endif

	if (unlikely(populate_list(L, 2, argc, args, userdata_args) != LUA_SUCCESS))
	{
		reporter->Error("Error populating val_list for BIF: %s", bif_name);
		LuajitManager::SetFaultyScript(L);
		if (argc > 0) {
			delete args;
			delete userdata_args;
		}
		return LUA_FAILURE;
	}
	
#ifdef LUA_DEBUG
	reporter->Info("Looking up BiF: %s", bif_name);
#endif
	//Generic BIF lookup

	ID* id = lookup_ID(bif_name, GLOBAL_MODULE_NAME);
	if (unlikely(!id))
	{
		reporter->Error("Invalid Bif name:  %s", bif_name);
		LuajitManager::SetFaultyScript(L);
		delete args;
		delete userdata_args;
		return LUA_FAILURE;
	}
	Unref(id);

	if (unlikely(!ValidateArgs(bif_name, false, args))) {
		reporter->Error("Invalid args for bif: %s", bif_name);
		LuajitManager::SetFaultyScript(L);
		delete args;
		delete[] userdata_args;
		return LUA_FAILURE;
	}

#ifdef LUA_DEBUG
	reporter->Info("Bif found, about to pass arguments");
#endif

	Func *bif = internal_func(bif_name);
	if (likely(bif))
	{

#ifdef LUA_DEBUG
		reporter->Info("bif->Name() = %s", bif->Name());
#endif // LUA_DEBUG

		if (bif->GetKind() == Func::BUILTIN_FUNC)
		{
			retval = ((BuiltinFunc*)bif)->LuaCall(args);
		}
		else
		{
			retval = ((BroFunc*)bif)->LuaCall(args);
		}
	}
	else
	{
		reporter->Error("Unable to obtain BroFunc for Bif  %s", bif_name);
		LuajitManager::SetFaultyScript(L);
		if (argc > 0) {
			delete args;
			delete userdata_args;
		}
		return LUA_FAILURE;
	}

	if (retval)
	{
		if (lua_mgr->PushLuaVal(L, retval) != LUA_SUCCESS)
		{
			reporter->Error("Unable to push retval in Bif  %s", bif_name);
			LuajitManager::SetFaultyScript(L);
			if (argc > 0) {
				delete args;
				delete userdata_args;
			}
			return LUA_FAILURE;
		}
		Unref(retval);
		retc = 1;
	}
	else
	{
		retc = 0;
		//Most BIF's should return a Val, but not all (like NOTICE)
#ifdef LUA_DEBUG
		reporter->Info("No return value detected from BIF  %s", bif_name);
#endif
	}

	//TODO: Can we assume that full ownership of Vals has been given to a BIF?
	if (argc > 0) {
		delete args;
		delete userdata_args;
	}

	return retc;
}

//Used solely for internal Bro behavior debugging in a controlled environment
int function_doTests(lua_State *L)
{
#ifdef LUA_DEBUG
	bool skip = true;
	if (skip) {
		return 0;
	}

	reporter->Info("Size of a Bro count in memory: %d bytes. Sad!", (int)sizeof(Val));
	reporter->Info("Size of an empty Bro string in memory: %d bytes. Sad!", (int)sizeof(StringVal));

	/*
	Val *v;
	const char *recordname;
	recordname = "lua_rec";

	type_decl_list *type_list = new type_decl_list();

	attr_list *attrs = NULL;
	Attr *attr_entry = NULL;
	BroType *typedecl_type = NULL;

	attr_entry = new Attr(ATTR_OPTIONAL);
	attrs = new attr_list();
	attrs->append(attr_entry);


	typedecl_type = new BroType(TYPE_STRING, false);
	TypeDecl *newtype = new TypeDecl(typedecl_type, "Lua_field", attrs, true);
	type_list->append(newtype);

	attr_entry = new Attr(ATTR_OPTIONAL);
	attrs = new attr_list();
	attrs->append(attr_entry);

	typedecl_type = new BroType(TYPE_COUNT, false);
	TypeDecl *newtype2 = new TypeDecl(typedecl_type, "Lua_field2", attrs, true);
	type_list->append(newtype2);

	attr_entry = new Attr(ATTR_OPTIONAL);
	attrs = new attr_list();
	attrs->append(attr_entry);

	typedecl_type = new BroType(TYPE_ADDR, false);
	TypeDecl *newtype3 = new TypeDecl(typedecl_type, "Lua_addr", attrs, true);
	type_list->append(newtype3);


	RecordType *idtype = new RecordType(type_list);

	//TODO: may change is_global -- does this require a module name is given?
	//May also choose not to export it
	ID *newrec = install_ID(extract_var_name(recordname).c_str(), \
		extract_module_name(recordname).c_str(), false, true);
	newrec->MakeType();
	newrec->SetType(idtype);

	RecordVal *rv = new RecordVal(internal_type("lua_rec")->AsRecordType());
	rv->Assign(1, new Val(5, TYPE_COUNT));

	val_list *both = new val_list(1);
	both->append((Val*)rv);

	BroFile* f;
	int offset = 0;

	f = new BroFile(stdout);

	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;
	ODesc d(DESC_READABLE);
	d.SetFlush(0);
	d.SetStyle(style);

	if ( f->IsRawOutput() )
	{
		ODesc d(DESC_READABLE);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(both, &d, offset);
		f->Write(d.Description(), d.Len());
	}
	else
	{
		ODesc d(DESC_READABLE, f);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(both, &d, offset);
		f->Write("\n", 1);
	}

	delete f;

	Unref(rv);
	*/

	/*
	Val *base1 = new Val(11, TYPE_COUNT);
	Val *base2 = new Val(12, TYPE_COUNT);
	Val *base3 = new Val(13, TYPE_COUNT);
	Val *base4 = new Val(14, TYPE_COUNT);

	BroType *btype = new BroType(TYPE_COUNT);
	VectorType *vtype = new VectorType(btype);

	VectorVal *orig = new VectorVal(internal_type("index_vec")->AsVectorType());
	orig->Assign(4, base1);
	orig->Assign(1, base2);
	orig->Assign(2, base3);
	orig->Assign(3, base4);

	Val *copy = orig->Clone();

	val_list *both = new val_list(1);

	delete orig;

	both->append(copy);

	BroFile* f;
	int offset = 0;

	f = new BroFile(stdout);

	desc_style style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;
	ODesc d(DESC_READABLE);
	d.SetFlush(0);
	d.SetStyle(style);

	if ( f->IsRawOutput() )
	{
		ODesc d(DESC_READABLE);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(both, &d, offset);
		f->Write(d.Description(), d.Len());
	}
	else
	{
		ODesc d(DESC_READABLE, f);
		d.SetFlush(0);
		d.SetStyle(style);

		describe_vals(both, &d, offset);
		f->Write("\n", 1);
	}

	delete f;

	reporter->Info("Did internal test 1 successfully");

	Val *table = NULL;

	TableType *type;

	BroType *ytype;
	BroType *itype;

	itype = new BroType(TYPE_STRING);
	ytype = new BroType(TYPE_DOUBLE);

	//TODO: Or use TYPE_ANY for table index for flexibility?
	TypeList *tl = new TypeList();
	tl->Append(itype);
	type = new TableType(tl, ytype);

	table = (Val *) new TableVal(type);

	Val *clone = table->Clone();


	reporter->Info("Did internal test 2 successfully");

	*/
#endif
	return 0;
}



/* Meta-events for Val userdata */

static const struct luaL_reg vallib_events [] = {
	{"__index", LuajitManager::function_GetLuaVal},
	{"__newindex", LuajitManager::function_SetLuaVal},
	{"__tostring", LuajitManager::function_ValToString},
	{"__gc", LuajitManager::function_GarbageCollectVal},
	{"__metatable", LuajitManager::function_HideMetaTable},

	{"__call", LuajitManager::function_CallLuaVal},
	{"__add", LuajitManager::function_AddLuaVals},
	{"__concat", LuajitManager::function_ConcatLuaVals},
	{"__eq", LuajitManager::function_CompareEqLuaVal},

	//TODO: add __lt __le

	{NULL, NULL}
};


/* Normal methods for Val userdata */
static const struct luaL_reg vallib_methods [] = {
	{"asTable", LuajitManager::function_PushLuaTable},
	{"asCopy", LuajitManager::function_CopyLuaVal}, 
	{"copy", LuajitManager::function_CopyLuaVal}, 
	{"clone", LuajitManager::function_CopyLuaVal}, 
	{"tostring", LuajitManager::function_ValToString},
	{"add", LuajitManager::function_AddElementToLuaVal},
	{"remove", LuajitManager::function_RemoveFromLuaVal},

	// General Val
	{"broType", LuajitManager::function_GetBroType}, 
	{"asString", LuajitManager::function_ValToString}, 
	{"isVector", LuajitManager::function_IsVector},
	{"isRecord", LuajitManager::function_IsRecord},
	{"isTable", LuajitManager::function_IsTable},
	{"isSet", LuajitManager::function_IsSet},
	{"isPort", LuajitManager::function_IsPort},
	{"isAddr", LuajitManager::function_IsAddr},
	{"isSubnet", LuajitManager::function_IsSubnet},
	{"isInterval", LuajitManager::function_IsInterval},
	{"getSize", LuajitManager::function_Size},
	
	// Table/Set
	{"indices", LuajitManager::function_GetTableIndicesVector},
	{"elements", LuajitManager::function_GetSetElementsVector},

	// PortVal
	{"isTCP", LuajitManager::function_IsTCP}, 
	{"isUDP", LuajitManager::function_IsUDP}, 
	{"isICMP", LuajitManager::function_IsICMP}, 
	{"getPort", LuajitManager::function_PortNumber},

	//Addr, use asString/tostring
	{"version", LuajitManager::function_IPVersion},
	{"asBytes", LuajitManager::function_IPByteArray},

	//SubnetVal
	//subnet contains an IP address arg, this also is used for Sets
	{"contains", LuajitManager::function_ValContains}, 
	{"getMask", LuajitManager::function_SubnetMask}, //subnet mask
	{"getWidth", LuajitManager::function_SubnetMaskWidth},
	{"getPrefix", LuajitManager::function_SubnetPrefix},

	//Pattern
	//Note: Expected this will not be used due to better Lua libraries / PCRE.
	//	Included for compatibility
	{"addPattern", LuajitManager::function_AddPattern},
	{"searchPattern", LuajitManager::function_SearchPattern},

	//Enum, Port, Interval, Time
	{"asNumber", LuajitManager::function_ToNumber}, //can also use this for port, interval, time

	//TYPE_FILE: 
	//TODO: Add capability to actually open the file, update documentation
	// Actually, why not just do this with Lua. Lua can handle files by itself?
	// Only advantage is being able to pass file descriptors from Bro script to Lua 
	// and vice versa, which seems unnecessary
	{"isOpen", LuajitManager::function_FileIsOpen},
	{"write", LuajitManager::function_WriteFile},
	{"close", LuajitManager::function_CloseFile},
	{"describe", LuajitManager::function_ValToString},
	
	{NULL, NULL}
};


/* Static library functions */
static const struct luaL_reg vallib_functions [] = {
	{"call", function_CallAnyBif},
	{"print", function_BroPrintVals},
	{"lookup", function_LookupBroVal},
	{"event", function_GenerateEvent},
	{"redefRecord", function_RedefRecord},
	{"redefEnum", function_RedefEnum},

	{"newPort", function_NewPort},
	{"newSubnet", function_NewSubnet},
	{"newAddr", function_NewAddr},
	{"newInterval", function_NewInterval},
	{"newRecord", function_NewRecord},
	{"newLog", function_NewLogRecord},
	{"newRecordType", function_NewRecordType},
	{"newSet", function_NewSet},
	{"newTable", function_NewTable}, 
	{"newList", function_NewList},
	{"newVector", function_NewVector},

	{"internalTests", function_doTests},

	{NULL, NULL}
};



int luaopen_bro(lua_State *L)
{
	
	luaL_newmetatable(L, "bro.val");

	luaL_register(L, NULL, vallib_events);
	luaL_register(L, NULL, vallib_methods);
	lua_pop(L, 1);

    luaL_register(L, "bro", vallib_functions);

	return 0;
}


int lua_reg_bro_libs(lua_State *L) 
{
	return luaopen_bro(L);
}





/* Auxiliary functions */

//Populates a val list with BIF arguments
int populate_list(lua_State *L, int start_index, int num_args, val_list *vl, \
	bool *userdata, TypeTag desired_type)
{
	//check correct number of args on stack

#ifdef LUA_DEBUG
	reporter->Info("Start index: %d\nNum args: %d", start_index, num_args);
#endif

	int i;
	for (i=start_index; i < start_index + num_args; i++)
	{
		userdata[i-1] = false;
#ifdef LUA_DEBUG
		reporter->Info("Pulling Val args for a Bro-BIF or Lua-BIF, at index: %d", i);
#endif
		Val *v; 
		if (desired_type != TYPE_VOID)
		{
			v = lua_mgr->PullLuaValFromGenericArg(L, i, &userdata[i-1], desired_type);
		}
		else
		{
			v = lua_mgr->PullLuaValFromGenericArg(L, i, &userdata[i-1]);
		}

		if (unlikely(!v))
		{
			if (!userdata[i-1])
			{
				//This is an intentional nil value, let's create a boolean here
				//bool_index = lua_toboolean(L, index);
				v = new Val( 0, TYPE_BOOL);
				vl->append(v);
				continue;
			}
			while(i > 0) {
				i--;
				Unref((*vl)[i]);
			}
			delete vl;

			reporter->Error("Could not call BIF, args could not be resolved as Vals");
			return LUA_FAILURE;
		}
#ifdef LUA_DEBUG
		reporter->Info("Pulling Val args for a bif, at index: %d", i);
#endif
		vl->append(v);
#ifdef LUA_DEBUG
		reporter->Info("Pulling Val args for a bif, index: %d appended", i);
#endif
	}

	return LUA_SUCCESS;
}

bool ParseRecordArgs(lua_State *L, type_decl_list *type_list, val_list *args, int argc, \
	attr_list *attrs)
{
	ParseState state = STATE_NAME;
	int attr_count = 0; //we only support a max of 2, so quit there

	TypeDecl *newtype;

	BroType *typedecl_type = NULL;
	const char *id = NULL;
	Attr *attr_entry = NULL;
	bool first = true;
	int tag = 0;

	bool failed = false;

	loop_over_list(*args, k)
	{
		if (unlikely(((*args)[k])->Type()->Tag() != TYPE_STRING))
		{
			reporter->Error("Must only pass in strings representing fieldname, fieldtype, attrs \
				to Redef Record. Assign to fields separately");
			LuajitManager::SetFaultyScript(L);
			failed = true;
			if (attrs)
				delete attrs;
			if (typedecl_type)
				delete typedecl_type;
			return failed;
		}
		switch (state)
		{
			case STATE_NAME:
#ifdef LUA_DEBUG
				reporter->Info("STATE_NAME: %s\t\targ: %d", ((*args)[k])->CoerceToCString(), k);
#endif
				if (!first)
				{
#ifdef LUA_DEBUG
					reporter->Info("attr_list length: %d", attrs ? attrs->length() : -1 );
#endif
					newtype = new TypeDecl(typedecl_type, id, attrs, true);
					type_list->append(newtype);
					//delete attrs; //new typedecl deletes it
					//delete typedecl_type; 
					//TODO: ^this is owned by new typedecl? what about attrs?
					typedecl_type = NULL;
				}
				first = false;
				typedecl_type = NULL;
				id = NULL;
				attrs = new attr_list();
				attr_count = 0;
				attr_entry = new Attr(ATTR_OPTIONAL);
				attrs->append(attr_entry);
				attr_count++;

				//check for name string which is not an attribute
				id = ((*args)[k])->CoerceToCString();
				
				state = STATE_TYPE;
				break;
			case STATE_TYPE:
#ifdef LUA_DEBUG
				reporter->Info("STATE_TYPE: %s\t\targ: %d", ((*args)[k])->CoerceToCString(), k);
#endif
				tag = StringToTypeTag(((*args)[k])->CoerceToCString());
				if (unlikely(!tag))
				{
					//TODO: (verify) 
					//now check brotype:
					ID *record = lookup_ID(extract_var_name(((*args)[k])->CoerceToCString()).c_str(), \
						extract_module_name(((*args)[k])->CoerceToCString()).c_str());
					if (!record)
					{
						reporter->Error("Bad string interpreted as type: %s", \
							((*args)[k])->CoerceToCString());
						LuajitManager::SetFaultyScript(L);
						failed = true;
						break;
					} 
					else {
						typedecl_type = record->Type()->Ref(); //TODO: is the Ref necessary?
#ifdef LUA_DEBUG
						reporter->Info("STATE_TYPE: \t\t using bro type: %s", typedecl_type->GetName().c_str());
#endif
						Unref(record);
					}
				}
				else {
					typedecl_type = new BroType((TypeTag)tag, false);
				}
				
				state = STATE_ATTRS;
				break;
			case STATE_ATTRS:
#ifdef LUA_DEBUG
				reporter->Info("STATE_ATTRS: %s\t\targ: %d", ((*args)[k])->CoerceToCString(), k);
#endif
				//check for attribute, if not found, treat as state_name
				//next state is state_type if not found, state_attr if found
				//maximum 2
				if (strcmp(((*args)[k])->CoerceToCString(), "log") == 0)
				{
					//create new attr, add to attr_list, increment attrs

					//TODO: CheckAttrs() -- you can't &log a Record for example
					attr_entry = new Attr(ATTR_LOG);
					attrs->append(attr_entry);
					attr_count++;
					if (attr_count >= 2)
					{
						state = STATE_NAME;
					}
#ifdef LUA_DEBUG
					reporter->Info("Found log attribute");
#endif
				}
				else
				{
					state = STATE_NAME;

					//newtype = new TypeDecl(typedecl_type, id, attrs, true);
					first = false;
					//typedecl_type = NULL;
					//id = NULL;
					//attrs = NULL;

					//check for name string which is not an attribute
					id = ((*args)[k])->CoerceToCString();
					
#ifdef LUA_DEBUG
					reporter->Info("Not an attribute, checking next name");
#endif				
				}

				break;
		}
	}
	if ((argc > 1) && (state != STATE_TYPE))
	{
		const char *state_string = "STATE_ATTRS";
		if (state == STATE_NAME)
		{
			state_string = "STATE_NAME";
		}

#ifdef LUA_DEBUG
		reporter->Info("Appending final typedecl, state was: %s", state_string);
		reporter->Info("attr_list length: %d", attrs ? attrs->length() : -1 );
#endif
		newtype = new TypeDecl(typedecl_type, id, attrs, true);
		type_list->append(newtype);
		/*if (attrs)
			delete attrs;
		if (typedecl_type)
			delete typedecl_type;*/ //TODO: this is owned by new typedecl?
		typedecl_type = NULL;

	}
	else if (state == STATE_TYPE)
	{
		failed = true;
		if (attrs)
			delete attrs;
		if (typedecl_type)
			delete typedecl_type;
		reporter->Error("Illegal arguments for redefRecord");
		LuajitManager::SetFaultyScript(L);
	}

	return failed;
}


const char * TransportProtoToString(TransportProto type)
{
	if (type == TRANSPORT_TCP)
		return "TCP";
	else if (type == TRANSPORT_UDP)
		return "UDP";
	else if (type == TRANSPORT_ICMP)
		return "ICMP";
	else
		return "UNKNOWN";
}

TransportProto StringToTransportProto(const char *type)
{
	if (strcmp(type, "TCP") == 0)
		return TRANSPORT_TCP;
	else if (strcmp(type, "UDP") == 0)
		return TRANSPORT_UDP;
	else if (strcmp(type, "ICMP") == 0)
		return TRANSPORT_ICMP;
	else
		return TRANSPORT_UNKNOWN;
}

int TypeTagToString(TypeTag tag, char *typestring)
{
	if (unlikely((tag < TYPE_VOID) || (tag > TYPE_ERROR)))
	{
		reporter->Error("Bad TypeTag in TypeTagToString: %d", (int) tag);
		return LUA_FAILURE;
	}

	if (likely(typestring))
	{
		const char *name = type_name(tag);
		
		if (unlikely(strlen(name) > 32)) {
			reporter->Error("Bad string from type_name: %s", name);
			return LUA_FAILURE;
		}

		snprintf(typestring, 32, name);
	}
	else
	{
		reporter->Error("Bad string in TypeTagToString");
		return LUA_FAILURE;
	}
	return LUA_SUCCESS;
}


int StringToTypeTag(const char *typestring, bool suppress_errors)
{
	if (strcmp(typestring, "bool") == 0)
	{
		return TYPE_BOOL;
	}
	else if (strcmp(typestring, "int") == 0)
	{
		return TYPE_INT;
	}
	else if (strcmp(typestring, "count") == 0)
	{
		return TYPE_COUNT;
	}
	else if (strcmp(typestring, "double") == 0)
	{
		return TYPE_DOUBLE;
	}
	else if (strcmp(typestring, "string") == 0)
	{
		return TYPE_STRING;
	}
	else if (strcmp(typestring, "port") == 0)
	{
		return TYPE_PORT;
	}
	else if (strcmp(typestring, "addr") == 0)
	{
		return TYPE_ADDR;
	}
	else if (strcmp(typestring, "subnet") == 0)
	{
		return TYPE_SUBNET;
	}
	else if (strcmp(typestring, "any") == 0)
	{
		return TYPE_ANY;
	}
	else if ((strcmp(typestring, "table") == 0) || (strcmp(typestring, "set") == 0))
	{
		return TYPE_TABLE;
	}
	else if (strcmp(typestring, "record") == 0)
	{
		return TYPE_RECORD;
	}
	else if (strcmp(typestring, "vector") == 0)
	{
		return TYPE_VECTOR;
	}
	else if (strcmp(typestring, "time") == 0)
	{
		return TYPE_TIME;
	}
	else if (strcmp(typestring, "interval") == 0)
	{
		return TYPE_INTERVAL;
	}
	else if (strcmp(typestring, "pattern") == 0)
	{
		return TYPE_PATTERN;
	}
	else if (strcmp(typestring, "enum") == 0)
	{
		return TYPE_ENUM;
	}
	else if (strcmp(typestring, "counter") == 0)
	{
		return TYPE_COUNTER;
	}
	else if (strcmp(typestring, "timer") == 0)
	{
		return TYPE_FILE;
	}
	else if (strcmp(typestring, "union") == 0)
	{
		return TYPE_UNION;
	}
	else if (strcmp(typestring, "file") == 0)
	{
		return TYPE_FILE;
	}
	else if (strcmp(typestring, "types") == 0)
	{
		return TYPE_LIST;
	}
	else if (strcmp(typestring, "func") == 0)
	{
		return TYPE_FUNC;
	}
	else if (strcmp(typestring, "opaque") == 0)
	{
		return TYPE_OPAQUE;
	}
	else if (strcmp(typestring, "type") == 0)
	{
		return TYPE_TYPE;
	}
	else if (strcmp(typestring, "error") == 0)
	{
		return TYPE_ERROR;
	}
	else
	{
		//check defined types:
		ID *type_id = lookup_ID(extract_var_name(typestring).c_str(), \
		extract_module_name(typestring).c_str());

		if (unlikely(!type_id))
		{
			if (!suppress_errors) {
				reporter->Error("Unknown type_id in StringToTypeTag: %s", typestring);
			}
			return 0;
		}

		Unref(type_id);

		BroType *idtype = (BroType *)type_id->AsType();
		if (likely(idtype)) {
			return idtype->Tag();
		}
	}
	
	if (!suppress_errors) {
		reporter->Error("Unknown type in StringToTypeTag: %s", typestring);
	}
	return 0;
}

bool IsValidComparison(Val *v1, Val *v2)
{
	bool swap_ops = false;
	if ( v2->Type()->Tag() == TYPE_PATTERN )
		swap_ops = true;

	else if ( v1->Type()->Tag() == TYPE_PATTERN )
		;

	TypeTag bt1 = v1->Type()->Tag();
	if ( IsVector(bt1) )
		bt1 = v1->Type()->AsVectorType()->YieldType()->Tag();

	TypeTag bt2 = v2->Type()->Tag();
	if ( IsVector(bt2) )
		bt2 = v2->Type()->AsVectorType()->YieldType()->Tag();

	/*
	if ( is_vector(v1) || is_vector(v2) )
		SetType(new VectorType(base_type(TYPE_BOOL)));
	else
		SetType(base_type(TYPE_BOOL));
	*/

	bool promote_ops = false;

	if ( BothArithmetic(bt1, bt2) )
		promote_ops = true; //PromoteOps(max_type(bt1, bt2));

	else if ( EitherArithmetic(bt1, bt2) &&
		// Allow comparisons with zero.
		  ((bt1 == TYPE_TIME && v2->IsZero()) ||
		   (bt2 == TYPE_TIME && v1->IsZero())) )
		promote_ops = true; //PromoteOps(TYPE_TIME);

	else if ( bt1 == bt2 )
	{
		switch ( bt1 ) {
		case TYPE_BOOL:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_ERROR:
			break;

		case TYPE_ENUM:
			if ( ! same_type(v1->Type(), v2->Type()) )
				reporter->Error("illegal enum comparison");
			break;

		default:
			reporter->Error("illegal comparison");
		}
	}

	else if ( bt1 == TYPE_PATTERN && bt2 == TYPE_STRING )
		;

	else {
		reporter->Error("type clash in comparison");
		return false;
	}

	return true;
}

Val *InExprFold(Val *v1, Val *v2)
{
	if ( v1->Type()->Tag() == TYPE_PATTERN )
	{
		RE_Matcher* re = v1->AsPattern();
		const BroString* s = v2->AsString();
		return new Val(re->MatchAnywhere(s) != 0, TYPE_BOOL);
	}

	if ( v2->Type()->Tag() == TYPE_STRING )
	{
		const BroString* s1 = v1->AsString();
		const BroString* s2 = v2->AsString();

		// Could do better here - either roll our own, to deal with
		// NULs, and/or Boyer-Moore if done repeatedly.
		return new Val(strstr(s2->CheckString(), s1->CheckString()) != 0, TYPE_BOOL);
	}

	if ( v1->Type()->Tag() == TYPE_SUBNET &&
	     v2->Type()->Tag() == TYPE_ADDR )
		return new Val(v1->AsSubNetVal()->Contains(v2->AsAddr()), TYPE_BOOL);

	//TODO: anything beyond this point should probably be handled as an error, since
	// we have special handling for tables/sets/vectors
#ifdef LUA_DEBUG
	reporter->Error("Invalid Val type in InExprFold (Lua)");
	return NULL;
#endif

	Val* res;

	if ( is_vector(v2) )
		res = v2->AsVectorVal()->Lookup(v1);
	else
		res = v2->AsTableVal()->Lookup(v1, false);

	if ( res )
		return new Val(1, TYPE_BOOL);
	else
		return new Val(0, TYPE_BOOL);
}

Val *BinaryExprFold(Val *v1, Val *v2)
{
	if ( v1->Type()->Tag() == TYPE_PATTERN )
	{
		RE_Matcher* re = v1->AsPattern();
		const BroString* s = v2->AsString();
		return new Val(re->MatchExactly(s), TYPE_BOOL);
	}

	if ( ( v1->Type()->Tag() == TYPE_COUNT || v1->Type()->Tag() == TYPE_DOUBLE || 
		  v1->Type()->Tag() == TYPE_INT) && ( v2->Type()->Tag() == TYPE_COUNT || 
		  v2->Type()->Tag() == TYPE_DOUBLE || v2->Type()->Tag() == TYPE_INT) )
	{
		return new Val( v1->CoerceToDouble() == v2->CoerceToDouble(), TYPE_BOOL);
	}
	
	//BinaryExpr::Fold
	InternalTypeTag it = v1->Type()->InternalType();

	if ( it == TYPE_INTERNAL_STRING )
		return BinaryStringFold(v1, v2);

	if ( it == TYPE_INTERNAL_ADDR )
		return BinaryAddrFold(v1, v2);

	if ( it == TYPE_INTERNAL_SUBNET )
		return EqSubNetFold(v1, v2);

	char s1[100];
	char s2[100];
	TypeTagToString(v1->Type()->Tag(), s1);
	TypeTagToString(v2->Type()->Tag(), s2);
	reporter->Error("BinaryExprFold unhandled tag: %s and %s", s1, s2);
	return NULL;
}

Val *BinaryStringFold(Val* v1, Val* v2)
	{
	const BroString* s1 = v1->AsString();
	const BroString* s2 = v2->AsString();
	int result = 0;

	//TODO: check substrings, this just checks equality
	switch ( EXPR_EQ ) {
#undef DO_FOLD
#define DO_FOLD(sense) { result = Bstr_cmp(s1, s2) sense 0; break; }

	case EXPR_LT:		DO_FOLD(<)
	case EXPR_LE:		DO_FOLD(<=)
	case EXPR_EQ:		DO_FOLD(==)
	case EXPR_NE:		DO_FOLD(!=)
	case EXPR_GE:		DO_FOLD(>=)
	case EXPR_GT:		DO_FOLD(>)

	default:
		reporter->Error("BinaryStringFold");
	}

	return new Val(result, TYPE_BOOL);
}

Val *BinaryAddrFold(Val* v1, Val* v2)
{
	IPAddr a1 = v1->AsAddr();
	IPAddr a2 = v2->AsAddr();
	int result = 0;

	switch ( EXPR_EQ ) {

	case EXPR_LT:
		result = a1 < a2;
		break;
	case EXPR_LE:
		result = a1 < a2 || a1 == a2;
		break;
	case EXPR_EQ:
		result = a1 == a2;
		break;
	case EXPR_NE:
		result = a1 != a2;
		break;
	case EXPR_GE:
		result = ! ( a1 < a2 );
		break;
	case EXPR_GT:
		result = ( ! ( a1 < a2 ) ) && ( a1 != a2 );
		break;

	default:
		reporter->Error("BinaryExpr::AddrFold");
	}

	return new Val(result, TYPE_BOOL);
}

Val *EqSubNetFold(Val* v1, Val* v2)
{
	const IPPrefix& n1 = v1->AsSubNet();
	const IPPrefix& n2 = v2->AsSubNet();

	bool result = ( n1 == n2 ) ? true : false;

	return new Val(result, TYPE_BOOL);
}

Val *EqExprFold(Val *v1, Val *v2)
{
	if ( v1->Type()->Tag() == TYPE_PATTERN )
	{
		RE_Matcher* re = v1->AsPattern();
		const BroString* s = v2->AsString();
		return new Val(re->MatchExactly(s), TYPE_BOOL);
	}
	else if (v1->Type()->Tag() == TYPE_PORT && v2->Type()->Tag() == TYPE_PORT ) {
		bool portsEq = (((PortVal*)v1)->Port() == ((PortVal*)v2)->Port()) && \
		(((PortVal*)v1)->PortType() == ((PortVal*)v2)->PortType());
		return new Val(portsEq, TYPE_BOOL);
	}

	else {
		return BinaryExprFold(v1, v2);
	}
}

#endif /*ENABLE_LUAJIT*/











