/**
 *  Integration of Lua scripts running on Luajit with Bro events
 *
 *  Author: Leo Linsky
 *
 *  Copyright: Packetsled 2016, 2017
 */

#ifndef MANAGE_LUAJIT_H
#define MANAGE_LUAJIT_H


#include "bro-config.h"
#include "Val.h"
#include "Type.h"

#ifdef ENABLE_LUAJIT
 
//includes all lua headers under extern 'C'
#include <lua.hpp>

#include <list>
#include <unordered_map>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <cstring>

// Big negative number so errors deep in a recursive tree still result in a negative arg count (error)
#define STACK_ERROR -9999999
#define MAX_INT 2147483645
#define SYS_BUF_SIZE ( (32)*(sizeof(struct inotify_event) + 16) )


#include <map>
struct cmp_str
{
   bool operator()(const char *a, const char *b) const
   {
      return strcmp(a, b) < 0;
   }
};

typedef std::map<const char*, std::list<void *>, cmp_str> EventToLuaMap;
typedef std::unordered_map<void *, const char *> LuaActiveMap;
typedef std::unordered_map<void *, int> LuaScriptAttrMap;

// if (map[lua_State][lua_call_idx][C++ function pointer] == true) { /*code has already passed*/}
typedef std::unordered_map<void *, std::map<long int, std::map<const char *, bool, cmp_str>>> LuaSafetyCheckCache;


class LuajitManager
{
public:

	/* Constructor / Destructor */

	LuajitManager(const char *lua_script_dir);
	
	~LuajitManager();



	/* Script Parsing and Loading */

	// Loads Lua scripts are starts inotify file detection
	int Load();

	//Recursively loads Lua scripts from the LUA_ROOT_DIR file tree
	int TraverseLuaScriptTree(const char *name, int level);

	//Loads a Lua script and all libraries and registers events
	int LoadLuaScript(const char *name);

	//Periodic thread function that checks for inotify filesystem events
	static void *CheckINotifyEvents(void *self);

	//Removes a script that has changed, as notified by an inotify event. Can be forced
	//	in the event of an error, not a script change
	int DynamicallyRemoveScript(const char *filename, bool force=false);

	//Secondary removal method to prevent lock contention, which should be called by direct 
	//	Lua script problems, not Bro-side errors
	void RemoveFaultyScript(lua_State *L);

	//Prepares script for removal
	static void SetFaultyScript(lua_State *L);

	//Adds a script that has changed or been added, as notified by an inotify event
	int DynamicallyAddScript(const char *filename);

	//Helper function to identify .lua files
	static int HasLuaExtension(char const *name);

	//Helper function to identify file attributes hash
	static int FileHash(char const *name);

	//Helper function returns false for events that we explicitly do not support for Lua
	static inline bool LuaEventSupported(const char *handler);



	/* Event Response and Argument Pushing */

	//Run the generated event on all registered lua scripts
	void LuajitTryEvent(const char *name, val_list *args, bool need_lock=true);

	//Push a list of arguments accompanying an Event to Lua's virtual stack
	int PushLuaArgs(lua_State *L, val_list *args);

	//Push Bro Val as a userdatum
	int PushLuaVal(lua_State *L, Val *, bool ref=true);

	//Used to reconstruct a Val from a generic Lua argument
	Val* PullLuaValFromGenericArg(lua_State *L, int index, bool *userdata, TypeTag desired_type=TYPE_ERROR);

	//Pushes a Bro Val recursively as a mutable table that can be used to modify complex types
	//TODO: May remove these, since it is currently believed that setting and getting will be possible
	//	with the accessors, albeit each base type would be referenced one at a time, and you couldn't
	//	just assign something to a Port type without this functionality (PullLuaValAsTable).. (or just
	//	use them for complex types)
	int PushLuaValAsTableRecursive(lua_State *L, Val *arg, int first_call);

	//TODO: Used to reconstruct a Val from a table, if we support tables as an alternate representation
	//	could be especially useful for ports and things
	Val* PullLuaValFromTableRecursive(lua_State *L, int index);


	/* Lua-Userdata/Bro-Val Meta-Events */

	//Setter for userdata with bro.val metatables. Called in the form val["field"] = newval, where 
	//	field and newval can be any valid types (interpreted appropriately when possible).
	static int function_SetLuaVal(lua_State *L);

	//Setter for userdata with bro.val metatables. Called in the form newval = val["field"], where 
	//	field can be any valid index type or string field.
	static int function_GetLuaVal(lua_State *L);

	//Registered to Lua descriptor AsTable(), calls PushLuaValAsTableRecursive
	static int function_PushLuaTable(lua_State *L);

	//Converts a userdata or valid Val table to string -- called in Lua with tostring()
	static int function_ValToString(lua_State *L);

	//Garbage collection method for Lua userdata (this ensures no memory leaks on Vals)
	static int function_GarbageCollectVal(lua_State *L);

	//Protect the userdata (and hence the Val) from metatable modifications by the Lua program
	static int function_HideMetaTable(lua_State *L);
	
	//Creates a copy of a Val for Lua assignment. Any time a Val/userdata is copied, it is Ref'd. 
	//	Once the variable is no longer needed, it's garbage collected. Event arguments are also
	//	Ref'd and garbage collected TODO: Verify that arguments are garbage collected, otherwise don't Ref
	//	them, manually garbage collect them when the function ends, or require explicit copies for persistent
	//	desired assignments
	static int function_CopyLuaVal(lua_State *L);

	//Called when Lua calls a userdata like a function. Currently undefined.
	static int function_CallLuaVal(lua_State *L);

	//Adds two Lua userdata together, if the underlying Vals support addition
	static int function_AddLuaVals(lua_State *L);

	//Adds one value to a Lua userdata and modifies the base object, if the types support addition
	static int function_AddElementToLuaVal(lua_State *L);

	//Removes one value from a Lua userdata and modifies the base object, if the types support subtraction 
	static int function_RemoveFromLuaVal(lua_State *L);

	//Concatenates two Lua userdata together, if the underlying Vals support concatenation. If
	//	not, returns concatenated __tostring() representation
	static int function_ConcatLuaVals(lua_State *L);

	//Compares two Lua Vals for equality
	static int function_CompareEqLuaVal(lua_State *L);
	

	/* Lua general Val userdata Methods */

	//Returns BroType enum as a string
	static int function_GetBroType(lua_State *L); 

	//Type checks for safe-Lua programming (optional)
	static int function_IsVector(lua_State *L);
	static int function_IsRecord(lua_State *L);
	static int function_IsTable(lua_State *L);
	static int function_IsSet(lua_State *L);
	static int function_IsPort(lua_State *L);
	static int function_IsAddr(lua_State *L);
	static int function_IsSubnet(lua_State *L);
	static int function_IsInterval(lua_State *L);

	//Returns size of vector, table, or set
	static int function_Size(lua_State *L);

	//Converts intervals, ports, and enums to numbers
	static int function_ToNumber(lua_State *L);


	/* Lua specific Val type methods */

	// PortVal userdata methods to return simple types (booleans/numbers)
	static int function_IsTCP(lua_State *L);
	static int function_IsUDP(lua_State *L);
	static int function_IsICMP(lua_State *L);
	static int function_PortNumber(lua_State *L);

	// AddrVal userdata methods to get IPVersion (number) and a byte array (table)
	static int function_IPVersion(lua_State *L);
	static int function_IPByteArray(lua_State *L);

	// SubnetVal userdata methods to check IP Vals
	static int function_SubnetMask(lua_State *L);
	static int function_SubnetMaskWidth(lua_State *L);
	static int function_SubnetPrefix(lua_State *L);

	// PatternVal userdata methods to combine and apply regexes
	static int function_AddPattern(lua_State *L);
	static int function_SearchPattern(lua_State *L);

	// BroFile manipulation
	static int function_FileIsOpen(lua_State *L);
	static int function_WriteFile(lua_State *L);
	static int function_CloseFile(lua_State *L);

	// Container methods (Sets, Tables, etc.)
	static int function_ValContains(lua_State *L); //dually used to test container membership
	static int function_GetTableIndicesVector(lua_State *L);
	static int function_GetSetElementsVector(lua_State *L);

	/* Auxiliary functions */

	//Checks and returns Val from userdata
	static Val* CheckLuaUserdata(lua_State *L, int index);

	//Helper function to get Val of specific type or error
	static Val* GetValOfType(lua_State *L, TypeTag type, int index, int argc, bool type_check=false);

	//Function that returns a string description of any eligible Val
	static std::string ValAsString(Val *v, char *print_type=NULL);

	// Pointer to responders
	EventToLuaMap EventResponders() { return responders; }

	//Lock that must be held for all active Lua functionality to prevent inconsistent
	//	state when removing or modifying scripts -- this condition should be satisfied by
	//	locking LuajitTryEvent, which owns all events called by Lua, unless Lua threading  
	//	or timers are used.... TODO 
	pthread_mutex_t lua_lock;


	//In the case that a script does not return with an error but has some Bro problem, this variable is 
	//	checked by LuajitTryEvent to determine whether to remove the active script
	std::list<void *> bad_context_list;

	void SafetyChecksPassed(lua_State *L, long int lua_index, const char *c_function_ptr)
	{
		execution_cache[((void *)L)][lua_index][c_function_ptr] = true;
	}
	
	// Cache of all Lua calls, such that expensive safety checks are not done redundantly
	// This contains a map of Lua state to map of C function to map of Lua calling line/statement,
	// such that we can optimize out redundant safety checks for the same line of code if it's
	// run multiple times.
	LuaSafetyCheckCache execution_cache;

private:

	//Map of events to registered Lua scripts
	EventToLuaMap responders;

	//Map of active Lua contexts and the script that each context represents
	LuaActiveMap active_states;

	//Map of active Lua contexts and a hash of the script metadata for the purposes
	//	of determining whether to remove an actively loaded script
	LuaScriptAttrMap active_hashes;

	//Inotify polling thread
	pthread_t tid_inotify;

	//Inotify file descriptors for dynamic script loading
	int ifd;
	int wfd;

	//Script root directory -- TODO: replace with an unordered_map of inotify wd's to full directory names
	const char *script_dir;

	//Keepalive flag for inotify thread
	bool keepalive;

};


extern LuajitManager *lua_mgr;

// Checks lua_mgr's execution_cache to determine if safety checks for a given function and
// execution context are redundant. See lua_absindex, lua_gethook, lua_getinfo, lua_getstack 
// for obtaining unique line pointers (may need to index full Lua stack)
bool inline passed_safety_checks(lua_State *L, long int lua_index, const char *c_function);


#endif /* ENABLE_LUAJIT */

#endif
