//Developed by Leo Linsky for Packetsled. Copyright 2016-2017.

#include "bro-config.h"

#include "Val.h"
#include "List.h"

// Register a library referencing C functions that can be called by Lua

#ifdef ENABLE_LUAJIT

#include <lua.hpp>


//wrapper for manual registration of luaopen_bro
extern int lua_reg_bro_libs(lua_State *L);

//this is the function that would be used by a .so Lua library, however we register functions manually
int luaopen_bro(lua_State *L);


/* Custom Lua BIF's */

//Converts the userdata var args to a val_list, and does a Bro print -- TODO: rewrite along 
//	clean template guidelines, i.e. using something like populate_list
extern int function_BroPrintVals(lua_State *L);

//Given a string, attempts to find and return the named global Bro Val by reference
extern int function_LookupBroVal(lua_State *L);

//Generate an event with the given name and arguments
extern int function_GenerateEvent(lua_State *L);

//Adds new fields to extend a RecordType
extern int function_RedefRecord(lua_State *L);

//Adds new fields to add members to an Enum global
extern int function_RedefEnum(lua_State *L);

//Creates a new RecordType
extern int function_NewRecordType(lua_State *L);





/* Special Val Userdata Constructors */

extern int function_NewPort(lua_State *L);
extern int function_NewSubnet(lua_State *L);
extern int function_NewAddr(lua_State *L);
extern int function_NewInterval(lua_State *L);
extern int function_NewRecord(lua_State *L);
extern int function_NewLogRecord(lua_State *L);
extern int function_NewRecordType(lua_State *L);
extern int function_NewSet(lua_State *L);
extern int function_NewTable(lua_State *L);
extern int function_NewList(lua_State *L);
extern int function_NewVector(lua_State *L);
extern int function_NewFile(lua_State *L);


/* General BIF's */

//Generic BIF call that takes the BIF name as its first argument
extern int function_CallAnyBif(lua_State *L);


/* Miscellaneous auxiliary functions */

//Populate a val_list
int populate_list(lua_State *L, int start_index, int num_args, val_list *vl, bool *userdata, TypeTag desired_type=TYPE_VOID);

//Parse record arguments (field name, type)
bool ParseRecordArgs(lua_State *L, type_decl_list *type_list, val_list *args, int argc, attr_list *attrs);

extern const char * TransportProtoToString(TransportProto type);

extern TransportProto StringToTransportProto(const char *type);

extern int TypeTagToString(TypeTag tag, char *typestring);

extern int StringToTypeTag(const char *typestring, bool suppress_errors=false);

//Checks whether v2 is "in" v1 (containers handled separately)
extern Val *InExprFold(Val *v1, Val *v2);

//Checks whether v1 "==" v2 (containers handled separately)
extern Val *EqExprFold(Val *v1, Val *v2);

//Type specific helper functions for EqExprFold -- disabling non-comparison type folds
Val *BinaryStringFold(Val* v1, Val* v2);
Val *BinaryAddrFold(Val* v1, Val* v2);
Val *EqSubNetFold(Val* v1, Val* v2);


//Returns true if this is a valid EqExpr comparison
extern bool IsValidComparison(Val *v1, Val *v2);

#endif

















