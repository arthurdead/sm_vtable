#if defined __vtable_included
	#endinput
#endif
#define __vtable_included

native bool is_class_vtable_loaded(const char[] class_name);
native bool is_vfunc_loaded(const char[] class_name, const char[] func_name);
native int get_vtable_size(const char[] class_name);
native int get_vfunc_index(const char[] class_name, const char[] func_name);
native Address get_vfunc_addr_by_name(const char[] class_name, const char[] func_name);
native Address get_vfunc_addr_by_index(const char[] class_name, int index);

native bool is_class_symbols_loaded(const char[] class_name);
native bool is_class_sym_loaded(const char[] class_name, const char[] func_name);
native Address get_class_sym_addr(const char[] class_name, const char[] func_name);

#if !defined REQUIRE_EXTENSIONS
public void __ext_vtable_SetNTVOptional()
{
	MarkNativeAsOptional("is_class_vtable_loaded");
	MarkNativeAsOptional("is_vfunc_loaded");
	MarkNativeAsOptional("get_vtable_size");
	MarkNativeAsOptional("get_vfunc_index");
	MarkNativeAsOptional("get_vfunc_addr_by_name");
	MarkNativeAsOptional("get_vfunc_addr_by_index");

	MarkNativeAsOptional("is_class_symbols_loaded");
	MarkNativeAsOptional("is_class_sym_loaded");
	MarkNativeAsOptional("get_class_sym_addr");
}
#endif

public Extension __ext_vtable = 
{
	name = "vtable", 
	file = "vtable.ext", 
	
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif

#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};
