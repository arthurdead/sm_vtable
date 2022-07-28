/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include <string_view>
#include <utility>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <unordered_map>

#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <dlfcn.h>

#include <cxxabi.h>

#if __has_include(<tinfo.h>)
	#include <tinfo.h>
	#define VTABLE_PREFIX_SIZE sizeof(__cxxabiv1::vtable_prefix)
#else
	#ifdef _GLIBCXX_VTABLE_PADDING
		#define VTABLE_PREFIX_SIZE 20
	#else
		#define VTABLE_PREFIX_SIZE 12
	#endif
#endif

#include "extension.h"
#include <server_class.h>

using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

Sample g_Sample;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_Sample);

class auto_fd
{
public:
	inline auto_fd(const char *path, int flags) noexcept
		: fd{::open(path, flags)}
	{
	}

	inline ~auto_fd() noexcept
	{ ::close(fd); }

	inline operator bool() const noexcept
	{ return fd != -1; }
	inline bool operator!() const noexcept
	{ return fd == -1; }
	inline operator int() const noexcept
	{ return fd; }

private:
	int fd;
};

class elf_reader
{
public:
	static bool init() noexcept
	{ return (elf_version(EV_CURRENT) != EV_NONE); }

	inline elf_reader(int fd) noexcept
		: elf{elf_begin(fd, ELF_C_READ, nullptr)}
	{
		if(!elf) {
			const int err{elf_errno()};
			const char *const msg{elf_errmsg(err)};
		}

		const bool valid{
			elf &&
			(elf_kind(elf) == ELF_K_ELF) &&
			(gelf_getclass(elf) != ELFCLASSNONE)
		};

		if(!valid) {
			if(elf) {
				elf_end(elf);
			}
			elf = nullptr;
		}
	}

	inline ~elf_reader() noexcept
	{
		if(elf) {
			elf_end(elf);
		}
	}

	inline operator bool() const noexcept
	{ return elf; }
	inline bool operator!() const noexcept
	{ return !elf; }

	template <typename F>
	inline void collect_symbols(F &&func) const noexcept
	{
		GElf_Shdr scn_hdr{};
		GElf_Sym sym{};

		Elf_Scn *scn{elf_nextscn(elf, nullptr)};
		while(scn) {
			if(!gelf_getshdr(scn, &scn_hdr)) {
				continue;
			}

			bool done{false};

			if(scn_hdr.sh_type == SHT_SYMTAB) {
				Elf_Data *scn_data{elf_getdata(scn, nullptr)};

				const std::size_t count{static_cast<std::size_t>(scn_hdr.sh_size) / static_cast<std::size_t>(scn_hdr.sh_entsize)};
				for(std::size_t i{0}; i < count; ++i) {
					gelf_getsym(scn_data, static_cast<int>(i), &sym);

					std::string name_mangled{elf_strptr(elf, scn_hdr.sh_link, sym.st_name)};
					if(func(std::move(name_mangled), static_cast<std::size_t>(sym.st_size), static_cast<std::ptrdiff_t>(sym.st_value))) {
						done = true;
						break;
					}
				}
			}

			if(done) {
				break;
			}

			scn = elf_nextscn(elf, scn);
		}
	}

private:
	Elf *elf;
};

class auto_dl
{
public:
	inline auto_dl(const char *path, int flags) noexcept
		: dl{dlopen(path, flags)}
	{
	}

	inline ~auto_dl() noexcept
	{ dlclose(dl); }

	inline operator bool() const noexcept
	{ return dl; }
	inline bool operator!() const noexcept
	{ return !dl; }
	inline operator void *() const noexcept
	{ return dl; }

private:
	void *dl;
};

struct vtable_func_info
{
	std::string name_mangled{"NULL"s};
	std::string name_unmangled{"NULL"s};
	std::string base_name_unmangled{"NULL"s};
	std::ptrdiff_t address{0};
	std::size_t index{static_cast<std::size_t>(-1)};
};

struct vable_info
{
	std::string class_name{"NULL"s};
	std::size_t size{0};
	std::size_t num_funcs{0};
	std::ptrdiff_t address{0};
	std::vector<vtable_func_info> funcs;
};

struct symbol_info
{
	std::string name_mangled{"NULL"s};
	std::string name_unmangled{"NULL"s};
	std::string base_name_unmangled{"NULL"s};
	std::ptrdiff_t address{0};
};

static std::string demangle(std::string_view mangled) noexcept
{
	size_t length{0};
	int status{0};
	char *buffer{__cxxabiv1::__cxa_demangle(mangled.data(), nullptr, &length, &status)};

	std::string unmmangled{};
	if(status == 0 && buffer && length > 0) {
		unmmangled.assign(buffer);
	}

	if(buffer) {
		free(buffer);
	}

	return unmmangled;
}

template <typename FV, typename FS>
static bool collect_everything(char *error, size_t maxlen, const void *baseaddr, std::vector<vable_info> &vtables, std::vector<symbol_info> &symbols, FV &&filter_vtable, FS &&filter_symbol) noexcept
{
	Dl_info base_addr_info{};
	if(dladdr(baseaddr, &base_addr_info) == 0) {
		std::strncpy(error, "failed to get base address info", maxlen);
		return false;
	}

	const auto_fd fd{base_addr_info.dli_fname, O_RDONLY};
	if(!fd) {
		std::strncpy(error, "failed to open file for reading symbols", maxlen);
		return false;
	}

	const elf_reader elf{fd};
	if(!elf) {
		std::strncpy(error, "failed to read elf", maxlen);
		return false;
	}

	elf.collect_symbols(
		[&vtables,&symbols,&filter_vtable = std::as_const(filter_vtable),&filter_symbol = std::as_const(filter_symbol),&base_addr_info = std::as_const(base_addr_info)](std::string &&name_mangled, std::size_t size, std::ptrdiff_t value) noexcept -> bool {
			std::string name_unmangled{demangle(name_mangled)};

			if(name_mangled.compare(0, 4, "_ZTV"sv) == 0) {
				std::string class_name{std::move(name_unmangled)};
				if(!class_name.empty()) {
					class_name = class_name.substr(11);
				}

				if(!filter_vtable(class_name)) {
					return false;
				}

				vable_info &info{vtables.emplace_back()};

				info.class_name = std::move(class_name);

				info.size = size;
				if(size > 0) {
					info.num_funcs = (size / sizeof(ptrdiff_t));
					info.funcs.resize(info.num_funcs);
				}

				info.address = value;

				const void *const *const vtable{reinterpret_cast<const void *const *const>((static_cast<const unsigned char *>(base_addr_info.dli_fbase) + info.address) + (VTABLE_PREFIX_SIZE - sizeof(std::ptrdiff_t)))};

				for(std::size_t i{0}; i < info.num_funcs; ++i) {
					vtable_func_info &func_info{info.funcs[i]};

					func_info.index = i;
					func_info.address = reinterpret_cast<std::ptrdiff_t>(vtable[i]);
				}
			} else if(filter_symbol(std::string_view{name_unmangled})) {
				symbol_info &sym{symbols.emplace_back()};

				sym.name_mangled = std::move(name_mangled);
				sym.name_unmangled = std::move(name_unmangled);

				std::size_t bfuncoff{sym.name_unmangled.find("::"sv)};
				if(bfuncoff != std::string::npos) {
					sym.base_name_unmangled = sym.name_unmangled.substr(bfuncoff+2);
				}

				sym.address = reinterpret_cast<std::ptrdiff_t>(static_cast<const unsigned char *>(base_addr_info.dli_fbase) + value);
			}

			return false;
		}
	);

	return true;
}

static std::vector<vable_info> server_vtables;
static std::unordered_map<std::string, const vable_info *> server_vtable_map;

static std::vector<symbol_info> server_symbols;
static std::unordered_map<std::string, std::vector<const symbol_info *>> server_class_symbol_map;

static cell_t get_vtable_size(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	if(class_it == server_vtable_map.cend()) {
		return pContext->ThrowNativeError("invalid class name %s", class_name.c_str());
	}

	return static_cast<cell_t>(class_it->second->funcs.size());
}

static cell_t get_vfunc_index(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	if(class_it == server_vtable_map.cend()) {
		return pContext->ThrowNativeError("invalid class name %s", class_name.c_str());
	}

	char *func_name_ptr{nullptr};
	pContext->LocalToString(params[2], &func_name_ptr);
	std::string_view func_name{func_name_ptr};

	const std::vector<vtable_func_info> &funcs{class_it->second->funcs};
	auto func_it{std::find_if(funcs.cbegin(), funcs.cend(),
		[func_name](const vtable_func_info &func) noexcept -> bool {
			return func.base_name_unmangled == func_name;
		}
	)};
	if(func_it == funcs.cend()) {
		return pContext->ThrowNativeError("invalid func name %s", func_name.data());
	}

	return static_cast<cell_t>(func_it->index);
}

static cell_t get_vfunc_addr_by_name(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	if(class_it == server_vtable_map.cend()) {
		return pContext->ThrowNativeError("invalid class name %s", class_name.c_str());
	}

	char *func_name_ptr{nullptr};
	pContext->LocalToString(params[2], &func_name_ptr);
	std::string_view func_name{func_name_ptr};

	const std::vector<vtable_func_info> &funcs{class_it->second->funcs};
	auto func_it{std::find_if(funcs.cbegin(), funcs.cend(),
		[func_name](const vtable_func_info &func) noexcept -> bool {
			return func.base_name_unmangled == func_name;
		}
	)};
	if(func_it == funcs.cend()) {
		return pContext->ThrowNativeError("invalid func name %s", func_name.data());
	}

	return static_cast<cell_t>(func_it->address);
}

static cell_t get_vfunc_addr_by_index(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	if(class_it == server_vtable_map.cend()) {
		return pContext->ThrowNativeError("invalid class name %s", class_name.c_str());
	}

	std::size_t index{params[2]};

	return static_cast<cell_t>(class_it->second->funcs[index].address);
}

static cell_t is_class_vtable_loaded(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	return (class_it != server_vtable_map.cend());
}

static cell_t is_vfunc_loaded(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_vtable_map.find(class_name)};
	if(class_it == server_vtable_map.cend()) {
		return 0;
	}

	char *func_name_ptr{nullptr};
	pContext->LocalToString(params[2], &func_name_ptr);
	std::string_view func_name{func_name_ptr};

	const std::vector<vtable_func_info> &funcs{class_it->second->funcs};
	auto func_it{std::find_if(funcs.cbegin(), funcs.cend(),
		[func_name](const vtable_func_info &func) noexcept -> bool {
			return func.base_name_unmangled == func_name;
		}
	)};

	return (func_it != funcs.cend());
}

static cell_t get_class_sym_addr(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_class_symbol_map.find(class_name)};
	if(class_it == server_class_symbol_map.cend()) {
		return pContext->ThrowNativeError("invalid class name %s", class_name.c_str());
	}

	char *sym_name_ptr{nullptr};
	pContext->LocalToString(params[2], &sym_name_ptr);
	std::string_view sym_name{sym_name_ptr};

	const std::vector<const symbol_info *> &syms{class_it->second};
	auto sym_it{std::find_if(syms.cbegin(), syms.cend(),
		[sym_name](const symbol_info *func) noexcept -> bool {
			return func->base_name_unmangled == sym_name;
		}
	)};
	if(sym_it == syms.cend()) {
		return pContext->ThrowNativeError("invalid symbol name %s", sym_name.data());
	}

	return static_cast<cell_t>((*sym_it)->address);
}

static cell_t is_class_symbols_loaded(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_class_symbol_map.find(class_name)};
	return (class_it != server_class_symbol_map.cend());
}

static cell_t is_class_sym_loaded(IPluginContext *pContext, const cell_t *params)
{
	char *class_name_ptr{nullptr};
	pContext->LocalToString(params[1], &class_name_ptr);
	std::string class_name{class_name_ptr};

	auto class_it{server_class_symbol_map.find(class_name)};
	if(class_it == server_class_symbol_map.cend()) {
		return 0;
	}

	char *sym_name_ptr{nullptr};
	pContext->LocalToString(params[2], &sym_name_ptr);
	std::string_view sym_name{sym_name_ptr};

	const std::vector<const symbol_info *> &syms{class_it->second};
	auto sym_it{std::find_if(syms.cbegin(), syms.cend(),
		[sym_name](const symbol_info *func) noexcept -> bool {
			return func->base_name_unmangled == sym_name;
		}
	)};

	return (sym_it != syms.cend());
}

static constexpr const sp_nativeinfo_t natives[]{
	{"is_class_vtable_loaded", is_class_vtable_loaded},
	{"is_vfunc_loaded", is_vfunc_loaded},
	{"get_vtable_size", get_vtable_size},
	{"get_vfunc_index", get_vfunc_index},
	{"get_vfunc_addr_by_name", get_vfunc_addr_by_name},
	{"get_vfunc_addr_by_index", get_vfunc_addr_by_index},

	{"is_class_symbols_loaded", is_class_symbols_loaded},
	{"is_class_sym_loaded", is_class_sym_loaded},
	{"get_class_sym_addr", get_class_sym_addr},

	{nullptr, nullptr}
};

bool Sample::SDK_OnLoad(char *error, size_t maxlen, bool late)
{
	sharesys->RegisterLibrary(myself, "vtable");

	sharesys->AddNatives(myself, natives);

	return true;
}

static bool str_ends_with(std::string_view str, std::string_view suffix) noexcept
{
	return str.length() >= suffix.length() && str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

bool Sample::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_ANY(GetServerFactory, gamedll, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL)
	GET_V_IFACE_CURRENT(GetEngineFactory, cvar, ICvar, CVAR_INTERFACE_VERSION);
	g_pCVar = cvar;
	ConVar_Register(0, this);

	if(!elf_reader::init()) {
		std::strncpy(error, "failed init elf library", maxlen);
		return false;
	}

	std::vector<std::string_view> svclasses_names;

	ServerClass *svclasses{gamedll->GetAllServerClasses()};
	while(svclasses) {
		svclasses_names.emplace_back(svclasses->GetName());
		svclasses = svclasses->m_pNext;
	}

	CreateInterfaceFn baseaddr{ismm->GetServerFactory(false)};

	if(!collect_everything(error, maxlen, reinterpret_cast<const void *>(baseaddr), server_vtables, server_symbols,
		[&svclasses_names](std::string_view name) noexcept -> bool {
			auto it{std::find_if(svclasses_names.cbegin(), svclasses_names.cend(),
				[name](std::string_view svclassname) noexcept -> bool {
					return svclassname.compare(0, svclassname.length(), name, 0, svclassname.length()) == 0;
				}
			)};
			if(it == svclasses_names.cend()) {
				return false;
			}
			return true;
		},
		[&svclasses_names](std::string_view name) noexcept -> bool {
			if(
				name.compare(0, 18, "typeinfo name for "sv) == 0 ||
				name.compare(0, 13, "typeinfo for "sv) == 0 ||
				str_ends_with(name, "::m_DataMap"sv) ||
				str_ends_with(name, "::g_DataMapHolder"sv) ||
				str_ends_with(name, "::m_pClassSendTable"sv) ||
				str_ends_with(name, "::YouForgotToImplementOrDeclareServerClass()"sv)
			) {
				return false;
			}
			auto it{std::find_if(svclasses_names.cbegin(), svclasses_names.cend(),
				[name](std::string_view svclassname) noexcept -> bool {
					return svclassname.compare(0, svclassname.length(), name, 0, svclassname.length()) == 0;
				}
			)};
			if(it == svclasses_names.cend()) {
				return false;
			}
			return true;
		}
	)) {
		return false;
	}

	for(vable_info &info : server_vtables) {
		for(vtable_func_info &func_info : info.funcs) {
			auto it{std::find_if(server_symbols.cbegin(), server_symbols.cend(),
				[&func_info = std::as_const(func_info)](const symbol_info &sym) noexcept -> bool {
					return sym.address == func_info.address;
				}
			)};
			if(it == server_symbols.cend()) {
				continue;
			}
			func_info.name_mangled = it->name_mangled;
			func_info.name_unmangled = it->name_unmangled;
			func_info.base_name_unmangled = it->base_name_unmangled;
		}
	}

	for(const vable_info &info : server_vtables) {
		server_vtable_map.emplace(info.class_name, &info);
	}

	for(const symbol_info &info : server_symbols) {
		std::size_t off{info.name_unmangled.find("::"sv)};
		if(off != std::string::npos) {
			std::string class_name{info.name_unmangled.substr(0, off)};

			auto it{server_class_symbol_map.find(class_name)};
			if(it == server_class_symbol_map.end()) {
				it = server_class_symbol_map.emplace(std::move(class_name), std::vector<const symbol_info *>{}).first;
			}

			it->second.emplace_back(&info);
		}
	}

	return true;
}

bool Sample::RegisterConCommandBase(ConCommandBase *pCommand)
{
	META_REGCVAR(pCommand);
	return true;
}

CON_COMMAND(dump_vtables, "")
{
	if (args.ArgC() < 2)
	{
		META_CONPRINT("Usage: dump_vtables <file>\n");
		return;
	}

	const char *file = args.Arg(1);
	if (!file || file[0] == '\0')
	{
		META_CONPRINT("Usage: dump_vtables <file>\n");
		return;
	}

	char path[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, path, sizeof(path), "%s", file);

	FILE *fp = NULL;
	if ((fp = fopen(path, "wt")) == NULL)
	{
		META_CONPRINTF("Could not open file \"%s\"\n", path);
		return;
	}
	
	char buffer[80];
	buffer[0] = 0;

	time_t t = g_pSM->GetAdjustedTime();
	size_t written = 0;
	{
#ifdef PLATFORM_WINDOWS
		InvalidParameterHandler p;
#endif
		written = strftime(buffer, sizeof(buffer), "%Y/%m/%d", localtime(&t));
	}

	fprintf(fp, "// Dump of all vtables for \"%s\" as at %s\n//\n\n", g_pSM->GetGameFolderName(), buffer);

	for(const auto &it : server_vtable_map) {
		fprintf(fp,"%s\n", it.first.c_str());
		for(const vtable_func_info &func : it.second->funcs) {
			fprintf(fp,"  %i - %p\n    %s\n    %s\n    %s\n", func.index, reinterpret_cast<const void *>(func.address), func.name_mangled.c_str(), func.name_unmangled.c_str(), func.base_name_unmangled.c_str());
		}
	}

	fclose(fp);
}

CON_COMMAND(dump_vtable, "")
{
	if (args.ArgC() < 3)
	{
		META_CONPRINT("Usage: dump_vtable <cls> <file>\n");
		return;
	}
	
	const char *cls = args.Arg(1);
	if (!cls || cls[0] == '\0')
	{
		META_CONPRINT("Usage: dump_vtable <cls> <file>\n");
		return;
	}

	const char *file = args.Arg(2);
	if (!file || file[0] == '\0')
	{
		META_CONPRINT("Usage: dump_vtable <cls> <file>\n");
		return;
	}

	char path[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, path, sizeof(path), "%s", file);

	FILE *fp = NULL;
	if ((fp = fopen(path, "wt")) == NULL)
	{
		META_CONPRINTF("Could not open file \"%s\"\n", path);
		return;
	}

	char buffer[80];
	buffer[0] = 0;

	time_t t = g_pSM->GetAdjustedTime();
	size_t written = 0;
	{
#ifdef PLATFORM_WINDOWS
		InvalidParameterHandler p;
#endif
		written = strftime(buffer, sizeof(buffer), "%Y/%m/%d", localtime(&t));
	}

	fprintf(fp, "// Dump of %s vtable for \"%s\" as at %s\n//\n//\n", cls, g_pSM->GetGameFolderName(), buffer);

	fprintf(fp, "//\n\n");
	
	auto it{server_vtable_map.find(std::string{cls})};
	if(it != server_vtable_map.cend()) {
		for(const vtable_func_info &func : it->second->funcs) {
			fprintf(fp,"  %i - %p\n    %s\n    %s\n    %s\n", func.index, reinterpret_cast<const void *>(func.address), func.name_mangled.c_str(), func.name_unmangled.c_str(), func.base_name_unmangled.c_str());
		}
	}

	fclose(fp);
}

CON_COMMAND(dump_symbols, "")
{
	if (args.ArgC() < 2)
	{
		META_CONPRINT("Usage: dump_symbols <file>\n");
		return;
	}

	const char *file = args.Arg(1);
	if (!file || file[0] == '\0')
	{
		META_CONPRINT("Usage: dump_symbols <file>\n");
		return;
	}

	char path[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, path, sizeof(path), "%s", file);

	FILE *fp = NULL;
	if ((fp = fopen(path, "wt")) == NULL)
	{
		META_CONPRINTF("Could not open file \"%s\"\n", path);
		return;
	}
	
	char buffer[80];
	buffer[0] = 0;

	time_t t = g_pSM->GetAdjustedTime();
	size_t written = 0;
	{
#ifdef PLATFORM_WINDOWS
		InvalidParameterHandler p;
#endif
		written = strftime(buffer, sizeof(buffer), "%Y/%m/%d", localtime(&t));
	}

	fprintf(fp, "// Dump of all vtables for \"%s\" as at %s\n//\n\n", g_pSM->GetGameFolderName(), buffer);

	for(const auto &it : server_class_symbol_map) {
		fprintf(fp,"%s\n", it.first.c_str());
		for(const symbol_info *func : it.second) {
			fprintf(fp,"  %p\n    %s\n    %s\n    %s\n", reinterpret_cast<const void *>(func->address), func->name_mangled.c_str(), func->name_unmangled.c_str(), func->base_name_unmangled.c_str());
		}
	}

	fclose(fp);
}

CON_COMMAND(dump_symbols_cls, "")
{
	if (args.ArgC() < 3)
	{
		META_CONPRINT("Usage: dump_symbols_cls <cls> <file>\n");
		return;
	}
	
	const char *cls = args.Arg(1);
	if (!cls || cls[0] == '\0')
	{
		META_CONPRINT("Usage: dump_symbols_cls <cls> <file>\n");
		return;
	}

	const char *file = args.Arg(2);
	if (!file || file[0] == '\0')
	{
		META_CONPRINT("Usage: dump_symbols_cls <cls> <file>\n");
		return;
	}

	char path[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, path, sizeof(path), "%s", file);

	FILE *fp = NULL;
	if ((fp = fopen(path, "wt")) == NULL)
	{
		META_CONPRINTF("Could not open file \"%s\"\n", path);
		return;
	}

	char buffer[80];
	buffer[0] = 0;

	time_t t = g_pSM->GetAdjustedTime();
	size_t written = 0;
	{
#ifdef PLATFORM_WINDOWS
		InvalidParameterHandler p;
#endif
		written = strftime(buffer, sizeof(buffer), "%Y/%m/%d", localtime(&t));
	}

	fprintf(fp, "// Dump of %s symbols for \"%s\" as at %s\n//\n//\n", cls, g_pSM->GetGameFolderName(), buffer);

	fprintf(fp, "//\n\n");
	
	auto it{server_class_symbol_map.find(std::string{cls})};
	if(it != server_class_symbol_map.cend()) {
		for(const symbol_info *func : it->second) {
			fprintf(fp,"  %p\n    %s\n    %s\n    %s\n", reinterpret_cast<const void *>(func->address), func->name_mangled.c_str(), func->name_unmangled.c_str(), func->base_name_unmangled.c_str());
		}
	}

	fclose(fp);
}
