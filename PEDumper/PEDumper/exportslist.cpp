#include "exportslist.hpp"


export_entry::export_entry(char* library_name, char* name, WORD ord, unsigned __int64 rva, unsigned __int64 address, bool is64)
{
	if (library_name != NULL)
	{
		this->library_name = new char[strlen(library_name) + 1];
		strcpy(this->library_name, library_name);
	}
	else
	{
		this->library_name = NULL;
	}

	if (name != NULL)
	{
		this->name = new char[strlen(name) + 1];
		strcpy(this->name, name);
	}
	else
	{
		this->name = NULL;
	}

	this->is64 = is64;
	this->ord = ord;
	this->rva = rva;
	this->address = address;
}

export_entry::export_entry(export_entry* other)
{
	if (other->library_name != NULL)
	{
		this->library_name = new char[strlen(other->library_name) + 1];
		strcpy(this->library_name, other->library_name);
	}
	else
	{
		this->library_name = NULL;
	}

	if (other->name != NULL)
	{
		this->name = new char[strlen(other->name) + 1];
		strcpy(this->name, other->name);
	}
	else
	{
		this->name = NULL;
	}

	this->is64 = other->is64;
	this->ord = other->ord;
	this->rva = other->rva;
	this->address = other->address;
}

export_entry::~export_entry(void)
{
	if (library_name != NULL)
		delete[] library_name;
	if (name != NULL)
		delete[] name;
}

export_list::export_list()
{
	_min64 = _UI64_MAX;
	_max64 = UINT_MAX;
	_min32 = UINT_MAX;
	_max32 = 0;
	_bits32 = 0;
	_bits64 = 0;
}

bool export_list::contains(unsigned __int64 address)
{
	// Look up a 64-bit value
	if (address <= UINT_MAX)
		return contains((unsigned __int32)address);

	if (address > _max64 || address < _min64 || (address & ~_bits64) > 0)
	{
		return false;
	}

	unordered_set<unsigned __int64>::const_iterator got = _addresses.find(address);
	if (got != _addresses.end())
	{
		return true;
	}
	return false;
}

bool export_list::contains(unsigned __int32 address)
{
	// Look up a 32-bit value
	if (address > _max32 || address < _min32 || (address & ~_bits32) > 0)
	{
		return false;
	}

	unordered_set<unsigned __int64>::const_iterator got = _addresses.find(address);
	if (got != _addresses.end())
	{
		return true;
	}
	return false;
}

unsigned __int64 export_list::find_export(char* library, char* name, bool is64)
{

	for (unordered_map<unsigned __int64, export_entry*>::iterator it = _address_to_exports.begin(); it != _address_to_exports.end(); ++it)
	{

		if (it->second->is64 == is64 && (library == NULL || strcmpi(library, it->second->library_name) == 0) && strcmpi(name, it->second->name) == 0)
		{
			return it->second->address;
		}
	}

	return NULL;
}

export_entry export_list::find(unsigned __int64 address)
{
	unordered_map<unsigned __int64, export_entry*>::const_iterator got = _address_to_exports.find(address);
	if (got != _address_to_exports.end())
	{
		return got->second;
	}
	return NULL;
}

void export_list::add_export(unsigned __int64 address, export_entry* entry)
{
	if (_address_to_exports.count(address) == 0)
	{
		_address_to_exports.insert(std::pair<unsigned __int64, export_entry*>(address, new export_entry(entry)));

		if (_addresses.count(address) == 0)
		{
			_addresses.insert(address);

			if (address > UINT_MAX)
			{
				// 64bit value
				if (address > _max64)
					_max64 = address;
				if (address < _min64)
					_min64 = address;
				_bits64 = _bits64 | address;
			}
			else
			{
				// 32bit value
				if (address > _max32)
					_max32 = address;
				if (address < _min32)
					_min32 = address;
				_bits32 = _bits32 | address;
			}
		}
	}
}

bool export_list::add_exports(export_list* other)
{
	for (unordered_map<unsigned __int64, export_entry*>::iterator it = other->_address_to_exports.begin();
		it != other->_address_to_exports.end(); ++it)
	{
		add_export(it->first, it->second);
	}
	return true;
}


bool export_list::add_exports(unsigned char* image, SIZE_T image_size, unsigned __int64 image_base, IMAGE_EXPORT_DIRECTORY* export_directory, bool is64)
{
	if (export_directory->NumberOfFunctions > 0 && export_directory->AddressOfNameOrdinals != 0)
	{
		char* library_name = (char*)((__int64)export_directory->Name + image);
		if (!test_read(image, image_size, (unsigned char*)library_name, 0x1ff) || strlen(library_name) == 0)
		{

			fprintf(stderr, "WARNING: Invalid library export directory module name. Unable to add exports to table for import reconstruction. Library base 0x%llX.\r\n",
				(unsigned long long int) image_base);
			return false;
		}

		for (int i = 0; i < export_directory->NumberOfNames; i++)
		{
			if (test_read(image, image_size, image + export_directory->AddressOfNameOrdinals + i * 2, 2))
			{
				DWORD ordinal_relative = *(WORD*)(export_directory->AddressOfNameOrdinals + i * 2 + image);
				DWORD ordinal = export_directory->Base + ordinal_relative;

				char* name = NULL;
				if (i < export_directory->NumberOfNames)
				{
					if (test_read(image, image_size, image + export_directory->AddressOfNames + i * 4, 4))
					{
						DWORD name_offset = *((DWORD*)(image + export_directory->AddressOfNames + i * 4));

						if (test_read(image, image_size, image + name_offset, 0x4f))
						{
							name = (char*)(name_offset + image);
						}
					}
				}


				// Load the rva
				if (test_read(image, image_size, image + export_directory->AddressOfFunctions + ordinal_relative * 4, 4))
				{
					__int64 rva = *((DWORD*)(image + export_directory->AddressOfFunctions + ordinal_relative * 4));

					if (rva % 0x1000 != 0)
					{
						__int64 address = image_base + rva;

						export_entry* new_entry = new export_entry(library_name, name, ordinal, rva, address, is64);
						add_export(address, new_entry);
						delete new_entry;
					}
				}

			}
		}
	}
	return true;


}

export_list::~export_list(void)
{
	for (unordered_map<unsigned __int64, export_entry*>::iterator it = _address_to_exports.begin();
		it != _address_to_exports.end(); ++it)
	{
		delete it->second;
	}
	_address_to_exports.clear();
}
