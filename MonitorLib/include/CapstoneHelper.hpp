//By AlSch092 @github
#pragma once
#include <exception>
#include <stdexcept>
#include <vector>
#include <string>
#include "Capstone/capstone.h"

struct CapstoneData
{
	std::vector<std::string> opcodes;
	std::vector<std::string> mnemonics;
	std::vector<uintptr_t> addresses;
};


/*
	CapstoneHelper - wrapper for using Capstone library (to parse byte strings as assembler instructions)
*/
class CapstoneHelper final
{
public:

	CapstoneHelper();
	~CapstoneHelper();

	CapstoneHelper(const CapstoneHelper&) = delete; //delete copy constructor
	CapstoneHelper& operator=(const CapstoneHelper&) = delete; //delete copy assignment

	CapstoneHelper operator+(const CapstoneHelper&) = delete;
	CapstoneHelper operator-(const CapstoneHelper&) = delete;
	CapstoneHelper operator*(const CapstoneHelper&) = delete;
	CapstoneHelper operator/(const CapstoneHelper&) = delete;

	CapstoneHelper(CapstoneHelper&& rhs) noexcept : CapstoneHandle(rhs.CapstoneHandle)
	{
		rhs.CapstoneHandle = 0;
	}

	CapstoneHelper& operator=(CapstoneHelper&& rhs) noexcept
	{
		if (this != &rhs)
		{
			if (CapstoneHandle)
			{
				cs_close(&CapstoneHandle);
			}

			CapstoneHandle = rhs.CapstoneHandle;
			rhs.CapstoneHandle = 0;
		}
		return *this;
	}

	csh GetHandle() const { return this->CapstoneHandle; }

	CapstoneData GetInstructionsFromBytes(__in const uint8_t* bytes, __in const int size, __in const uintptr_t startAddress, __in const int numInstructionsToDecode);

private:
	csh CapstoneHandle = 0;
};