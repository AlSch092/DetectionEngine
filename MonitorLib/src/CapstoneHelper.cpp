//By Alsch092 @ Github
#include "../include/CapstoneHelper.hpp"

/**
 * @brief CapstoneHelper constructor
 *
 *
 * @return CapStoneHelper allocated object
 *
 * @usage
 * CapstoneHelper* ch = new CapstoneHelper();
 */
CapstoneHelper::CapstoneHelper()
{
	cs_err init = cs_open(CS_ARCH_X86, CS_MODE_64, &this->CapstoneHandle); 	// Initialize Capstone for x86-64

	if (init != CS_ERR_OK)
	{
		this->CapstoneHandle = 0;

		if (init == CS_ERR_ARCH)
		{
			if (!cs_support(CS_ARCH_X86))
			{
				throw std::runtime_error("Capstone does not support X86 architecture");  //err, this static lib was set to work with x86/64. this should never occur
			}
		}
	}
}

/**
 * @brief CapstoneHelper class destructor
 *
 * @param implicit `this` pointer, representing current context's class object
 *
 * @return None
 *
 * @usage
 * delete ch;
 */
CapstoneHelper::~CapstoneHelper()
{
	if (this->CapstoneHandle)
	{
		cs_close(&this->CapstoneHandle);
	}
}

/**
 * @brief Fetches information about assembler instructions for a set of bytes
 *
 * @param `bytes` array of bytes to parse
 * @param `size`  size of array of bytes
 * @param `startAddress`  size of array of bytes
 * @param `numInstructionsToDecode`  
 * 
 * 
 * @return CapstoneData object, containing information about the instructions parsed from `bytes`
 *
 * @usage
 * const byte* b = "\x48\x28\x24\x0C\xC3";
 * CapstoneData CD = CapstoneHelper::GetInstructionsFromBytes(b, 5, &b, 2);
 */
CapstoneData CapstoneHelper::GetInstructionsFromBytes(__in const uint8_t* bytes, __in const int size, __in const uintptr_t startAddress, __in const int numInstructionsToDecode)
{
	cs_insn* insn = nullptr;

	CapstoneData capstoneData;

	size_t count = cs_disasm(this->CapstoneHandle, bytes, size, startAddress, numInstructionsToDecode, &insn);

	if (count > 0)
	{
		for (size_t i = 0; i < count; i++)
		{
			char buffer[128]{ 0 };
			snprintf(buffer, sizeof(buffer), "0x%" PRIx64 ": %s %s", insn[i].address, insn[i].mnemonic, insn[i].op_str);

			capstoneData.opcodes.push_back(insn[i].op_str);
			capstoneData.mnemonics.push_back(insn[i].mnemonic);
			capstoneData.addresses.push_back(insn[i].address);
		}

		cs_free(insn, count);
	}
	else
	{
		//throw std::runtime_error("ERROR: Failed to disassemble code.");
		return capstoneData;
	}

	return capstoneData;
}


