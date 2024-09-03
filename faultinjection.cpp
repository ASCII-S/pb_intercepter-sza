#include "faultinjection.h"
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "pin.H"
#include "fi_cjmp_map.h"

#include "utils.h"
#include "instselector.h"
#include "memtrack.h"
#include <fstream>
#include "libload.h"
//#define INCLUDEALLINST
#define NOBRANCHES //always set
//#define NOSTACKFRAMEOP
//#define ONLYFP
using namespace std;
UINT64 fi_inject_instance = 0;
UINT64 fi_iterator = 0;
UINT64 total_num_inst = 0;
int activated = 0;

KNOB<string> fioption(KNOB_MODE_WRITEONCE, "pintool", "fioption", "AllInst", "specify fault injection option: AllInst, SPInst, FPInst, CCSavedInst");

//KNOB<string> instcount_file;

KNOB<string> fi_activation_file (KNOB_MODE_WRITEONCE, "pintool",
                                 "fi_activation", "activate", "specify fault injection activation file");

KNOB<BOOL> track_store(KNOB_MODE_WRITEONCE, "pintool", "memtrack", "0", "track all memory written?: default false." );
KNOB<string> memtrackfile(KNOB_MODE_WRITEONCE, "pintool", "memtrackfile", "", "file name to write the memtrack records.");
KNOB<BOOL> enable_fi(KNOB_MODE_WRITEONCE, "pintool", "enablefi", "0", "enable fault injection?: default no");


KNOB<string> instcount_file(KNOB_MODE_WRITEONCE, "pintool",
							"o", "pin.instcount.txt", "specify instruction count file name");

CJmpMap jmp_map;
FILE *activationFile;
RegMap reg_map;
UINT32 InstCounters[4] ={0};


UINT32 getRegSize(REG reg)
{
    if (REG_is_gr8(reg))
        return 8;
    else if (REG_is_gr16(reg))
        return 16;
    else if (REG_is_gr32(reg))
        return 32;
    else if (REG_is_gr64(reg))
        return 64;
    else
        return 128;
}

VOID FI_InjectFault_FlagReg(VOID * ip, UINT32 reg_num, UINT32 jmp_num, CONTEXT* ctxt, VOID * routine_name)
{
	//if(fi_iterator == fi_inject_instance) {
  //  cout << "here1" << endl;
    bool isvalid = false;

    const REG reg =  reg_map.findInjectReg(reg_num);
	//fprintf(stdout, "Reg name %s, ip %lx\n", REG_StringShort(reg).c_str(),
	//		(unsigned long)ip);
		if(REG_valid(reg)){

      isvalid = true;

			CJmpMap::JmpType jmptype = jmp_map.findJmpType(jmp_num);
		//PRINT_MESSAGE(3, ("EXECUTING flag reg: Original Reg name %s value %p\n", REG_StringShort(reg).c_str(),
		//			(VOID*)PIN_GetContextReg( ctxt, reg )));
			if(jmptype == CJmpMap::DEFAULT) {
				ADDRINT temp = PIN_GetContextReg( ctxt, reg );
				UINT32 inject_bit = jmp_map.findInjectBit(jmp_num);
				temp = temp ^ (1UL << inject_bit);

				PIN_SetContextReg( ctxt, reg, temp);
	    } else if (jmptype == CJmpMap::USPECJMP) {
				ADDRINT temp = PIN_GetContextReg( ctxt, reg );
				UINT32 CF_val = (temp & (1UL << CF_BIT)) >> CF_BIT;
				UINT32 ZF_val = (temp & (1UL << ZF_BIT)) >> ZF_BIT;
				if(CF_val || ZF_val) {
					temp = temp & (~(1UL << CF_BIT));
					temp = temp & (~(1UL << ZF_BIT));
				}
				else {
					temp = temp | (1UL << ZF_BIT);
				}
				PIN_SetContextReg( ctxt, reg, temp);
	    }	else {
				ADDRINT temp = PIN_GetContextReg( ctxt, reg );
				UINT32 SF_val = (temp & (1UL << SF_BIT)) >> SF_BIT;
				UINT32 OF_val = (temp & (1UL << OF_BIT)) >> OF_BIT;
				UINT32 ZF_val = (temp & (1UL << ZF_BIT)) >> ZF_BIT;
				if(ZF_val || (SF_val != OF_val)) {
					temp = temp & (~(1UL << ZF_BIT));
					if(SF_val != OF_val) {
						temp = temp ^ (1UL << SF_BIT);
					}
				}
				else {
					temp = temp | (1UL << ZF_BIT);
				}
				PIN_SetContextReg( ctxt, reg, temp);
			}
			//PRINT_MESSAGE(3, ("EXECUTING flag reg: Changed Reg name %s value %p\n", REG_StringShort(reg).c_str(),
			//		(VOID*)PIN_GetContextReg( ctxt, reg )));
			
			//FI_PrintActivationInfo();	
			//fi_iterator ++;
		}
		if(isvalid){
			fprintf(activationFile, "Activated: Valid Reg name %s, ip %lx inside %s\n", REG_StringShort(reg).c_str(),
					(unsigned long)ip, (const char *)routine_name);
			fclose(activationFile); // can crash after this!
			activated = 1;
			fi_iterator ++;
	
			PIN_ExecuteAt(ctxt);
				//PIN_ExecuteAt() will lead to reexecution of the function right after injection
		}



 else
      fi_inject_instance++;

		//fi_iterator ++;

	//}
	//fi_iterator ++;
}



//analysis code -- injection code
/*
VOID inject_SP_FP(VOID *ip, UINT32 reg_num, CONTEXT *ctxt){
	if(fi_iterator == fi_inject_instance) {
		const REG reg =  reg_map.findInjectReg(reg_num);
		if(!REG_valid(reg)){
			fprintf(stderr, "ERROR, Has to be one of SP or BP\n");
			exit(1);
		}	
		PRINT_MESSAGE(4, ("EXECUTING: Reg name %s value %p\n", REG_StringShort(reg).c_str(), 
			(VOID*)PIN_GetContextReg( ctxt, reg )));

		ADDRINT temp = PIN_GetContextReg( ctxt, reg );
		srand((unsigned)time(0)); 
		UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
		UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

		UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;

		temp = (ADDRINT) (temp ^ (1UL << inject_bit));

		PIN_SetContextReg( ctxt, reg, temp);
		PRINT_MESSAGE(4, ("EXECUTING: Changed Reg name %s value %p\n", REG_StringShort(reg).c_str(), 
			(VOID*)PIN_GetContextReg( ctxt, reg )));

		FI_PrintActivationInfo();	
		fi_iterator ++;
		PIN_ExecuteAt(ctxt);
	}
	//PIN_ExecuteAt() will lead to reexecution of the function right after injection
	fi_iterator ++;
}
*/


VOID inject_CCS(VOID *ip, UINT32 reg_num, CONTEXT *ctxt, VOID *routine_name){
	//need to consider FP regs and context
	//if(fi_iterator == fi_inject_instance) {
  //  cout << "here2" << endl;
		const REG reg =  reg_map.findInjectReg(reg_num);
		int isvalid = 0;
		if(REG_valid(reg)){
			isvalid = 1;
//PRINT_MESSAGE(4, ("Executing: Valid Reg name %s\n", REG_StringShort(reg).c_str()));

			if(reg_map.isFloatReg(reg_num)) {
				//PRINT_MESSAGE(4, ("Executing: Float Reg name %s\n", REG_StringShort(reg).c_str()));

        if (REG_is_xmm(reg)) {
          //PRINT_MESSAGE(4, ("Executing: xmm: Reg name %s\n", REG_StringShort(reg).c_str()));

					FI_SetXMMContextReg(ctxt, reg, reg_num);
				}
				else if (REG_is_ymm(reg)) {
					
					//PRINT_MESSAGE(4, ("Executing: ymm: Reg name %s\n", REG_StringShort(reg).c_str()));

					FI_SetYMMContextReg(ctxt, reg, reg_num);
				}
				else if(REG_is_fr(reg)||REG_is_st(reg) || REG_is_mm(reg)) {
					//PRINT_MESSAGE(4, ("Executing: mm or x87: Reg name %s\n", REG_StringShort(reg).c_str()));

					FI_SetSTContextReg(ctxt, reg, reg_num);
				}
				else {
					fprintf(stderr, "Register %s not covered!\n", REG_StringShort(reg).c_str());
					exit(3);
				}
			}
			else{
				//PRINT_MESSAGE(4, ("EXECUTING: Reg name %s value %p\n", REG_StringShort(reg).c_str(), 
				//	(VOID*)PIN_GetContextReg( ctxt, reg )));

				ADDRINT temp = PIN_GetContextReg( ctxt, reg );
				srand((unsigned)time(0)); 
				UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
				UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

				UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;

				temp = (ADDRINT)(temp ^ (1UL << inject_bit));

				PIN_SetContextReg( ctxt, reg, temp);

				
				//PRINT_MESSAGE(4, ("EXECUTING: Changed Reg name %s value %p\n", REG_StringShort(reg).c_str(), 
				//	(VOID*)PIN_GetContextReg( ctxt, reg )));
			}

                        //FI_PrintActivationInfo();	
		}
		if(isvalid){
			fprintf(activationFile, "Activated: Valid Reg name %s, ip %lx inside %s\n", REG_StringShort(reg).c_str(),
					(unsigned long)ip, (const char *)routine_name);
			fclose(activationFile); // can crash after this!
			activated = 1;
			fi_iterator ++;
	
			PIN_ExecuteAt(ctxt);
				//PIN_ExecuteAt() will lead to reexecution of the function right after injection
		}
        else
			fi_inject_instance++;
	//}
	//fi_iterator ++;
}

VOID FI_InjectFault_Mem(VOID * ip, VOID *memp, UINT32 size)
{
		//if(fi_iterator == fi_inject_instance) {
			if(size == 4) {
				PRINT_MESSAGE(4, ("Executing %p, memory %p, value %d, in hex %p\n",
					ip, memp, * ((int*)memp), (VOID*)(*((int*)memp))));
			}

			UINT8* temp_p = (UINT8*) memp;
			srand((unsigned)time(0)); 	
			UINT32 inject_bit = rand() % (size * 8/* bits in one byte*/);
		
			UINT32 byte_num = inject_bit / 8;
			UINT32 offset_num = inject_bit % 8;
		
			*(temp_p + byte_num) = *(temp_p + byte_num) ^ (1U << offset_num);
		
			if(size == 4) {
				PRINT_MESSAGE(4, ("Executing %p, memory %p, value %d, in hex %p\n", 
					ip, memp, * ((int*)memp), (VOID*)(*((int*)memp))));
			}
			

      fprintf(activationFile, "Activated: Memory injection\n");
			fclose(activationFile); // can crash after this!
			activated = 1;


			fi_iterator ++; //This is because the inject_reg will mistakenly add 1 more time when injecting 
		//}

		//fi_iterator ++;
}

VOID FI_InjectFaultMemAddr(VOID *ip, PIN_REGISTER *reg,UINT32 size, VOID *routine_name) {
	//if (fi_iterator == fi_inject_instance) {
   // cout << "here3" << endl;
	//	UINT32 *valp = reg->dword;
     // if (valp == NULL)
      //    cout << "fuck! thats it" << endl;
    //cout << "line1" << endl;
	//	srand((unsigned)time(0));
	//	UINT32 inject_bit = rand() % 32;
	//	UINT32 oldval = valp[0];
    //cout << "line2" << endl;
	//	*valp = *valp ^ (1U << inject_bit);
    //cout << "line3" << endl;
    UINT8* temp_p = (UINT8*) reg->byte;
    srand((unsigned)time(0));
    //UINT32 size = sizeof(reg);
    UINT32 inject_bit = rand() % (size/* bits in one byte*/);

    UINT32 byte_num = inject_bit / 8;
    UINT32 offset_num = inject_bit % 8;
    /*cout << "line2" << endl;
    cout << byte_num << endl;
    cout << offset_num << endl;
    cout << inject_bit << endl;
    cout << size << endl;
    cout << (unsigned long)ip << endl;*/
    *(temp_p + byte_num) = *(temp_p + byte_num) ^ (1U << offset_num);
    //cout << "line4" << endl;
	 //   cout << (const char *) routine_name << endl;
    //cout << "line3" << endl;
    /*
     * try to use existing code
     * */
    //ADDRINT temp = PIN_GetContextReg( ctxt, reg );
    //srand((unsigned)time(0));
    //UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
    //UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

    //UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;
    //UINT32 inject_bit = rand() % 32;
    //temp = (ADDRINT)(temp ^ (1UL << inject_bit));

    //PIN_SetContextReg( ctxt, reg, temp);
		fprintf(activationFile, "Activated: Memory address injection. [oldval,inject_bit]=[%" PRIu32 ",%" PRIu32 "], ip %lx inside %s\n",
                * ((int*)temp_p), inject_bit, (unsigned long)ip, (const char *)routine_name);
		fclose(activationFile);
		activated=1;
		fi_iterator++;
	//}
	//fi_iterator++;

}
ADDRINT FI_InjectIf() {
	fi_iterator++;
	return (fi_iterator==fi_inject_instance);
}

ADDRINT FI_InjectFlagsIf() {
	InstCounters[0]++;
	fi_iterator++;
    //cout << "---";
    //cout << fi_iterator << endl;
    //cout << fi_inject_instance << endl;
	return (fi_iterator==fi_inject_instance);

}
ADDRINT FI_InjectMemIf() {
	InstCounters[1]++;
	fi_iterator++;
    //cout << "---";
    //cout << fi_iterator << endl;
    //cout << fi_inject_instance << endl;
	return (fi_iterator==fi_inject_instance);

}
ADDRINT FI_InjectCSSIf() {
	InstCounters[2]++;
	fi_iterator++;
    //cout << "---";
    //cout << fi_iterator << endl;
    //cout << fi_inject_instance << endl;
	return (fi_iterator==fi_inject_instance);

}
VOID instruction_Instrumentation(INS ins, VOID *v){
	// decides where to insert the injection calls and what calls to inject
    if(!is_inlib.Value()) {
        if (!isValidInst(ins))
            return;
    }
	int numW = INS_MaxNumWRegs(ins), randW = 0;
	UINT32 index = 0;
	REG reg;
   // cout << "here5" << endl;
    string *s_temp = new string(RTN_Name(INS_Rtn(ins)));
    const char * routine_name = s_temp->c_str();
    //cout << routine_name << "+++"<<IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) << endl;
#ifdef INCLUDEALLINST	
  int mayChangeControlFlow = 0;
        if(!INS_HasFallThrough(ins))
			mayChangeControlFlow = 1;
		for(int i =0; i < numW; i++){
			reg = INS_RegW(ins, i);
			if(reg == REG_RIP || reg == REG_EIP || reg == REG_IP) // conditional branches
			{	mayChangeControlFlow = 1; break;}
		}
        if(numW > 1)
			randW = random() % numW;
        if(numW > 1 && (reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS))
           randW = (randW + 1) % numW; 
		if(numW > 1 && REG_valid(INS_RegW(ins, randW)))
            reg = INS_RegW(ins, randW);
        else
            reg = INS_RegW(ins, 0);
        if(!REG_valid(reg))
            return;
        index = reg_map.findRegIndex(reg);
        LOG("ins:" + INS_Disassemble(ins) + "\n"); 
		LOG("reg:" + REG_StringShort(reg) + "\n");
		
    // FIXME: INCLUDEINST is not used now. However, if you enable this option
    // in the future, you need to change the code below. If it changes the 
    // control flow, you need to inject fault in the read register rather than
    // write register
        if(mayChangeControlFlow)
			INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)inject_CCS,
					IARG_ADDRINT, INS_Address(ins),
					IARG_UINT32, index,	
					IARG_CONTEXT,
					IARG_END);		
		else
			INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)inject_CCS,
					IARG_ADDRINT, INS_Address(ins),
					IARG_UINT32, index,	
					IARG_CONTEXT,
					IARG_END);
#else


#ifdef NOBRANCHES
  if(INS_IsBranch(ins) || !INS_HasFallThrough(ins)) {
    //LOG("faultinject: branch/ret inst: " + INS_Disassemble(ins) + "\n");
		return;
  }
#endif

// NOSTACKFRAMEOP must be used together with NOBRANCHES, IsStackWrite 
// has a bug that does not put pop into the list
#ifdef NOSTACKFRAMEOP
  if(INS_IsStackWrite(ins) || OPCODE_StringShort(INS_Opcode(ins)) == "POP") {
    //LOG("faultinject: stack frame change inst: " + INS_Disassemble(ins) + "\n");    
    return;
  }
#endif

#ifdef ONLYFP
  bool hasfp = false;
  for (int i = 0; i < numW; i++){
    if (reg_map.isFloatReg(reg)) {
      hasfp = true;
      break;
    }
  }
  if (!hasfp){
    return;  
  }
#endif


// select instruction based on instruction type
  if(!isInstFITarget(ins))
    return;



      if(numW > 1)
			  randW = random() % numW;
      else
        randW = 0;

// Jiesheng
      reg = INS_RegW(ins, randW);
#ifdef ONLYFP
    while (!reg_map.isFloatReg(reg)) {
      randW = (randW + 1) % numW;
      reg = INS_RegW(ins, randW);
    }
#endif

  if(numW > 1 && (reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS))
           randW = (randW + 1) % numW; 
		if(numW > 1 && REG_valid(INS_RegW(ins, randW)))
            reg = INS_RegW(ins, randW);
        else
            reg = INS_RegW(ins, 0);
        if(!REG_valid(reg)) {

            LOG("REGNOTVALID: inst " + INS_Disassemble(ins) + "\n");
            return;
      }
        index = reg_map.findRegIndex(reg);
        LOG("ins:" + INS_Disassemble(ins) + "\n"); 
		LOG("reg:" + REG_StringShort(reg) + "\n");

// Jiesheng Wei
	if (reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS) {
		INS next_ins = INS_Next(ins);
		if (INS_Valid(next_ins) && INS_Category(next_ins) == XED_CATEGORY_COND_BR) {
      //LOG("inject flag bit:" + REG_StringShort(reg) + "\n");
			
      	UINT32 jmpindex = jmp_map.findJmpIndex(OPCODE_StringShort(INS_Opcode(next_ins)));
			INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)FI_InjectFlagsIf, IARG_END);
			INS_InsertThenPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)FI_InjectFault_FlagReg,
						IARG_INST_PTR,
						IARG_UINT32, index,
						IARG_UINT32, jmpindex,
						IARG_CONTEXT,
						IARG_PTR, routine_name,
						IARG_END);
			return;
		} else if (INS_IsMemoryWrite(ins) || INS_IsMemoryRead(ins)) {
//        	LOG("COMP2MEM: inst " + INS_Disassemble(ins) + "\n");
//
//        	INS_InsertPredicatedCall(
//								ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
//								IARG_ADDRINT, INS_Address(ins),
//								IARG_MEMORYREAD_EA,
//								IARG_MEMORYREAD_SIZE,
//								IARG_END);
			REG base_reg = INS_MemoryBaseReg(ins);
			if (REG_valid(base_reg)) {
                UINT32 size = getRegSize(base_reg);
				INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) FI_InjectMemIf, IARG_END);
				INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) FI_InjectFaultMemAddr,
											 IARG_INST_PTR, IARG_REG_REFERENCE, base_reg,IARG_UINT32,size,IARG_PTR, routine_name,IARG_END);
			} else {
				cout << "WTF why base_reg not valid?";
				exit(8);
			}
        	return;
    
		} else {
		  LOG("NORMAL FLAG REG: inst " + INS_Disassemble(ins) + "\n");
		}

	}

	if (INS_IsMemoryWrite(ins) || INS_IsMemoryRead(ins)) {
		LOG("COMP2MEM: inst " + INS_Disassemble(ins) + "\n");

//        INS_InsertPredicatedCall(
//								ins, IPOINT_BEFORE, (AFUNPTR)FI_InjectFault_Mem,
//								IARG_ADDRINT, INS_Address(ins),
//								IARG_MEMORYREAD_EA,
//								IARG_MEMORYREAD_SIZE,
//								IARG_END);
		REG reg = INS_MemoryBaseReg(ins);
		if (!REG_valid(reg)) {
			reg = INS_MemoryIndexReg(ins);
		}

		if (REG_valid(reg)) {
            UINT32 size = getRegSize(reg);
			INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) FI_InjectMemIf, IARG_END);
			INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) FI_InjectFaultMemAddr,
										 IARG_INST_PTR, IARG_REG_REFERENCE, reg,IARG_UINT32,size,IARG_PTR, routine_name, IARG_END);
			return;
		}

	}


		INS_InsertIfPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) FI_InjectCSSIf, IARG_END);
		INS_InsertThenPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR) inject_CCS,
				IARG_ADDRINT, INS_Address(ins),
				IARG_UINT32, index,
				IARG_CONTEXT,
				IARG_PTR,routine_name,
				IARG_END);

#endif        

}

VOID get_instance_number(const char* fi_instcount_file)
{
	FILE *fi_input_FILE = fopen(fi_instcount_file, "r");
    activationFile = fopen(fi_activation_file.Value().c_str(), "a");
    char line_buffer[FI_MAX_CHAR_PER_LINE];
	char *word = NULL;
	char *brnode = NULL;
	char *temp = NULL;
	UINT32 index = 0;
	if(fi_input_FILE == NULL) {
		fprintf(stderr, "ERROR, can not open Instruction count file %s, use -fi_function to specify a valid one\n", 
		fi_instcount_file);
		exit(1);
	}
	if(!(fioption.Value() == CCS_INST || fioption.Value() == FP_INST || fioption.Value() == SP_INST || fioption.Value() == ALL_INST)){
		fprintf(stderr, "ERROR, Specify one of valid options\n");
		exit(1);
	}
		
	while(fgets(line_buffer,FI_MAX_CHAR_PER_LINE,fi_input_FILE) != NULL){
		if(line_buffer[0] == '#') //only accept comments that start a new line
			continue;
		
		word=strtok_r(line_buffer,":", &brnode);
		index=0;
		while(word != NULL){
			switch(index){
			case 0:
				temp = word;
				break;
			case 1:
				if(strcmp(temp, fioption.Value().c_str()) == 0) 
					total_num_inst = atol (word);
				break;
			default:
				fprintf(stderr, "Too many argument in the line\n");
				exit(1);
			}
			index++;		
			word=strtok_r(NULL,":",&brnode);	
		}
				
		//assert((index == 2 || index == 0) && "Too few arguments in the line");
	}
	//PRINT_MESSAGE(4, ("Num Insts:%llu\n",total_num_inst)); 
	//srand((unsigned)time(0)); 
	unsigned int seed;
	FILE* urandom = fopen("/dev/urandom", "r");
	fread(&seed, sizeof(int), 1, urandom);
	fclose(urandom);
	srand(seed);
	fi_inject_instance = random() / (RAND_MAX * 1.0) * total_num_inst;
	//PRINT_MESSAGE(4, ("Instance:%llu\n",fi_inject_instance));
	fclose(fi_input_FILE);	
}

VOID Fini(INT32 code, VOID *v)
{
	if(!activated){
		fprintf(activationFile, "Not Activated!\n");
		fclose(activationFile);
	}




	if (memtrackfile.Value()=="") {
		cout << "# instructions [Flags,Mem,CSS]=[" << InstCounters[0] << ","
			<< InstCounters[1] << "," << InstCounters[2] << "]" << endl;
		cout << "total # instrs instrumented " << InstCounters[0]+InstCounters[1]+InstCounters[2] << endl;
		cout << "Memtrack: # addresses tracked: " << MemStore.size() << endl;
		cout << "Memtrack: sanity check # inst" << NMemWriteInstStatic << endl;
		for (map<VOID*,UINT64>::iterator it=MemStore.begin(); it!=MemStore.end(); ++it) {
			cout << hex << it->first << "\t" << it->second << endl;
		}
	} else {
		ofstream mf;
		mf.open(memtrackfile.Value().c_str());
		mf << "Memtrack: # addresses tracked: " << MemStore.size() << endl;
		mf << "Memtrack: sanity check # inst" << NMemWriteInstStatic << endl;
		for (map<VOID*,UINT64>::iterator it=MemStore.begin(); it!=MemStore.end(); ++it) {
			mf << hex << it->first << "\t" << it->second << endl;
		}
	}


}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool does fault injection\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}
//VOID fake(INS ins, VOID *) {
//	cout << "####Fake instrumentation.####" << endl;
//}
int main(int argc, char *argv[])
{
	PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();
  


  configInstSelector();


	get_instance_number(instcount_file.Value().c_str());
    if (is_inlib.Value())
    {

		parseLibNames(libnames.Value());
        INS_AddInstrumentFunction(libLoad, 0);
    }
    else{
        if (enable_fi.Value())
            INS_AddInstrumentFunction(instruction_Instrumentation, 0);
    }

	if (track_store.Value())
		INS_AddInstrumentFunction(memtrack,0);
	PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

VOID FI_SetSTContextReg (CONTEXT* ctxt, REG reg, UINT32 reg_num)
{
    //INPUT: x87 or st0-7 or MM[0-7]
    //choose st[i] to inject
    UINT32 i = 0;
    if(reg == REG_X87) {
        srand((unsigned)time(0));
        i = rand() % MAX_ST_NUM;
    }
    else {
        string reg_name = REG_StringShort(reg);
        i = reg_name[reg_name.size() - 1] - '0';
    }

    CHAR fpContextSpace[FPSTATE_SIZE];
    FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

    PIN_GetContextFPState(ctxt, fpContext);


    UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
    UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

    UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;

    if(inject_bit < 64) {
        //PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
         //       (VOID*)fpContext->fxsave_legacy._sts[i]._raw._lo));

        fpContext->fxsave_legacy._sts[i]._raw._lo ^= (1UL << inject_bit);

        //PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
          //      (VOID*)fpContext->fxsave_legacy._sts[i]._raw._lo));

    }
    else {
        //PRINT_MESSAGE(3, ("EXECUTING: Reg name %s High value %p\n", REG_StringShort(reg).c_str(),
          //      (VOID*)fpContext->fxsave_legacy._sts[i]._raw._hi));

        fpContext->fxsave_legacy._sts[i]._raw._hi ^= (1UL << (inject_bit - 64));

        //PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s High value %p\n", REG_StringShort(reg).c_str(),
         //       (VOID*)fpContext->fxsave_legacy._sts[i]._raw._hi));

    }

    PIN_SetContextFPState(ctxt, fpContext);
}

// FI: set the XMM[0-7] context register
VOID FI_SetXMMContextReg (CONTEXT* ctxt, REG reg, UINT32 reg_num)
{
    //choose XMM[i] to inject
    string reg_name = REG_StringShort(reg);
    UINT32 i = reg_name[reg_name.size() - 1] - '0';

    CHAR fpContextSpace[FPSTATE_SIZE];
    FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

    PIN_GetContextFPState(ctxt, fpContext);


    UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
    UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

    UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;

    // JIESHENG: this is not a right change from the hardware perspective, but it
    // is to improve the activated faults.
    // xmm is used for double, so only the lower 64 bits are used
    if (inject_bit >= 64)
        inject_bit -= 64;

    // JIESHNEG: something wrong, just to test whether the xmm injection is correct or not
    //
    srand(time(NULL));
    inject_bit = (rand() % 64);
    std::cerr << "Inject into bit " << inject_bit << std::endl;

    if(inject_bit < 64) {
       // PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
         //       (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));

        fpContext->fxsave_legacy._xmms[i]._vec64[0] ^= (1UL << inject_bit);

        //PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %p\n", REG_StringShort(reg).c_str(),
         //       (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[0]));

    }
    else {
        //PRINT_MESSAGE(3, ("EXECUTING: Reg name %s High value %p\n", REG_StringShort(reg).c_str(),
         //       (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[1]));

        fpContext->fxsave_legacy._xmms[i]._vec64[1] ^= (1UL << (inject_bit - 64));

        //PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s High value %p\n", REG_StringShort(reg).c_str(),
          //      (VOID*)fpContext->fxsave_legacy._xmms[i]._vec64[1]));

    }

    PIN_SetContextFPState(ctxt, fpContext);
}

// FI: set the YMM[0-7] context register
VOID FI_SetYMMContextReg (CONTEXT* ctxt, REG reg, UINT32 reg_num)
{
    //choose YMM[i] to inject
    string reg_name = REG_StringShort(reg);
    UINT32 i = reg_name[reg_name.size() - 1] - '0';

    CHAR fpContextSpace[FPSTATE_SIZE];
    FPSTATE *fpContext = reinterpret_cast<FPSTATE *>(fpContextSpace);

    PIN_GetContextFPState(ctxt, fpContext);


    UINT32 low_bound_bit = reg_map.findLowBoundBit(reg_num);
    UINT32 high_bound_bit = reg_map.findHighBoundBit(reg_num);

    UINT32 inject_bit = (rand() % (high_bound_bit - low_bound_bit)) + low_bound_bit;

    //FIXME: change number below to parameter
    UINT32 index = (i * 128 + inject_bit) / (sizeof(UINT8) * 8);
    UINT32 bit = (i * 128 + inject_bit) % (sizeof(UINT8) * 8);

    //PRINT_MESSAGE(3, ("EXECUTING: Reg name %s Low value %u\n", REG_StringShort(reg).c_str(),
      //      fpContext->_xstate._ymmUpper[index]));

    fpContext->_xstate._ymmUpper[index] ^= (1UL << bit);

    //PRINT_MESSAGE(3, ("EXECUTING: Changed Reg name %s Low value %u\n", REG_StringShort(reg).c_str(),
      //      fpContext->_xstate._ymmUpper[index]));

    PIN_SetContextFPState(ctxt, fpContext);
}

VOID FI_PrintActivationInfo()
{
    if(fi_activation_file.Value() != "") {
        FILE* fi_act_FILE = fopen(fi_activation_file.Value().c_str(), "w");

        if(fi_act_FILE != NULL) {
            fprintf(fi_act_FILE, "activated");
            fclose(fi_act_FILE);
        }
    }

}

bool is_stackptrReg(REG reg){
    if(reg == REG_RSP || reg == REG_ESP || reg == REG_SP)
        return true;
    return false;
}

bool is_frameptrReg(REG reg){
    if(reg == REG_RBP || reg == REG_EBP || reg == REG_BP)
        return true;
    return false;
}



VOID libLoad(INS ins,VOID *v)
{
	/*
    for (vector<string>::iterator it = libs.begin(); it != libs.end(); ++it)
    {
        string  image = IMG_Name(SEC_Img(RTN_Sec(rtn)));
        if (image.find(*it) != string::npos)
        {
            RTN_Open(rtn);
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                instruction_Instrumentation(ins,v);
            }
            RTN_Close(rtn);
            break;
        }
    }*/
   // cout << "here7" << endl;
    if (!RTN_Valid(INS_Rtn(ins))) { // some library instructions do not have rtn !?
        LOG("Invalid RTN " + INS_Disassemble(ins) + "\n");
        return;
    }
    std::string image = IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins))));
    //std::cout << image.c_str() << std::endl;
    for (std::vector<std::string>::iterator it = libs.begin(); it != libs.end(); ++it) {
        // std::cout << "it " << *it << std::endl;
        if (image.find(*it) != std::string::npos) {
            instruction_Instrumentation(ins,v);
            break;
        }
    }
}
