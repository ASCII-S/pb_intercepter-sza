//
// Created by Bo Fang on 2016-05-18.
//

#include<iostream>
#include<fstream>

#include <set>
#include <map>
//#include <string>

#include "pin.H"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cstddef> // For size_t
using namespace std;

KNOB<UINT64> randInst(KNOB_MODE_WRITEONCE, "pintool",
                      "randinst","0", "random instructions");

static UINT64 allinst = 0 ;
static UINT32 find_flag = 0;

#define Target_Opecode "MOV"
static UINT64 start_dec_adr = 4198496;
static UINT64 end_dec_adr = 4314860;


//mflag = 1;  表示ins是内存基址或内存索引寄存器
//mflag = -1; 表示ins是无效内存
//mflag = 0;  表示除了二者之外

//ip是每次遇到的指令,regname是在指令ins中随机找到的寄存器名称,mflag表示寄存器的状态
VOID docount(VOID *ip, VOID *reg_name,UINT32 mflag) {
    //allinst++;
    if (randInst.Value() <= allinst && find_flag ==0) {   //遇到参数中给定的随机数时执行下文;在randInst之后开始找第一个期望的操作码
        /*
        cout << "\ndocount in:" << endl;
        cout << "randInst:" << randInst.Value() << endl;
        cout << "actual Inst:" << allinst << endl;
        cout << "pc:\t" << std::hex << ip << dec << endl;
            */

        find_flag = 1;
        if (((unsigned long)ip > start_dec_adr) && ((unsigned long)ip < end_dec_adr)){  //符合预期的ip值
        //cout << "Find hexpc:\t" << std::dec << ip << dec << endl;
        ofstream OutFile;
        OutFile.open("instruction");
        if (mflag == 1){
            OutFile << "mem:"<<(const char *)reg_name << endl;
        }
        if (mflag == 0){
            OutFile << "reg:"<<(const char*)reg_name << endl;
        }
        if (static_cast<int>(mflag) == -1){
            OutFile << (const char*)reg_name << endl;
        }
        OutFile << "pc:"<<(unsigned long)ip << endl;
        OutFile.close();

        }
        else{
            find_flag = 0;
        }
    }
}
// Pin calls this function every time a new instruction is encountered
VOID CountInst(INS ins, VOID *v)
{
    //allinst++;
    //cout << "Current is" << allinst << endl;

        int mflag = 0;
        REG reg;
        const char * reg_name = NULL;

        // 获取操作码
        OPCODE opcode = INS_Opcode(ins);
        std::string opcodeStr = OPCODE_StringShort(opcode);
        const char *target_ope = Target_Opecode;

//------------------------------------------------------全局if,不是目标操作码就啥也不做--------------------------------------------------------//
        allinst++;
        //strncmp(opcodeStr.c_str(), target_ope, target_len) == 0
    if (opcodeStr == target_ope && find_flag ==0 && randInst.Value() <= allinst) { //只考虑目标操作码,考虑第一次命中,从随机数开始考虑
        /*
        std::cout << "\n\nFound JNE instruction: " << opcodeStr << std::endl;  // 如果前几项字符匹配
        // 使用 strncmp 比较 opcodeStr 的前 target_len 个字符
        cout << "Inj ope:\t" << opcodeStr.c_str() << "\tInj ins:\t" <<  INS_Disassemble(ins)<<endl;
        cout << "Target ope:\t" << target_ope << endl;
        cout << "Now Inst:\t" << allinst << endl;
        */


        if (INS_IsMemoryWrite(ins) || INS_IsMemoryRead(ins)) {//内存读写指令
            REG reg = INS_MemoryBaseReg(ins);//获取当前指令的内存基址寄存器
            string *temp = new string(REG_StringShort(reg));
            reg_name = temp->c_str();

            if (!REG_valid(reg)) {
                reg = INS_MemoryIndexReg(ins);//获取给定指令的内存索引寄存器
                string *temp = new string(REG_StringShort(reg));
                reg_name = temp->c_str();
                //OutFile <<"mem:" + REG_StringShort(reg) << endl;//不要打开这些OutFile,除非你仅调试这个工具
            }
            mflag = 1;  //表示ins是内存基址或内存索引寄存器
        }
        else {
            int numW = INS_MaxNumWRegs(ins), randW = 0;
            if (numW > 1)
                randW = rand() % numW;
            else
                randW = 0;

            reg = INS_RegW(ins, randW); //在ins中找随机的写寄存器,排除标志寄存器和无效寄存器
            if (numW > 1 && (reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS))
                randW = (randW + 1) % numW;
            if (numW > 1 && REG_valid(INS_RegW(ins, randW)))
                reg = INS_RegW(ins, randW);
            else
                reg = INS_RegW(ins, 0);
            if (!REG_valid(reg)) {
                string *temp = new string( "REGNOTVALID: inst " + INS_Disassemble(ins));
                reg_name = temp->c_str();
                //OutFile << "REGNOTVALID: inst " + INS_Disassemble(ins) << endl;
                mflag = -1;
            }
            if (reg == REG_RFLAGS || reg == REG_FLAGS || reg == REG_EFLAGS) {
                string *temp = new string( "REGNOTVALID: inst " + INS_Disassemble(ins));
                reg_name = temp->c_str();
                mflag = -1;
                //OutFile << "REGNOTVALID: inst " + INS_Disassemble(ins) << endl;
            }

            string *temp = new string(REG_StringShort(reg));
            reg_name = temp->c_str();
            //OutFile << "reg:" + REG_StringShort(reg) << endl;
        }
        //if (INS_Valid(INS_Next(ins)))
        //    OutFile<<"next:"<<INS_Address(INS_Next(ins)) << endl;
        //OutFile.close();
        INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)docount,IARG_INST_PTR,IARG_PTR,reg_name,IARG_UINT32,mflag,IARG_END);

        }
//------------------------------------------------------以上全局if,不是目标操作码就啥也不做--------------------------------------------------------//
    //cout<<"pc:"<<INS_Address(ins) << " " << allinst<< endl;
}

// bool mayChangeControlFlow(INS ins){
// 	REG reg;
// 	if(!INS_HasFallThrough(ins))
// 		return true;
// 	int numW = INS_MaxNumWRegs(ins);
// 	for(int i =0; i < numW; i++){
// 		if(reg == REG_RIP || reg == REG_EIP || reg == REG_IP) // conditional branches
// 			return true;
// 	}
// 	return false;
// }
// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    //ofstream OutFile;
    //OutFile.open(instcount_file.Value().c_str());
    //OutFile.setf(ios::showbase);
    //OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}



int main(int argc, char * argv[])
{
    PIN_InitSymbols();
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(CountInst, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
