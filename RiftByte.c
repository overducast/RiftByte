/*
 * RiftByte.c - Binary diff tool for PE and ELF files
 *
 * Copyright (c) 2026 overducast
 *
 * Repository: https://github.com/overducast/RiftByte
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define CHUNK 4096

/* PE */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
} DOS;

typedef struct {
    uint32_t Signature;
    uint16_t machine;
    uint16_t sections;
    uint32_t timestamp;
    uint32_t sym;
    uint32_t symnum;
    uint16_t optsize;
    uint16_t characteristics;
} PE;

typedef struct {
    uint8_t  name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t reloc;
    uint32_t lineno;
    uint16_t reloc_count;
    uint16_t lineno_count;
    uint32_t characteristics;
} SEC;

/* ELF */

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ELF64HDR;

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ELF32HDR;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} ELF64SHDR;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} ELF32SHDR;

#pragma pack(pop)

#define MACHINE_I386   0x014C
#define MACHINE_AMD64  0x8664
#define MACHINE_ARM    0x01C0
#define MACHINE_ARM64  0xAA64
#define MACHINE_ARMNT  0x01C4

SEC sections[64];
int secCount = 0;

uint64_t imageBase  = 0;
uint64_t entryPoint = 0;
uint64_t entryPoint2 = 0;  /* EP of the comparison file */
uint64_t imageBase2  = 0;
int is64bit  = 0;
int isArm    = 0;
int isDll    = 0;
int isDotNet = 0;
int isElf    = 0;

typedef enum { FMT_PE, FMT_ELF, FMT_UNKNOWN } FileFormat;
FileFormat fileFormat = FMT_UNKNOWN;

typedef struct {
    char     name[32];
    uint64_t va;
    uint64_t size;
    uint64_t file_off;
} ElfSection;

ElfSection elfSections[64];
int elfSecCount = 0;

/* MAX_PATCH_BYTES: max bytes captured per diff group for .1337 export */
#define MAX_PATCH_BYTES 2048

typedef struct {
    char     sec[32];
    uint64_t va;
    uint64_t file_off;
    char     before_op[64];
    char     after_op[64];
    /* hex-dump strings for display */
    char     before_bytes[4096];
    char     after_bytes[4096];
    /* raw bytes for accurate .1337 export */
    uint8_t  raw_before[MAX_PATCH_BYTES];
    uint8_t  raw_after[MAX_PATCH_BYTES];
    int      raw_len;
    int      has_jump;
    uint64_t jump_target;
} LogEntry;

#define MAX_LOG 4096
static LogEntry gLog[MAX_LOG];
static int      gLogCount = 0;

static void banner() {
    printf(
"                                        \n"
"  \u2584\u2584\u2584\u2584\u2584\u2584        \u2584\u2584       \u2584\u2584\u2584                 \n"
" \u2588\u2580\u2588\u2580\u2580\u2580\u2588\u2584     \u2588\u2588  \u2588\u2584   \u2588\u2588\u2580\u2580\u2588\u2584       \u2588\u2584      \n"
"   \u2588\u2588\u2584\u2584\u2584\u2588\u2580  \u2580\u2580\u2584\u2588\u2588\u2584\u2584\u2588\u2588\u2584  \u2588\u2588 \u2584\u2588\u2580      \u2584\u2588\u2588\u2584     \n"
"   \u2588\u2588\u2580\u2580\u2588\u2584   \u2588\u2588 \u2588\u2588  \u2588\u2588   \u2588\u2588\u2580\u2580\u2588\u2584 \u2588\u2588 \u2588\u2588 \u2588\u2588 \u2584\u2588\u2580\u2588\u2584\n"
" \u2584 \u2588\u2588  \u2588\u2588   \u2588\u2588 \u2588\u2588  \u2588\u2588 \u2584 \u2588\u2588  \u2584\u2588 \u2588\u2588\u2584\u2588\u2588 \u2588\u2588 \u2588\u2588\u2584\u2588\u2580\n"
" \u2580\u2588\u2588\u2580  \u2580\u2588\u2588\u2580\u2584\u2588\u2588\u2584\u2588\u2588 \u2584\u2588\u2588 \u2580\u2588\u2588\u2588\u2588\u2588\u2588\u2580\u2584\u2584\u2580\u2588\u2588\u2580\u2584\u2588\u2588\u2584\u2580\u2588\u2584\u2584\u2584\n"
"               \u2588\u2588                \u2588\u2588          \n"
"              \u2580\u2580               \u2580\u2580\u2580           \n"
"           Developer: Revexordd \n"
"           Telegram:  @DABHOYMEP\n"
"           TON: UQBfBXGoHIxi6qHaMg51BU83LQuMkDdib7twb4fO2t6vpwmt           \n"
"\n"
    );
}

const char* decode_opcode(uint8_t b) {
    switch (b) {
        case 0x90: return "NOP";
        case 0xCC: return "INT3";
        case 0xCD: return "INT imm8";
        case 0xC3: return "RET";
        case 0xC2: return "RETN imm16";
        case 0xCB: return "RETF";
        case 0xCA: return "RETF imm16";
        case 0xCF: return "IRET";
        case 0x88: return "MOV r/m8, r8";
        case 0x89: return "MOV r/m, r";
        case 0x8A: return "MOV r8, r/m8";
        case 0x8B: return "MOV r, r/m";
        case 0x8C: return "MOV r/m16, Sreg";
        case 0x8E: return "MOV Sreg, r/m16";
        case 0xA0: return "MOV AL, moffs8";
        case 0xA1: return "MOV EAX, moffs";
        case 0xA2: return "MOV moffs8, AL";
        case 0xA3: return "MOV moffs, EAX";
        case 0xC6: return "MOV r/m8, imm8";
        case 0xC7: return "MOV r/m, imm";
        case 0xB0: return "MOV AL, imm8";
        case 0xB1: return "MOV CL, imm8";
        case 0xB2: return "MOV DL, imm8";
        case 0xB3: return "MOV BL, imm8";
        case 0xB4: return "MOV AH, imm8";
        case 0xB5: return "MOV CH, imm8";
        case 0xB6: return "MOV DH, imm8";
        case 0xB7: return "MOV BH, imm8";
        case 0xB8: return "MOV EAX, imm";
        case 0xB9: return "MOV ECX, imm";
        case 0xBA: return "MOV EDX, imm";
        case 0xBB: return "MOV EBX, imm";
        case 0xBC: return "MOV ESP, imm";
        case 0xBD: return "MOV EBP, imm";
        case 0xBE: return "MOV ESI, imm";
        case 0xBF: return "MOV EDI, imm";
        case 0x50: return "PUSH EAX";
        case 0x51: return "PUSH ECX";
        case 0x52: return "PUSH EDX";
        case 0x53: return "PUSH EBX";
        case 0x54: return "PUSH ESP";
        case 0x55: return "PUSH EBP";
        case 0x56: return "PUSH ESI";
        case 0x57: return "PUSH EDI";
        case 0x68: return "PUSH imm";
        case 0x6A: return "PUSH imm8";
        case 0x06: return "PUSH ES";
        case 0x0E: return "PUSH CS";
        case 0x16: return "PUSH SS";
        case 0x1E: return "PUSH DS";
        case 0x58: return "POP EAX";
        case 0x59: return "POP ECX";
        case 0x5A: return "POP EDX";
        case 0x5B: return "POP EBX";
        case 0x5C: return "POP ESP";
        case 0x5D: return "POP EBP";
        case 0x5E: return "POP ESI";
        case 0x5F: return "POP EDI";
        case 0x07: return "POP ES";
        case 0x17: return "POP SS";
        case 0x1F: return "POP DS";
        case 0x8F: return "POP r/m";
        case 0x60: return "PUSHA";
        case 0x61: return "POPA";
        case 0xEB: return "JMP short";
        case 0xE9: return "JMP near";
        case 0xEA: return "JMP far ptr";
        case 0xE8: return "CALL";
        case 0x9A: return "CALL far ptr";
        case 0x70: return "JO";
        case 0x71: return "JNO";
        case 0x72: return "JB";
        case 0x73: return "JAE";
        case 0x74: return "JE";
        case 0x75: return "JNE";
        case 0x76: return "JBE";
        case 0x77: return "JA";
        case 0x78: return "JS";
        case 0x79: return "JNS";
        case 0x7A: return "JP";
        case 0x7B: return "JNP";
        case 0x7C: return "JL";
        case 0x7D: return "JGE";
        case 0x7E: return "JLE";
        case 0x7F: return "JG";
        case 0xE0: return "LOOPNE";
        case 0xE1: return "LOOPE";
        case 0xE2: return "LOOP";
        case 0xE3: return "JCXZ";
        case 0x00: return "ADD r/m8, r8";
        case 0x01: return "ADD r/m, r";
        case 0x02: return "ADD r8, r/m8";
        case 0x03: return "ADD r, r/m";
        case 0x04: return "ADD AL, imm8";
        case 0x05: return "ADD EAX, imm";
        case 0x28: return "SUB r/m8, r8";
        case 0x29: return "SUB r/m, r";
        case 0x2A: return "SUB r8, r/m8";
        case 0x2B: return "SUB r, r/m";
        case 0x2C: return "SUB AL, imm8";
        case 0x2D: return "SUB EAX, imm";
        case 0x08: return "OR r/m8, r8";
        case 0x09: return "OR r/m, r";
        case 0x0A: return "OR r8, r/m8";
        case 0x0B: return "OR r, r/m";
        case 0x0C: return "OR AL, imm8";
        case 0x0D: return "OR EAX, imm";
        case 0x20: return "AND r/m8, r8";
        case 0x21: return "AND r/m, r";
        case 0x22: return "AND r8, r/m8";
        case 0x23: return "AND r, r/m";
        case 0x24: return "AND AL, imm8";
        case 0x25: return "AND EAX, imm";
        case 0x30: return "XOR r/m8, r8";
        case 0x31: return "XOR r/m, r";
        case 0x32: return "XOR r8, r/m8";
        case 0x33: return "XOR r, r/m";
        case 0x34: return "XOR AL, imm8";
        case 0x35: return "XOR EAX, imm";
        case 0x38: return "CMP r/m8, r8";
        case 0x39: return "CMP r/m, r";
        case 0x3A: return "CMP r8, r/m8";
        case 0x3B: return "CMP r, r/m";
        case 0x3C: return "CMP AL, imm8";
        case 0x3D: return "CMP EAX, imm";
        case 0x10: return "ADC r/m8, r8";
        case 0x11: return "ADC r/m, r";
        case 0x12: return "ADC r8, r/m8";
        case 0x13: return "ADC r, r/m";
        case 0x14: return "ADC AL, imm8";
        case 0x15: return "ADC EAX, imm";
        case 0x18: return "SBB r/m8, r8";
        case 0x19: return "SBB r/m, r";
        case 0x1A: return "SBB r8, r/m8";
        case 0x1B: return "SBB r, r/m";
        case 0x1C: return "SBB AL, imm8";
        case 0x1D: return "SBB EAX, imm";
        case 0x84: return "TEST r/m8, r8";
        case 0x85: return "TEST r/m, r";
        case 0xA8: return "TEST AL, imm8";
        case 0xA9: return "TEST EAX, imm";
        case 0xF6: return "TEST/NOT/NEG/MUL/DIV r/m8";
        case 0xF7: return "TEST/NOT/NEG/MUL/DIV r/m";
        case 0x69: return "IMUL r, r/m, imm";
        case 0x6B: return "IMUL r, r/m, imm8";
        case 0x40: return "INC EAX";
        case 0x41: return "INC ECX";
        case 0x42: return "INC EDX";
        case 0x43: return "INC EBX";
        case 0x44: return "INC ESP";
        case 0x45: return "INC EBP";
        case 0x46: return "INC ESI";
        case 0x47: return "INC EDI";
        case 0x48: return "DEC EAX";
        case 0x49: return "DEC ECX";
        case 0x4A: return "DEC EDX";
        case 0x4B: return "DEC EBX";
        case 0x4C: return "DEC ESP";
        case 0x4D: return "DEC EBP";
        case 0x4E: return "DEC ESI";
        case 0x4F: return "DEC EDI";
        case 0xFE: return "INC/DEC r/m8";
        case 0xD0: return "SHL/SHR r/m8, 1";
        case 0xD1: return "SHL/SHR r/m, 1";
        case 0xD2: return "SHL/SHR r/m8, CL";
        case 0xD3: return "SHL/SHR r/m, CL";
        case 0xC0: return "SHL/SHR r/m8, imm8";
        case 0xC1: return "SHL/SHR r/m, imm8";
        case 0x9C: return "PUSHF";
        case 0x9D: return "POPF";
        case 0xF5: return "CMC";
        case 0xF8: return "CLC";
        case 0xF9: return "STC";
        case 0xFA: return "CLI";
        case 0xFB: return "STI";
        case 0xFC: return "CLD";
        case 0xFD: return "STD";
        case 0xA4: return "MOVSB";
        case 0xA5: return "MOVSD";
        case 0xAA: return "STOSB";
        case 0xAB: return "STOSD";
        case 0xAC: return "LODSB";
        case 0xAD: return "LODSD";
        case 0xAE: return "SCASB";
        case 0xAF: return "SCASD";
        case 0xA6: return "CMPSB";
        case 0xA7: return "CMPSD";
        case 0x80: return "ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m8, imm8";
        case 0x81: return "ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm";
        case 0x83: return "ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm8";
        case 0x86: return "XCHG r/m8, r8";
        case 0x87: return "XCHG r/m, r";
        case 0x91: return "XCHG ECX, EAX";
        case 0x92: return "XCHG EDX, EAX";
        case 0x93: return "XCHG EBX, EAX";
        case 0x94: return "XCHG ESP, EAX";
        case 0x95: return "XCHG EBP, EAX";
        case 0x96: return "XCHG ESI, EAX";
        case 0x97: return "XCHG EDI, EAX";
        case 0x98: return "CWDE";
        case 0x99: return "CDQ";
        case 0x9B: return "WAIT/FWAIT";
        case 0x9E: return "SAHF";
        case 0x9F: return "LAHF";
        case 0xC4: return "LES r, m16:32";
        case 0xC5: return "LDS r, m16:32";
        case 0xC8: return "ENTER imm16, imm8";
        case 0xC9: return "LEAVE";
        case 0xD4: return "AAM";
        case 0xD5: return "AAD";
        case 0xD6: return "SALC";
        case 0xD7: return "XLAT";
        case 0xE4: return "IN AL, imm8";
        case 0xE5: return "IN EAX, imm8";
        case 0xE6: return "OUT imm8, AL";
        case 0xE7: return "OUT imm8, EAX";
        case 0xEC: return "IN AL, DX";
        case 0xED: return "IN EAX, DX";
        case 0xEE: return "OUT DX, AL";
        case 0xEF: return "OUT DX, EAX";
        case 0x62: return "BOUND r, m";
        case 0x63: return "ARPL r/m16, r16";
        case 0x64: return "FS: prefix";
        case 0x65: return "GS: prefix";
        case 0x67: return "ADDR SIZE PREFIX";
        case 0x0F: return "0F PREFIX";
        case 0xF3: return "REP";
        case 0xF2: return "REPNE";
        case 0x66: return "OPERAND SIZE PREFIX";
        case 0x26: return "ES: prefix";
        case 0x2E: return "CS: prefix";
        case 0x36: return "SS: prefix";
        case 0x3E: return "DS: prefix";
        case 0xF0: return "LOCK prefix";
        case 0xF1: return "INT1";
        case 0xF4: return "HLT";
        case 0xFF: return "CALL/JMP/PUSH group";
        case 0x8D: return "LEA r, m";
        default:   return "UNK";
    }
}

const char* decode_0f(uint8_t b) {
    switch (b) {
        case 0x80: return "JO near";
        case 0x81: return "JNO near";
        case 0x82: return "JB near";
        case 0x83: return "JAE near";
        case 0x84: return "JE near";
        case 0x85: return "JNE near";
        case 0x86: return "JBE near";
        case 0x87: return "JA near";
        case 0x88: return "JS near";
        case 0x89: return "JNS near";
        case 0x8A: return "JP near";
        case 0x8B: return "JNP near";
        case 0x8C: return "JL near";
        case 0x8D: return "JGE near";
        case 0x8E: return "JLE near";
        case 0x8F: return "JG near";
        case 0x40: return "CMOVO";
        case 0x41: return "CMOVNO";
        case 0x42: return "CMOVB";
        case 0x43: return "CMOVAE";
        case 0x44: return "CMOVE";
        case 0x45: return "CMOVNE";
        case 0x46: return "CMOVBE";
        case 0x47: return "CMOVA";
        case 0x48: return "CMOVS";
        case 0x49: return "CMOVNS";
        case 0x4A: return "CMOVP";
        case 0x4B: return "CMOVNP";
        case 0x4C: return "CMOVL";
        case 0x4D: return "CMOVGE";
        case 0x4E: return "CMOVLE";
        case 0x4F: return "CMOVG";
        case 0x90: return "SETO";
        case 0x91: return "SETNO";
        case 0x92: return "SETB";
        case 0x93: return "SETAE";
        case 0x94: return "SETE";
        case 0x95: return "SETNE";
        case 0x96: return "SETBE";
        case 0x97: return "SETA";
        case 0x98: return "SETS";
        case 0x99: return "SETNS";
        case 0x9A: return "SETP";
        case 0x9B: return "SETNP";
        case 0x9C: return "SETL";
        case 0x9D: return "SETGE";
        case 0x9E: return "SETLE";
        case 0x9F: return "SETG";
        case 0xA3: return "BT r/m, r";
        case 0xAB: return "BTS r/m, r";
        case 0xB3: return "BTR r/m, r";
        case 0xBB: return "BTC r/m, r";
        case 0xBA: return "BT/BTS/BTR/BTC r/m, imm8";
        case 0xBC: return "BSF r, r/m";
        case 0xBD: return "BSR r, r/m";
        case 0xB6: return "MOVZX r, r/m8";
        case 0xB7: return "MOVZX r, r/m16";
        case 0xBE: return "MOVSX r, r/m8";
        case 0xBF: return "MOVSX r, r/m16";
        case 0xB8: return "POPCNT r, r/m";
        case 0x01: return "LGDT/LIDT/LLDT (group)";
        case 0x31: return "RDTSC";
        case 0x32: return "RDMSR";
        case 0x33: return "RDPMC";
        case 0x30: return "WRMSR";
        case 0xA2: return "CPUID";
        case 0xA0: return "PUSH FS";
        case 0xA1: return "POP FS";
        case 0xA8: return "PUSH GS";
        case 0xA9: return "POP GS";
        case 0xA4: return "SHLD imm8";
        case 0xA5: return "SHLD CL";
        case 0xAC: return "SHRD imm8";
        case 0xAD: return "SHRD CL";
        case 0x00: return "SLDT/STR/LLDT/LTR/VERR/VERW (group)";
        case 0x02: return "LAR r, r/m16";
        case 0x03: return "LSL r, r/m16";
        case 0x05: return "SYSCALL";
        case 0x06: return "CLTS";
        case 0x07: return "SYSRET";
        case 0x08: return "INVD";
        case 0x09: return "WBINVD";
        case 0x0B: return "UD2";
        case 0x0D: return "PREFETCHW";
        case 0x18: return "PREFETCH group";
        case 0x19: return "NOP r/m (multi-byte)";
        case 0x1F: return "NOP r/m (long)";
        case 0x20: return "MOV r, CRn";
        case 0x21: return "MOV r, DRn";
        case 0x22: return "MOV CRn, r";
        case 0x23: return "MOV DRn, r";
        case 0x34: return "SYSENTER";
        case 0x35: return "SYSEXIT";
        case 0xAE: return "FXSAVE/FXRSTOR/LDMXCSR/STMXCSR/SFENCE/LFENCE/MFENCE";
        case 0xAF: return "IMUL r, r/m";
        case 0xB0: return "CMPXCHG r/m8, r8";
        case 0xB1: return "CMPXCHG r/m, r";
        case 0xC0: return "XADD r/m8, r8";
        case 0xC1: return "XADD r/m, r";
        case 0xC7: return "CMPXCHG8B/CMPXCHG16B m";
        case 0xC8: return "BSWAP EAX";
        case 0xC9: return "BSWAP ECX";
        case 0xCA: return "BSWAP EDX";
        case 0xCB: return "BSWAP EBX";
        case 0xCC: return "BSWAP ESP";
        case 0xCD: return "BSWAP EBP";
        case 0xCE: return "BSWAP ESI";
        case 0xCF: return "BSWAP EDI";
        case 0x10: return "MOVUPS xmm, xmm/m128";
        case 0x11: return "MOVUPS xmm/m128, xmm";
        case 0x12: return "MOVLPS xmm, m64";
        case 0x13: return "MOVLPS m64, xmm";
        case 0x14: return "UNPCKLPS xmm, xmm/m128";
        case 0x15: return "UNPCKHPS xmm, xmm/m128";
        case 0x16: return "MOVHPS xmm, m64";
        case 0x17: return "MOVHPS m64, xmm";
        case 0x28: return "MOVAPS xmm, xmm/m128";
        case 0x29: return "MOVAPS xmm/m128, xmm";
        case 0x2A: return "CVTPI2PS xmm, mm/m64";
        case 0x2B: return "MOVNTPS m128, xmm";
        case 0x2C: return "CVTTPS2PI mm, xmm/m64";
        case 0x2D: return "CVTPS2PI mm, xmm/m64";
        case 0x2E: return "UCOMISS xmm, xmm/m32";
        case 0x2F: return "COMISS xmm, xmm/m32";
        case 0x50: return "MOVMSKPS r, xmm";
        case 0x51: return "SQRTPS xmm, xmm/m128";
        case 0x52: return "RSQRTPS xmm, xmm/m128";
        case 0x53: return "RCPPS xmm, xmm/m128";
        case 0x54: return "ANDPS xmm, xmm/m128";
        case 0x55: return "ANDNPS xmm, xmm/m128";
        case 0x56: return "ORPS xmm, xmm/m128";
        case 0x57: return "XORPS xmm, xmm/m128";
        case 0x58: return "ADDPS xmm, xmm/m128";
        case 0x59: return "MULPS xmm, xmm/m128";
        case 0x5A: return "CVTPS2PD xmm, xmm/m64";
        case 0x5B: return "CVTDQ2PS xmm, xmm/m128";
        case 0x5C: return "SUBPS xmm, xmm/m128";
        case 0x5D: return "MINPS xmm, xmm/m128";
        case 0x5E: return "DIVPS xmm, xmm/m128";
        case 0x5F: return "MAXPS xmm, xmm/m128";
        case 0x60: return "PUNPCKLBW mm, mm/m32";
        case 0x61: return "PUNPCKLWD mm, mm/m32";
        case 0x62: return "PUNPCKLDQ mm, mm/m32";
        case 0x63: return "PACKSSWB mm, mm/m64";
        case 0x64: return "PCMPGTB mm, mm/m64";
        case 0x65: return "PCMPGTW mm, mm/m64";
        case 0x66: return "PCMPGTD mm, mm/m64";
        case 0x67: return "PACKUSWB mm, mm/m64";
        case 0x68: return "PUNPCKHBW mm, mm/m64";
        case 0x69: return "PUNPCKHWD mm, mm/m64";
        case 0x6A: return "PUNPCKHDQ mm, mm/m64";
        case 0x6B: return "PACKSSDW mm, mm/m64";
        case 0x6E: return "MOVD mm, r/m32";
        case 0x6F: return "MOVQ mm, mm/m64";
        case 0x70: return "PSHUFW mm, mm/m64, imm8";
        case 0x74: return "PCMPEQB mm, mm/m64";
        case 0x75: return "PCMPEQW mm, mm/m64";
        case 0x76: return "PCMPEQD mm, mm/m64";
        case 0x77: return "EMMS";
        case 0x7E: return "MOVD r/m32, mm";
        case 0x7F: return "MOVQ mm/m64, mm";
        case 0xD1: return "PSRLW mm, mm/m64";
        case 0xD2: return "PSRLD mm, mm/m64";
        case 0xD3: return "PSRLQ mm, mm/m64";
        case 0xD4: return "PADDQ mm, mm/m64";
        case 0xD5: return "PMULLW mm, mm/m64";
        case 0xD7: return "PMOVMSKB r, mm";
        case 0xD8: return "PSUBUSB mm, mm/m64";
        case 0xD9: return "PSUBUSW mm, mm/m64";
        case 0xDA: return "PMINUB mm, mm/m64";
        case 0xDB: return "PAND mm, mm/m64";
        case 0xDC: return "PADDUSB mm, mm/m64";
        case 0xDD: return "PADDUSW mm, mm/m64";
        case 0xDE: return "PMAXUB mm, mm/m64";
        case 0xDF: return "PANDN mm, mm/m64";
        case 0xE0: return "PAVGB mm, mm/m64";
        case 0xE1: return "PSRAW mm, mm/m64";
        case 0xE2: return "PSRAD mm, mm/m64";
        case 0xE3: return "PAVGW mm, mm/m64";
        case 0xE4: return "PMULHUW mm, mm/m64";
        case 0xE5: return "PMULHW mm, mm/m64";
        case 0xE7: return "MOVNTQ m64, mm";
        case 0xE8: return "PSUBSB mm, mm/m64";
        case 0xE9: return "PSUBSW mm, mm/m64";
        case 0xEA: return "PMINSW mm, mm/m64";
        case 0xEB: return "POR mm, mm/m64";
        case 0xEC: return "PADDSB mm, mm/m64";
        case 0xED: return "PADDSW mm, mm/m64";
        case 0xEE: return "PMAXSW mm, mm/m64";
        case 0xEF: return "PXOR mm, mm/m64";
        case 0xF1: return "PSLLW mm, mm/m64";
        case 0xF2: return "PSLLD mm, mm/m64";
        case 0xF3: return "PSLLQ mm, mm/m64";
        case 0xF4: return "PMULUDQ mm, mm/m64";
        case 0xF5: return "PMADDWD mm, mm/m64";
        case 0xF6: return "PSADBW mm, mm/m64";
        case 0xF7: return "MASKMOVQ mm, mm";
        case 0xF8: return "PSUBB mm, mm/m64";
        case 0xF9: return "PSUBW mm, mm/m64";
        case 0xFA: return "PSUBD mm, mm/m64";
        case 0xFB: return "PSUBQ mm, mm/m64";
        case 0xFC: return "PADDB mm, mm/m64";
        case 0xFD: return "PADDW mm, mm/m64";
        case 0xFE: return "PADDD mm, mm/m64";
        default:   return "UNK_0F";
    }
}

const char* smart_decode(uint8_t* buf, size_t i, size_t size) {
    if (buf[i] == 0x0F && i + 1 < size)
        return decode_0f(buf[i + 1]);
    return decode_opcode(buf[i]);
}

#define CLR_RESET  "\033[0m"
#define CLR_CYAN   "\033[96m"
#define CLR_RED    "\033[91m"
#define CLR_YELLOW "\033[93m"
#define CLR_WHITE  "\033[97m"
#define CLR_GREY   "\033[90m"
#define CLR_GREEN  "\033[92m"


const char* sec_name_at_rva(uint32_t rva) {
    for (int i = 0; i < secCount; i++) {
        uint32_t va   = sections[i].VirtualAddress;
        uint32_t size = sections[i].VirtualSize ? sections[i].VirtualSize : sections[i].SizeOfRawData;
        if (rva >= va && rva < va + size) {
            static char name[16];
            int n = 0;
            /* PE section names are null-padded up to 8 bytes */
            for (n = 0; n < 8 && sections[i].name[n] != '\0'; n++)
                name[n] = sections[i].name[n];
            name[n] = '\0';
            return name[0] ? name : "?";
        }
    }
    /* rva falls in the PE header (before any section) */
    if (secCount > 0 && rva < sections[0].VirtualAddress)
        return "header";
    return "?";
}

static int is_jump_or_call(uint8_t b) {
    return (b == 0xE8 || b == 0xE9 || b == 0xEB ||
            (b >= 0x70 && b <= 0x7F));
}

/* Compute jump/call target; returns 1 if resolved */
static int get_jump_target(uint8_t* buf, size_t i, size_t r, uint64_t va, uint64_t* out) {
    uint8_t op = buf[i];
    if ((op == 0xE8 || op == 0xE9) && i + 4 < r) {
        int32_t rel;
        memcpy(&rel, buf + i + 1, 4);
        *out = va + 5 + (int64_t)rel;
        return 1;
    } else if (op == 0xEB && i + 1 < r) {
        *out = va + 2 + (int64_t)(int8_t)buf[i + 1];
        return 1;
    } else if (op >= 0x70 && op <= 0x7F && i + 1 < r) {
        *out = va + 2 + (int64_t)(int8_t)buf[i + 1];
        return 1;
    }
    return 0;
}

static void print_jump_target(uint8_t* buf, size_t i, size_t r, uint64_t va) {
    uint64_t target = 0;
    if (get_jump_target(buf, i, r, va, &target))
        printf(CLR_GREY "  jump target: " CLR_YELLOW "%016llX" CLR_RESET "\n",
               (unsigned long long)target);
}

uint32_t file_to_rva(uint32_t off) {
    for (int i = 0; i < secCount; i++) {
        uint32_t raw  = sections[i].PointerToRawData;
        uint32_t size = sections[i].SizeOfRawData;
        if (off >= raw && off < raw + size)
            return sections[i].VirtualAddress + (off - raw);
    }
    return off;
}

uint64_t rva_to_va(uint32_t rva) { return imageBase + rva; }

uint64_t elf_file_to_va(uint64_t off) {
    for (int i = 0; i < elfSecCount; i++) {
        uint64_t fo   = elfSections[i].file_off;
        uint64_t size = elfSections[i].size;
        if (off >= fo && off < fo + size)
            return elfSections[i].va + (off - fo);
    }
    return off;
}

const char* elf_sec_name_at(uint64_t va) {
    for (int i = 0; i < elfSecCount; i++) {
        if (va >= elfSections[i].va && va < elfSections[i].va + elfSections[i].size)
            return elfSections[i].name;
    }
    return "?";
}

/* ===== .NET DETECTION ===== */

/*
 * Method 1: COM Descriptor data directory (directory entry 14).
 * PE32  -> data dirs start at opt_header + 96
 * PE32+ -> data dirs start at opt_header + 112
 * Entry 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
 * Non-zero RVA + Size = managed .NET assembly.
 */
static int check_dotnet_dir(FILE *f, long pe_off, uint16_t magic) {
    long opt_start  = pe_off + 24L;
    long dd_start   = opt_start + (magic == 0x20B ? 112 : 96);
    long com_offset = dd_start + 14 * 8;

    if (fseek(f, com_offset, SEEK_SET) != 0) return 0;

    uint32_t rva = 0, sz = 0;
    if (fread(&rva, 4, 1, f) != 1) return 0;
    if (fread(&sz,  4, 1, f) != 1) return 0;

    return (rva != 0 && sz != 0);
}

/*
 * Method 2: Scan for CLR/MSIL byte signatures in the file body.
 * Used as a SECONDARY hint only — never as sole proof.
 * These strings appear in .NET metadata streams and section data.
 *
 * Fixed bugs vs original:
 *  - carry buffer built from the *merged* tmp[], not raw buf[],
 *    so boundary bytes are always correct.
 *  - added null-check on fopen result path.
 *  - sigs table and NSIGS driven by one array so they can't desync.
 */
static int check_dotnet_sigs(const char *path) {
    static const struct { const char *str; int len; } sigs[] = {
        { "MSCorLib",            8  },
        { ".NETFramework",       13 },  /* was 14 — off-by-one fixed */
        { ".NETCore",            8  },
        { "Microsoft.DotNet",    16 },
        { "runtime.core",        12 },
        { "mscorlib",            8  },  /* lowercase variant */
        { "MSCOREE.DLL",         11 },  /* import seen in all .NET stubs */
        { "_CorExeMain",         12 },  /* entry-point thunk */
        { "_CorDllMain",         12 },  /* DLL variant */
    };
    static const int NSIGS    = (int)(sizeof(sigs) / sizeof(sigs[0]));
    static const int MAX_SIG  = 16;    /* length of longest sig */

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint8_t  buf[8192];
    uint8_t  carry[32] = {0};
    int      carry_len = 0;
    int      found     = 0;

    while (!found) {
        size_t r = fread(buf, 1, sizeof(buf), f);
        if (!r) break;

        /* merge carry + new chunk */
        uint8_t tmp[8192 + 32];
        memcpy(tmp, carry, carry_len);
        memcpy(tmp + carry_len, buf, r);
        size_t total = (size_t)carry_len + r;

        for (int s = 0; s < NSIGS && !found; s++) {
            int slen = sigs[s].len;
            for (size_t i = 0; i + (size_t)slen <= total && !found; i++) {
                if (memcmp(tmp + i, sigs[s].str, (size_t)slen) == 0)
                    found = 1;
            }
        }

        /* carry = last (MAX_SIG-1) bytes of the MERGED window */
        int new_carry = MAX_SIG - 1;
        if ((int)total >= new_carry) {
            memcpy(carry, tmp + total - new_carry, new_carry);
            carry_len = new_carry;
        } else {
            memcpy(carry, tmp, total);
            carry_len = (int)total;
        }
    }

    fclose(f);
    return found;
}

/* LOADERS  */

int load_pe(const char *file) {
    FILE *f = fopen(file, "rb");
    if (!f) return 0;

    DOS dos;
    fread(&dos, sizeof(dos), 1, f);
    fseek(f, dos.e_lfanew, SEEK_SET);

    PE pe;
    fread(&pe, sizeof(pe), 1, f);
    /* now positioned at optional header start */

    if (pe.characteristics & 0x2000) isDll = 1;

    switch (pe.machine) {
        case MACHINE_AMD64: is64bit = 1; isArm = 0; break;
        case MACHINE_ARM64: is64bit = 1; isArm = 1; break;
        case MACHINE_ARM:
        case MACHINE_ARMNT: is64bit = 0; isArm = 1; break;
        default:            is64bit = 0; isArm = 0; break;
    }

    long opt_start = dos.e_lfanew + (long)sizeof(PE); /* start of optional header */

    fseek(f, opt_start, SEEK_SET);
    uint16_t magic = 0;
    fread(&magic, 2, 1, f);

    fseek(f, opt_start + 16, SEEK_SET);
    uint32_t ep_rva = 0;
    fread(&ep_rva, 4, 1, f);

    if (magic == 0x20B) {
        /* PE32+: ImageBase at opt + 24, 8 bytes */
        is64bit = 1;
        fseek(f, opt_start + 24, SEEK_SET);
        uint64_t imgBase = 0;
        fread(&imgBase, 8, 1, f);
        imageBase = imgBase;
    } else {
        /* PE32:  ImageBase at opt + 28, 4 bytes */
        fseek(f, opt_start + 28, SEEK_SET);
        uint32_t imgBase = 0;
        fread(&imgBase, 4, 1, f);
        imageBase = (uint64_t)imgBase;
    }

    entryPoint = imageBase + (uint64_t)ep_rva;

    /*.NET detection: data directory first, then sig scan */
    isDotNet = check_dotnet_dir(f, dos.e_lfanew, magic);
    if (!isDotNet) isDotNet = check_dotnet_sigs(file);

    /* sections  */
    long sec_table_off = dos.e_lfanew + 0x18 + pe.optsize;
    fseek(f, sec_table_off, SEEK_SET);
    secCount = pe.sections;
    if (secCount > 64) secCount = 64;
    fread(sections, sizeof(SEC), secCount, f);

    fileFormat = FMT_PE;
    fclose(f);
    return 1;
}

int load_elf(const char *file) {
    FILE *f = fopen(file, "rb");
    if (!f) return 0;

    uint8_t ident[16];
    fread(ident, 1, 16, f);
    rewind(f);

    if (ident[4] == 2) {
        is64bit = 1;
        ELF64HDR hdr;
        fread(&hdr, sizeof(hdr), 1, f);
        imageBase  = 0;          /* ELF has no fixed image base */
        entryPoint = hdr.e_entry;

        switch (hdr.e_machine) {
            case 0xB7: case 0x28: isArm = 1; break;
            default:              isArm = 0; break;
        }

        if (hdr.e_shoff == 0 || hdr.e_shnum == 0) { fclose(f); return 1; }

        ELF64SHDR shstr;
        fseek(f, hdr.e_shoff + (uint64_t)hdr.e_shstrndx * hdr.e_shentsize, SEEK_SET);
        fread(&shstr, sizeof(shstr), 1, f);

        char strtab[4096] = {0};
        uint64_t strsz = shstr.sh_size < 4096 ? shstr.sh_size : 4095;
        fseek(f, shstr.sh_offset, SEEK_SET);
        fread(strtab, 1, strsz, f);

        int n = hdr.e_shnum < 64 ? hdr.e_shnum : 64;
        for (int i = 0; i < n; i++) {
            ELF64SHDR sh;
            fseek(f, hdr.e_shoff + (uint64_t)i * hdr.e_shentsize, SEEK_SET);
            fread(&sh, sizeof(sh), 1, f);
            if (sh.sh_addr == 0) continue;
            strncpy(elfSections[elfSecCount].name, strtab + sh.sh_name, 31);
            elfSections[elfSecCount].name[31] = 0;
            if (elfSections[elfSecCount].name[0] == 0)
                snprintf(elfSections[elfSecCount].name, 32, "sec%d", i);
            elfSections[elfSecCount].va       = sh.sh_addr;
            elfSections[elfSecCount].size     = sh.sh_size;
            elfSections[elfSecCount].file_off = sh.sh_offset;
            elfSecCount++;
        }
    } else {
        is64bit = 0;
        ELF32HDR hdr;
        fread(&hdr, sizeof(hdr), 1, f);
        imageBase  = 0;
        entryPoint = (uint64_t)hdr.e_entry;

        switch (hdr.e_machine) {
            case 0x28: isArm = 1; break;
            default:   isArm = 0; break;
        }

        if (hdr.e_shoff == 0 || hdr.e_shnum == 0) { fclose(f); return 1; }

        ELF32SHDR shstr;
        fseek(f, hdr.e_shoff + (uint32_t)hdr.e_shstrndx * hdr.e_shentsize, SEEK_SET);
        fread(&shstr, sizeof(shstr), 1, f);

        char strtab[4096] = {0};
        uint32_t strsz = shstr.sh_size < 4096 ? shstr.sh_size : 4095;
        fseek(f, shstr.sh_offset, SEEK_SET);
        fread(strtab, 1, strsz, f);

        int n = hdr.e_shnum < 64 ? hdr.e_shnum : 64;
        for (int i = 0; i < n; i++) {
            ELF32SHDR sh;
            fseek(f, hdr.e_shoff + (uint32_t)i * hdr.e_shentsize, SEEK_SET);
            fread(&sh, sizeof(sh), 1, f);
            if (sh.sh_addr == 0) continue;
            strncpy(elfSections[elfSecCount].name, strtab + sh.sh_name, 31);
            elfSections[elfSecCount].name[31] = 0;
            if (elfSections[elfSecCount].name[0] == 0)
                snprintf(elfSections[elfSecCount].name, 32, "sec%d", i);
            elfSections[elfSecCount].va       = (uint64_t)sh.sh_addr;
            elfSections[elfSecCount].size     = (uint64_t)sh.sh_size;
            elfSections[elfSecCount].file_off = (uint64_t)sh.sh_offset;
            elfSecCount++;
        }
    }

    fileFormat = FMT_ELF;
    fclose(f);
    return 1;
}

int detect_and_load(const char *file) {
    FILE *f = fopen(file, "rb");
    if (!f) return 0;
    uint8_t magic[4] = {0};
    fread(magic, 1, 4, f);
    fclose(f);

    if (magic[0] == 'M' && magic[1] == 'Z')
        return load_pe(file);
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return load_elf(file);

    printf("unknown format (not PE or ELF)\n");
    return 0;
}

static int get_ep_from_file(const char *file, uint64_t *ep_out, uint64_t *base_out) {
    FILE *f = fopen(file, "rb");
    if (!f) return 0;

    uint8_t magic4[4] = {0};
    fread(magic4, 1, 4, f);
    fseek(f, 0, SEEK_SET);

    /* ----- PE ----- */
    if (magic4[0] == 'M' && magic4[1] == 'Z') {
        DOS dos;
        fread(&dos, sizeof(dos), 1, f);
        fseek(f, dos.e_lfanew + (long)sizeof(PE), SEEK_SET);

        uint16_t opt_magic = 0;
        fread(&opt_magic, 2, 1, f);

        long opt_start = dos.e_lfanew + (long)sizeof(PE);

        /* AddressOfEntryPoint at opt+16 */
        fseek(f, opt_start + 16, SEEK_SET);
        uint32_t ep_rva = 0;
        fread(&ep_rva, 4, 1, f);

        uint64_t imgBase = 0;
        if (opt_magic == 0x20B) {
            fseek(f, opt_start + 24, SEEK_SET);
            fread(&imgBase, 8, 1, f);
        } else {
            fseek(f, opt_start + 28, SEEK_SET);
            uint32_t ib32 = 0;
            fread(&ib32, 4, 1, f);
            imgBase = (uint64_t)ib32;
        }

        *base_out = imgBase;
        *ep_out   = imgBase + (uint64_t)ep_rva;
        fclose(f);
        return 1;
    }

    if (magic4[0] == 0x7F && magic4[1] == 'E' &&
        magic4[2] == 'L'  && magic4[3] == 'F') {
        uint8_t ident[16];
        fread(ident, 1, 16, f);
        fseek(f, 0, SEEK_SET);

        *base_out = 0;
        if (ident[4] == 2) {
            ELF64HDR hdr;
            fread(&hdr, sizeof(hdr), 1, f);
            *ep_out = hdr.e_entry;
        } else {
            ELF32HDR hdr;
            fread(&hdr, sizeof(hdr), 1, f);
            *ep_out = (uint64_t)hdr.e_entry;
        }
        fclose(f);
        return 1;
    }

    fclose(f);
    return 0;
}

static void log_add(const char *sec, uint64_t va, uint64_t file_off,
                    const char *bop, const char *aop,
                    const char *bb,  const char *ab,
                    const uint8_t *rb, const uint8_t *ra, int rlen,
                    int has_jump, uint64_t jump_target)
{
    if (gLogCount >= MAX_LOG) return;
    LogEntry *e = &gLog[gLogCount++];
    strncpy(e->sec,          sec,  31);  e->sec[31]          = 0;
    strncpy(e->before_op,    bop,  63);  e->before_op[63]    = 0;
    strncpy(e->after_op,     aop,  63);  e->after_op[63]     = 0;
    strncpy(e->before_bytes, bb,  4095); e->before_bytes[4095] = 0;
    strncpy(e->after_bytes,  ab,  4095); e->after_bytes[4095]  = 0;
    if (rlen > MAX_PATCH_BYTES) rlen = MAX_PATCH_BYTES;
    memcpy(e->raw_before, rb, (size_t)rlen);
    memcpy(e->raw_after,  ra, (size_t)rlen);
    e->raw_len     = rlen;
    e->va          = va;
    e->file_off    = file_off;
    e->has_jump    = has_jump;
    e->jump_target = jump_target;
}

static void save_log_to_file(const char *file1, const char *file2) {
    /* MM_DD_YYYY_HH_MM_SS.txt */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char fname[64];
    strftime(fname, sizeof(fname), "%m_%d_%Y_%H_%M_%S.txt", t);

    FILE *out = fopen(fname, "w");
    if (!out) {
        printf("  [!] Could not create log file: %s\n", fname);
        return;
    }

    char timestr[32];
    strftime(timestr, sizeof(timestr), "%m/%d/%Y %H:%M:%S", t);
    fprintf(out, "RiftByte Diff Log -- %s\n", timestr);
    fprintf(out, "Original : %s\n", file1);
    fprintf(out, "Compared : %s\n", file2);

    const char *arch_str;
    if      (isArm && is64bit)  arch_str = "ARM64";
    else if (isArm && !is64bit) arch_str = "ARM32";
    else if (is64bit)           arch_str = "x64";
    else                        arch_str = "x32";

    const char *fmt_str = (fileFormat == FMT_ELF) ? "ELF" : (isDll ? "DLL" : "EXE");

    if (is64bit) {
        fprintf(out,
            "\n[Original]  [ %s | %s ]  ImageBase: %016llX  EntryPoint: %016llX\n",
            arch_str, fmt_str,
            (unsigned long long)imageBase,
            (unsigned long long)entryPoint);
        fprintf(out,
            "[Compared]                          ImageBase: %016llX  EntryPoint: %016llX\n",
            (unsigned long long)imageBase2,
            (unsigned long long)entryPoint2);
    } else {
        fprintf(out,
            "\n[Original]  [ %s | %s ]  ImageBase: %08llX  EntryPoint: %08llX\n",
            arch_str, fmt_str,
            (unsigned long long)imageBase,
            (unsigned long long)entryPoint);
        fprintf(out,
            "[Compared]                          ImageBase: %08llX  EntryPoint: %08llX\n",
            (unsigned long long)imageBase2,
            (unsigned long long)entryPoint2);
    }

    if (isDotNet) fprintf(out, "[ .NET ]\n");

    if (gLogCount == 0) {
        fprintf(out, "  [+] No differences found.\n");
    } else {
        fprintf(out, " lOG  - %d entr%s\n", gLogCount, gLogCount == 1 ? "y" : "ies");

        for (int i = 0; i < gLogCount; i++) {
            LogEntry *e = &gLog[i];
            if (is64bit) {
                fprintf(out,
                    "#%04d [%-8s]  VA:%016llX  OFF:0x%016llX\n",
                    i + 1, e->sec,
                    (unsigned long long)e->va,
                    (unsigned long long)e->file_off);
            } else {
                fprintf(out,
                    "#%04d [%-8s]  VA:%08llX  OFF:0x%08llX\n",
                    i + 1, e->sec,
                    (unsigned long long)e->va,
                    (unsigned long long)e->file_off);
            }
            fprintf(out, "       %-30s -> %-30s\n", e->before_op, e->after_op);
            fprintf(out, "       %-48s -> %s\n",    e->before_bytes, e->after_bytes);
            if (e->has_jump)
                fprintf(out, "       jump target: %016llX\n",
                        (unsigned long long)e->jump_target);
            fprintf(out, "\n");
        }
    }

    fprintf(out,
        "  Total: %d difference%s\n",
        gLogCount, gLogCount == 1 ? "" : "s");

    fclose(out);
    printf(CLR_GREEN "  [+] Log saved to: " CLR_WHITE "%s\n" CLR_RESET, fname);
}

static const char *basename_only(const char *path) {
    const char *p = path;
    const char *last = path;
    while (*p) {
        if (*p == '/' || *p == '\\') last = p + 1;
        p++;
    }
    return last;
}

static void save_1337(const char *file1) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char fname[64];
    strftime(fname, sizeof(fname), "%m_%d_%Y_%H_%M_%S.1337", t);

    FILE *out = fopen(fname, "w");
    if (!out) {
        printf("  [!] Could not create .1337 file: %s\n", fname);
        return;
    }

    fprintf(out, ">%s\n", basename_only(file1));

    for (int i = 0; i < gLogCount; i++) {
        LogEntry *e = &gLog[i];

        for (int k = 0; k < e->raw_len; k++) {
            uint8_t b = e->raw_before[k];
            uint8_t a = e->raw_after[k];
            if (b == a) continue;

            /* RVA = VA - ImageBase; for x64dbg .1337 uses */
            uint64_t rva = (e->va + (uint64_t)k) - imageBase;

            if (is64bit)
                fprintf(out, "%016llX:%02X->%02X\n", (unsigned long long)rva, b, a);
            else
                fprintf(out, "%08llX:%02X->%02X\n", (unsigned long long)rva, b, a);
        }
    }

    fclose(out);
    printf(CLR_GREEN "  [+] Patch saved to: " CLR_WHITE "%s\n" CLR_RESET, fname);
}

static void print_log_summary(void) {
    if (gLogCount == 0) {
        printf(CLR_GREEN "\n  [+] No differences found.\n" CLR_RESET);
        return;
    }

    printf("\n");
    printf(CLR_WHITE
           "  LOG  - %d entr%s\n"
           CLR_RESET,
           gLogCount, gLogCount == 1 ? "y" : "ies");

    for (int i = 0; i < gLogCount; i++) {
        LogEntry *e = &gLog[i];

        if (is64bit) {
            printf(CLR_GREY "#%04d [" CLR_GREY "%-8s" CLR_GREY "]"
                   "  VA:" CLR_YELLOW "%016llX"
                   CLR_GREY "  OFF:0x%016llX\n" CLR_RESET,
                   i + 1, e->sec,
                   (unsigned long long)e->va,
                   (unsigned long long)e->file_off);
        } else {
            printf(CLR_GREY "#%04d [" CLR_GREY "%-8s" CLR_GREY "]"
                   "  VA:" CLR_YELLOW "%08llX"
                   CLR_GREY "  OFF:0x%08llX\n" CLR_RESET,
                   i + 1, e->sec,
                   (unsigned long long)e->va,
                   (unsigned long long)e->file_off);
        }

        printf("       " CLR_CYAN "%-30s" CLR_GREY " -> " CLR_CYAN "%-30s" CLR_RESET "\n",
               e->before_op, e->after_op);
        printf("       " CLR_RED "%-48s" CLR_GREY "-> " CLR_RED "%s" CLR_RESET "\n",
               e->before_bytes, e->after_bytes);

        if (e->has_jump)
            printf("       " CLR_GREY "jump target: " CLR_YELLOW "%016llX\n" CLR_RESET,
                   (unsigned long long)e->jump_target);
    }

    printf(CLR_WHITE
           "  Total: %d difference%s\n"
           CLR_RESET,
           gLogCount, gLogCount == 1 ? "" : "s");
}

int main(int argc, char **argv) {
#ifdef _WIN32
    SetConsoleOutputCP(65001); /* UTF-8 */
    SetConsoleCP(65001);
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            GetConsoleMode(hOut, &dwMode);
            dwMode |= 0x0004; /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
    banner();

    if (argc != 3) {
        printf("usage: RiftByte <original> <patched>\n");
        return 1;
    }

    if (!detect_and_load(argv[1])) {
        printf("failed to parse file\n");
        return 1;
    }

    if (!get_ep_from_file(argv[2], &entryPoint2, &imageBase2)) {
        printf("  [!] Could not read EP from comparison file (will show 0)\n");
    }

    const char *arch_str;
    if      (isArm && is64bit)  arch_str = "ARM64";
    else if (isArm && !is64bit) arch_str = "ARM32";
    else if (is64bit)           arch_str = "x64";
    else                        arch_str = "x32";

    const char *fmt_str = (fileFormat == FMT_ELF) ? "ELF" : (isDll ? "DLL" : "EXE");

    if (is64bit) {
        printf(CLR_WHITE "[ %s | %s ]" CLR_RESET
               "  ImageBase:  " CLR_YELLOW "%016llX" CLR_RESET
               "  EntryPoint: " CLR_GREEN  "%016llX" CLR_RESET
               CLR_WHITE "  (original)" CLR_RESET "\n",
               arch_str, fmt_str,
               (unsigned long long)imageBase,
               (unsigned long long)entryPoint);
        printf(CLR_WHITE "[ %s | %s ]" CLR_RESET
               "  ImageBase:  " CLR_YELLOW "%016llX" CLR_RESET
               "  EntryPoint: " CLR_GREEN  "%016llX" CLR_RESET
               CLR_WHITE "  (compared)" CLR_RESET,
               arch_str, fmt_str,
               (unsigned long long)imageBase2,
               (unsigned long long)entryPoint2);
    } else {
        printf(CLR_WHITE "[ %s | %s ]" CLR_RESET
               "  ImageBase:  " CLR_YELLOW "%08llX" CLR_RESET
               "  EntryPoint: " CLR_GREEN  "%08llX" CLR_RESET
               CLR_WHITE "  (original)" CLR_RESET "\n",
               arch_str, fmt_str,
               (unsigned long long)imageBase,
               (unsigned long long)entryPoint);
        printf(CLR_WHITE "[ %s | %s ]" CLR_RESET
               "  ImageBase:  " CLR_YELLOW "%08llX" CLR_RESET
               "  EntryPoint: " CLR_GREEN  "%08llX" CLR_RESET
               CLR_WHITE "  (compared)" CLR_RESET,
               arch_str, fmt_str,
               (unsigned long long)imageBase2,
               (unsigned long long)entryPoint2);
    }

    if (isDotNet) printf(CLR_CYAN "  [ .NET ]" CLR_RESET);
    printf("\n\n");

/* debugger */
    const char *dbg_label;
    if      (isArm && is64bit)  dbg_label = "[ arm64dbg ]";
    else if (isArm && !is64bit) dbg_label = "[ arm32dbg ]";
    else if (is64bit)           dbg_label = "[ x64dbg ]";
    else                        dbg_label = "[ x32dbg ]";

    FILE *f1 = fopen(argv[1], "rb");
    FILE *f2 = fopen(argv[2], "rb");
    if (!f1 || !f2) { printf("open error\n"); return 1; }

    uint8_t b1[CHUNK], b2[CHUNK];
    uint64_t off = 0;
    /* pending cross-chunk diff accumulation */
    uint64_t pend_file_off = 0;
    int      pend_active   = 0;
    uint8_t  pend_b[MAX_PATCH_BYTES], pend_a[MAX_PATCH_BYTES];
    int      pend_len      = 0;

    while (1) {
        size_t r1 = fread(b1, 1, CHUNK, f1);
        size_t r2 = fread(b2, 1, CHUNK, f2);
        size_t r  = (r1 < r2) ? r1 : r2;

        /* flush pending diff if the new chunk starts with a match (or file ended) */
        if (pend_active && (!r || b1[0] == b2[0])) {
            pend_active = 0;
            size_t grp_start = 0, grp_end = (size_t)pend_len - 1;
            uint64_t file_off = pend_file_off;
            uint64_t va; const char *sec;
            if (fileFormat == FMT_ELF) { va = elf_file_to_va(file_off); sec = elf_sec_name_at(va); }
            else { uint32_t rva = file_to_rva((uint32_t)file_off); va = rva_to_va(rva); sec = sec_name_at_rva(rva); }
            const char *a    = decode_opcode(pend_b[0]);
            const char *b_op = decode_opcode(pend_a[0]);
            char bytes_before[4096] = {0}, bytes_after[4096] = {0};
            int bp = 0, ap = 0;
            for (int k = 0; k < pend_len && bp < 4080; k++) bp += sprintf(bytes_before + bp, "%02X ", pend_b[k]);
            for (int k = 0; k < pend_len && ap < 4080; k++) ap += sprintf(bytes_after  + ap, "%02X ", pend_a[k]);
            if (bp > 0) bytes_before[bp - 1] = 0;
            if (ap > 0) bytes_after [ap - 1] = 0;
            int has_jump = 0; uint64_t jump_target = 0;
            if (!isArm) {
                if (is_jump_or_call(pend_a[0])) { uint8_t tmp[5]; memcpy(tmp, pend_a, pend_len < 5 ? pend_len : 5); has_jump = get_jump_target(tmp, 0, pend_len < 5 ? pend_len : 5, va, &jump_target); if (has_jump) printf(CLR_GREY "  jump target: " CLR_YELLOW "%016llX" CLR_RESET "\n", (unsigned long long)jump_target); }
                else if (is_jump_or_call(pend_b[0])) { uint8_t tmp[5]; memcpy(tmp, pend_b, pend_len < 5 ? pend_len : 5); has_jump = get_jump_target(tmp, 0, pend_len < 5 ? pend_len : 5, va, &jump_target); if (has_jump) printf(CLR_GREY "  jump target: " CLR_YELLOW "%016llX" CLR_RESET "\n", (unsigned long long)jump_target); }
            }
            if (is64bit) printf(CLR_GREY "[ %s ] %s " CLR_WHITE "%016llX" CLR_GREY "   OFF:0x%016llX | " CLR_CYAN "%-30s" CLR_GREY " -> " CLR_CYAN "%-30s" CLR_GREY " (" CLR_RED "%s" CLR_GREY " -> " CLR_RED "%s" CLR_GREY ")" CLR_RESET "\n", sec, dbg_label, (unsigned long long)va, (unsigned long long)file_off, a, b_op, bytes_before, bytes_after);
            else         printf(CLR_GREY "[ %s ] %s " CLR_WHITE "%08llX"   CLR_GREY "   OFF:0x%08llX | "   CLR_CYAN "%-30s" CLR_GREY " -> " CLR_CYAN "%-30s" CLR_GREY " (" CLR_RED "%s" CLR_GREY " -> " CLR_RED "%s" CLR_GREY ")" CLR_RESET "\n", sec, dbg_label, (unsigned long long)va, (unsigned long long)file_off, a, b_op, bytes_before, bytes_after);
            log_add(sec, va, file_off, a, b_op, bytes_before, bytes_after, pend_b, pend_a, pend_len, has_jump, jump_target);
            (void)grp_start; (void)grp_end;
        }

        if (!r) break;

        size_t i = 0;
        /* if still in a pending diff at the start of the new chunk, extend it */
        if (pend_active) {
            while (i < r && b1[i] != b2[i]) {
                if (pend_len < MAX_PATCH_BYTES) { pend_b[pend_len] = b1[i]; pend_a[pend_len] = b2[i]; pend_len++; }
                i++;
            }
            if (i < r) pend_active = 0; /* ended within this chunk; will be flushed next iteration or below */
        }

        while (i < r) {
            if (b1[i] != b2[i]) {
                size_t grp_start = i;
                while (i < r && b1[i] != b2[i]) i++;
                size_t grp_end = i - 1;

                /* diff hit the chunk boundary — defer to next iteration */
                if (i == r) {
                    pend_file_off = off + (uint64_t)grp_start;
                    pend_len = (int)(grp_end - grp_start + 1);
                    if (pend_len > MAX_PATCH_BYTES) pend_len = MAX_PATCH_BYTES;
                    for (int k = 0; k < pend_len; k++) { pend_b[k] = b1[grp_start + (size_t)k]; pend_a[k] = b2[grp_start + (size_t)k]; }
                    pend_active = 1;
                    break;
                }

                uint64_t file_off = off + (uint64_t)grp_start;
                uint64_t va;
                const char *sec;

                if (fileFormat == FMT_ELF) {
                    va  = elf_file_to_va(file_off);
                    sec = elf_sec_name_at(va);
                } else {
                    uint32_t rva = file_to_rva((uint32_t)file_off);
                    va  = rva_to_va(rva);
                    sec = sec_name_at_rva(rva);
                }

                const char *a    = smart_decode(b1, grp_start, r);
                const char *b_op = smart_decode(b2, grp_start, r);

                char bytes_before[4096] = {0};
                char bytes_after[4096]  = {0};
                int  bp = 0, ap = 0;
                for (size_t k = grp_start; k <= grp_end && bp < 4080; k++)
                    bp += sprintf(bytes_before + bp, "%02X ", b1[k]);
                for (size_t k = grp_start; k <= grp_end && ap < 4080; k++)
                    ap += sprintf(bytes_after  + ap, "%02X ", b2[k]);
                if (bp > 0) bytes_before[bp - 1] = 0;
                if (ap > 0) bytes_after[ap  - 1] = 0;

/* .1337 export */
                uint8_t raw_b[MAX_PATCH_BYTES], raw_a[MAX_PATCH_BYTES];
                int raw_len = (int)(grp_end - grp_start + 1);
                if (raw_len > MAX_PATCH_BYTES) raw_len = MAX_PATCH_BYTES;
                for (int k = 0; k < raw_len; k++) {
                    raw_b[k] = b1[grp_start + (size_t)k];
                    raw_a[k] = b2[grp_start + (size_t)k];
                }

                if (is64bit) {
                    printf(CLR_GREY "[" CLR_GREY " %s " CLR_GREY "] "
                           CLR_GREY "%s " CLR_WHITE "%016llX"
                           CLR_GREY "   OFF:0x%016llX | "
                           CLR_CYAN "%-30s" CLR_GREY " -> " CLR_CYAN "%-30s"
                           CLR_GREY " (" CLR_RED "%s" CLR_GREY " -> " CLR_RED "%s" CLR_GREY ")" CLR_RESET "\n",
                           sec, dbg_label,
                           (unsigned long long)va,
                           (unsigned long long)file_off,
                           a, b_op,
                           bytes_before, bytes_after);
                } else {
                    printf(CLR_GREY "[" CLR_GREY " %s " CLR_GREY "] "
                           CLR_GREY "%s " CLR_WHITE "%08llX"
                           CLR_GREY "   OFF:0x%08llX | "
                           CLR_CYAN "%-30s" CLR_GREY " -> " CLR_CYAN "%-30s"
                           CLR_GREY " (" CLR_RED "%s" CLR_GREY " -> " CLR_RED "%s" CLR_GREY ")" CLR_RESET "\n",
                           sec, dbg_label,
                           (unsigned long long)va,
                           (unsigned long long)file_off,
                           a, b_op,
                           bytes_before, bytes_after);
                }

 /* jmp */
                int      has_jump    = 0;
                uint64_t jump_target = 0;

                if (!isArm) {
                    if (is_jump_or_call(b2[grp_start])) {
                        print_jump_target(b2, grp_start, r, va);
                        has_jump = get_jump_target(b2, grp_start, r, va, &jump_target);
                    } else if (is_jump_or_call(b1[grp_start])) {
                        print_jump_target(b1, grp_start, r, va);
                        has_jump = get_jump_target(b1, grp_start, r, va, &jump_target);
                    }
                }

                {
                    int ctx_start = (int)grp_start - 8;
                    int ctx_end   = (int)grp_end   + 8;
                    if (ctx_start < 0)     ctx_start = 0;
                    if (ctx_end >= (int)r) ctx_end   = (int)r - 1;

                    printf(CLR_GREY "  full bytes: " CLR_RESET);
                    for (int k = ctx_start; k <= ctx_end; k++) {
                        if (k >= (int)grp_start && k <= (int)grp_end)
                            printf(CLR_RED "%02X " CLR_RESET, b1[k]);
                        else
                            printf("%02X ", b1[k]);
                    }
                    printf("\n");
                    printf(CLR_GREY "           -> " CLR_RESET);
                    for (int k = ctx_start; k <= ctx_end; k++) {
                        if (k >= (int)grp_start && k <= (int)grp_end)
                            printf(CLR_RED "%02X " CLR_RESET, b2[k]);
                        else
                            printf("%02X ", b2[k]);
                    }
                    printf("\n");
                }

                log_add(sec, va, file_off, a, b_op,
                        bytes_before, bytes_after,
                        raw_b, raw_a, raw_len,
                        has_jump, jump_target);

            } else {
                i++;
            }
        }

        off += (uint64_t)r;

        if (r1 != r2) {
            printf(CLR_YELLOW "  [!] size mismatch\n" CLR_RESET);
            break;
        }
    }

    fclose(f1);
    fclose(f2);

    print_log_summary();
    save_log_to_file(argv[1], argv[2]);
    save_1337(argv[1]);

    return 0;
}