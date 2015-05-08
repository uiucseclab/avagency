/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    mspyLog.c

Abstract:

    This module contains functions used to retrieve and see the log records
    recorded by MiniSpy.sys.

Environment:

    User mode

--*/

#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <winioctl.h>
#include "mspyLog.h"
#include <assert.h>
#include <strsafe.h>
// #include "md5.h"
#include <wchar.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define MINISPY_NAME            L"MiniSpy"

#define TIME_BUFFER_LENGTH 20
#define TIME_ERROR         "time error"

#define POLL_INTERVAL   200     // 200 milliseconds

struct device_letter_name
{
    WCHAR letter[15];
    WCHAR name[1000];
    USHORT namelength;
};

void blacklist_check(WCHAR CONST *Name, char **blacklist, WCHAR devicename[1000], WCHAR deviceletter[15]);
void on_access_filter(WCHAR CONST *Name, struct device_letter_name *devicelist, char **blacklist);
ULONG IsAttachedToVolume(_In_ LPCWSTR VolumeName);
void getDevices(struct device_letter_name *devicelist);
static void MDFile (WCHAR *filename, unsigned char hexout[33]);

BOOLEAN
TranslateFileTag(
    _In_ PLOG_RECORD logRecord
    )
/*++

Routine Description:

    If this is a mount point reparse point, move the given name string to the
    correct position in the log record structure so it will be displayed
    by the common routines.

Arguments:

    logRecord - The log record to update

Return Value:

    TRUE - if this is a mount point reparse point
    FALSE - otherwise

--*/
{
    PFLT_TAG_DATA_BUFFER TagData;
    ULONG Length;

    //
    // The reparse data structure starts in the NAME field, point to it.
    //

    TagData = (PFLT_TAG_DATA_BUFFER) &logRecord->Name[0];

    //
    //  See if MOUNT POINT tag
    //

    if (TagData->FileTag == IO_REPARSE_TAG_MOUNT_POINT) {

        //
        //  calculate how much to copy
        //

        Length = min( MAX_NAME_SPACE - sizeof(UNICODE_NULL), TagData->MountPointReparseBuffer.SubstituteNameLength );

        //
        //  Position the reparse name at the proper position in the buffer.
        //  Note that we are doing an overlapped copy
        //

        MoveMemory( &logRecord->Name[0],
                    TagData->MountPointReparseBuffer.PathBuffer,
                    Length );

        logRecord->Name[Length/sizeof(WCHAR)] = UNICODE_NULL;
        return TRUE;
    }

    return FALSE;
}


DWORD
WINAPI
RetrieveLogRecords(
    _In_ LPVOID lpParameter
    )
/*++

Routine Description:

    This runs as a separate thread.  Its job is to retrieve log records
    from the filter and then output them

Arguments:

    lpParameter - Contains context structure for synchronizing with the
        main program thread.

Return Value:

    The thread successfully terminated

--*/
{
    PLOG_CONTEXT context = (PLOG_CONTEXT)lpParameter;
    DWORD bytesReturned = 0;
    DWORD used;
    PVOID alignedBuffer[BUFFER_SIZE/sizeof( PVOID )];
    PCHAR buffer = (PCHAR) alignedBuffer;
    HRESULT hResult;
    PLOG_RECORD pLogRecord;
    PRECORD_DATA pRecordData;
    COMMAND_MESSAGE commandMessage;
    char ch;
    char **blacklist=NULL;
    int lines=0;
    FILE *blacklist_fp;
    errno_t err;


    blacklist_fp = fopen("blacklist.txt", "r");
    if(blacklist_fp == NULL)
    {
        char error_temp[1000];
        strerror_s(error_temp, 1000, errno);
        printf("ERROR : open blacklist error0. %s\n", error_temp);
    }
    else
    {
        printf("lines = %u\n", lines);
        while(!feof(blacklist_fp))
        {
            printf("lines = %u\n", lines);
          ch = (char)fgetc(blacklist_fp);
          if(ch == '\n')
          {
            lines++;
          }
        }
        fclose(blacklist_fp);
    }
    
    blacklist_fp = fopen("blacklist.txt", "r");
    if(blacklist_fp == NULL)
    {
        char error_temp[1000];
        strerror_s(error_temp, 1000, errno);
        printf("ERROR : open blacklist error1. %s\n", error_temp);
    }
    else
    {
        // blacklist = NULL;
        printf("lines = %l\n", lines);
        blacklist = (char**) malloc((lines + 2) * sizeof(char*));
        blacklist[lines+1]=NULL;
        for(int i=0; i<lines+1; i++)
        {
            blacklist[i] = (char*)malloc(100*sizeof(char));
            if(fgets(blacklist[i], 34, blacklist_fp) == NULL)
            {
                free(blacklist[i]);
                blacklist[i] = NULL;
                break;
            }
            if(feof(blacklist_fp))
            {
                blacklist[i+1] = NULL;
                break;
            }
        }
        fclose(blacklist_fp);
    }

    struct device_letter_name *devicelist;
    devicelist = (struct device_letter_name *) malloc(1000*sizeof(struct device_letter_name));
    // devicelist[0].namelength = 0;

    for(int i=0; i<1000; i++)
    {
        wcsncpy_s(devicelist[i].letter, 15, L"\0", 1);
        wcsncpy_s(devicelist[i].name, 1000, L"\0", 1);
        devicelist[i].letter[0] = UNICODE_NULL;
        devicelist[i].name[0] = UNICODE_NULL;
        devicelist[i].namelength = 0;
    }
    getDevices(devicelist);

    printf("Log: Starting up\n");

    


#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while (TRUE) {

#pragma warning(pop)

        //
        //  Check to see if we should shut down.
        //

        if (context->CleaningUp) {

            break;
        }

        //
        //  Request log data from MiniSpy.
        //

        commandMessage.Command = GetMiniSpyLog;

        hResult = FilterSendMessage( context->Port,
                                     &commandMessage,
                                     sizeof( COMMAND_MESSAGE ),
                                     buffer,
                                     sizeof(alignedBuffer),
                                     &bytesReturned );

        if (IS_ERROR( hResult )) {

            if (HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE ) == hResult) {

                printf( "The kernel component of minispy has unloaded. Exiting\n" );
                ExitProcess( 0 );
            } else {

                if (hResult != HRESULT_FROM_WIN32( ERROR_NO_MORE_ITEMS )) {

                    printf( "UNEXPECTED ERROR received: %x\n", hResult );
                }

                Sleep( POLL_INTERVAL );
            }

            continue;
        }

        //
        //  Buffer is filled with a series of LOG_RECORD structures, one
        //  right after another.  Each LOG_RECORD says how long it is, so
        //  we know where the next LOG_RECORD begins.
        //

        pLogRecord = (PLOG_RECORD) buffer;
        used = 0;

        //
        //  Logic to write record to screen and/or file
        //
        for (;;) {

            if (used+FIELD_OFFSET(LOG_RECORD,Name) > bytesReturned) {

                break;
            }

            if (pLogRecord->Length < (sizeof(LOG_RECORD)+sizeof(WCHAR))) {

                printf( "UNEXPECTED LOG_RECORD->Length: length=%d expected>=%d\n",
                        pLogRecord->Length,
                        (sizeof(LOG_RECORD)+sizeof(WCHAR)));

                break;
            }

            used += pLogRecord->Length;

            if (used > bytesReturned) {

                printf( "UNEXPECTED LOG_RECORD size: used=%d bytesReturned=%d\n",
                        used,
                        bytesReturned);

                break;
            }

            pRecordData = &pLogRecord->Data;

            //
            //  See if a reparse point entry
            //

            if (FlagOn(pLogRecord->RecordType,RECORD_TYPE_FILETAG)) {

                if (!TranslateFileTag( pLogRecord )){

                    //
                    // If this is a reparse point that can't be interpreted, move on.
                    //

                    pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord,pLogRecord->Length);
                    continue;
                }
            }

// switch (MajorCode) {
//         case IRP_MJ_CREATE:
//         RecordData->CallbackMajorId,

            // printf("my start\n");
            // if(pRecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION)
            if(pRecordData->CallbackMajorId == IRP_MJ_CREATE)
                // fprintf(test, "0x%08X\t%S\n", pLogRecord->SequenceNumber, pLogRecord->Name);
                on_access_filter(pLogRecord->Name, devicelist, blacklist);
            // printf("my end\n");



            if (context->LogToScreen) {

                ScreenDump( pLogRecord->SequenceNumber,
                            pLogRecord->Name,
                            pRecordData );
            }

            if (context->LogToFile) {

                FileDump( pLogRecord->SequenceNumber,
                          pLogRecord->Name,
                          pRecordData,
                          context->OutputFile );
            }

            //
            //  The RecordType could also designate that we are out of memory
            //  or hit our program defined memory limit, so check for these
            //  cases.
            //

            if (FlagOn(pLogRecord->RecordType,RECORD_TYPE_FLAG_OUT_OF_MEMORY)) {

                if (context->LogToScreen) {

                    printf( "M:  %08X System Out of Memory\n",
                            pLogRecord->SequenceNumber );
                }

                if (context->LogToFile) {

                    fprintf( context->OutputFile,
                             "M:\t0x%08X\tSystem Out of Memory\n",
                             pLogRecord->SequenceNumber );
                }

            } else if (FlagOn(pLogRecord->RecordType,RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE)) {

                if (context->LogToScreen) {

                    printf( "M:  %08X Exceeded Mamimum Allowed Memory Buffers\n",
                            pLogRecord->SequenceNumber );
                }

                if (context->LogToFile) {

                    fprintf( context->OutputFile,
                             "M:\t0x%08X\tExceeded Mamimum Allowed Memory Buffers\n",
                             pLogRecord->SequenceNumber );
                }
            }

            //
            // Move to next LOG_RECORD
            //

            pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord,pLogRecord->Length);
        }

        //
        //  If we didn't get any data, pause for 1/2 second
        //

        if (bytesReturned == 0) {

            Sleep( POLL_INTERVAL );
        }
    }

    printf( "Log: Shutting down\n" );
    ReleaseSemaphore( context->ShutDown, 1, NULL );
    printf( "Log: All done\n" );
    return 0;
}


VOID
PrintIrpCode(
    _In_ UCHAR MajorCode,
    _In_ UCHAR MinorCode,
    _In_opt_ FILE *OutputFile,
    _In_ BOOLEAN PrintMajorCode
)
/*++

Routine Description:

    Display the operation code

Arguments:

    MajorCode - Major function code of operation

    MinorCode - Minor function code of operation

    OutputFile - If writing to a file (not the screen) the handle for that file

    PrintMajorCode - Only used when printing to the display:
        TRUE - if we want to display the MAJOR CODE
        FALSE - if we want to display the MINOR code

Return Value:

    None

--*/
{
    CHAR *irpMajorString, *irpMinorString = NULL;
    CHAR errorBuf[128];

    switch (MajorCode) {
        case IRP_MJ_CREATE:
            irpMajorString = IRP_MJ_CREATE_STRING;
            break;
        case IRP_MJ_CREATE_NAMED_PIPE:
            irpMajorString = IRP_MJ_CREATE_NAMED_PIPE_STRING;
            break;
        case IRP_MJ_CLOSE:
            irpMajorString = IRP_MJ_CLOSE_STRING;
            break;
        case IRP_MJ_READ:
            irpMajorString = IRP_MJ_READ_STRING;
            switch (MinorCode) {
                case IRP_MN_NORMAL:
                    irpMinorString = IRP_MN_NORMAL_STRING;
                    break;
                case IRP_MN_DPC:
                    irpMinorString = IRP_MN_DPC_STRING;
                    break;
                case IRP_MN_MDL:
                    irpMinorString = IRP_MN_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE:
                    irpMinorString = IRP_MN_COMPLETE_STRING;
                    break;
                case IRP_MN_COMPRESSED:
                    irpMinorString = IRP_MN_COMPRESSED_STRING;
                    break;
                case IRP_MN_MDL_DPC:
                    irpMinorString = IRP_MN_MDL_DPC_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL:
                    irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL_DPC:
                    irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_WRITE:
            irpMajorString = IRP_MJ_WRITE_STRING;
            switch (MinorCode) {
                case IRP_MN_NORMAL:
                    irpMinorString = IRP_MN_NORMAL_STRING;
                    break;
                case IRP_MN_DPC:
                    irpMinorString = IRP_MN_DPC_STRING;
                    break;
                case IRP_MN_MDL:
                    irpMinorString = IRP_MN_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE:
                    irpMinorString = IRP_MN_COMPLETE_STRING;
                    break;
                case IRP_MN_COMPRESSED:
                    irpMinorString = IRP_MN_COMPRESSED_STRING;
                    break;
                case IRP_MN_MDL_DPC:
                    irpMinorString = IRP_MN_MDL_DPC_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL:
                    irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL_DPC:
                    irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_QUERY_INFORMATION:
            irpMajorString = IRP_MJ_QUERY_INFORMATION_STRING;
            break;
        case IRP_MJ_SET_INFORMATION:
            irpMajorString = IRP_MJ_SET_INFORMATION_STRING;
            break;
        case IRP_MJ_QUERY_EA:
            irpMajorString = IRP_MJ_QUERY_EA_STRING;
            break;
        case IRP_MJ_SET_EA:
            irpMajorString = IRP_MJ_SET_EA_STRING;
            break;
        case IRP_MJ_FLUSH_BUFFERS:
            irpMajorString = IRP_MJ_FLUSH_BUFFERS_STRING;
            break;
        case IRP_MJ_QUERY_VOLUME_INFORMATION:
            irpMajorString = IRP_MJ_QUERY_VOLUME_INFORMATION_STRING;
            break;
        case IRP_MJ_SET_VOLUME_INFORMATION:
            irpMajorString = IRP_MJ_SET_VOLUME_INFORMATION_STRING;
            break;
        case IRP_MJ_DIRECTORY_CONTROL:
            irpMajorString = IRP_MJ_DIRECTORY_CONTROL_STRING;
            switch (MinorCode) {
                case IRP_MN_QUERY_DIRECTORY:
                    irpMinorString = IRP_MN_QUERY_DIRECTORY_STRING;
                    break;
                case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
                    irpMinorString = IRP_MN_NOTIFY_CHANGE_DIRECTORY_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_FILE_SYSTEM_CONTROL:
            irpMajorString = IRP_MJ_FILE_SYSTEM_CONTROL_STRING;
            switch (MinorCode) {
                case IRP_MN_USER_FS_REQUEST:
                    irpMinorString = IRP_MN_USER_FS_REQUEST_STRING;
                    break;
                case IRP_MN_MOUNT_VOLUME:
                    irpMinorString = IRP_MN_MOUNT_VOLUME_STRING;
                    break;
                case IRP_MN_VERIFY_VOLUME:
                    irpMinorString = IRP_MN_VERIFY_VOLUME_STRING;
                    break;
                case IRP_MN_LOAD_FILE_SYSTEM:
                    irpMinorString = IRP_MN_LOAD_FILE_SYSTEM_STRING;
                    break;
                case IRP_MN_TRACK_LINK:
                    irpMinorString = IRP_MN_TRACK_LINK_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_DEVICE_CONTROL:
            irpMajorString = IRP_MJ_DEVICE_CONTROL_STRING;
            switch (MinorCode) {
                case IRP_MN_SCSI_CLASS:
                    irpMinorString = IRP_MN_SCSI_CLASS_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
            irpMajorString = IRP_MJ_INTERNAL_DEVICE_CONTROL_STRING;
            break;
        case IRP_MJ_SHUTDOWN:
            irpMajorString = IRP_MJ_SHUTDOWN_STRING;
            break;
        case IRP_MJ_LOCK_CONTROL:
            irpMajorString = IRP_MJ_LOCK_CONTROL_STRING;
            switch (MinorCode) {
                case IRP_MN_LOCK:
                    irpMinorString = IRP_MN_LOCK_STRING;
                    break;
                case IRP_MN_UNLOCK_SINGLE:
                    irpMinorString = IRP_MN_UNLOCK_SINGLE_STRING;
                    break;
                case IRP_MN_UNLOCK_ALL:
                    irpMinorString = IRP_MN_UNLOCK_ALL_STRING;
                    break;
                case IRP_MN_UNLOCK_ALL_BY_KEY:
                    irpMinorString = IRP_MN_UNLOCK_ALL_BY_KEY_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_CLEANUP:
            irpMajorString = IRP_MJ_CLEANUP_STRING;
            break;
        case IRP_MJ_CREATE_MAILSLOT:
            irpMajorString = IRP_MJ_CREATE_MAILSLOT_STRING;
            break;
        case IRP_MJ_QUERY_SECURITY:
            irpMajorString = IRP_MJ_QUERY_SECURITY_STRING;
            break;
        case IRP_MJ_SET_SECURITY:
            irpMajorString = IRP_MJ_SET_SECURITY_STRING;
            break;
        case IRP_MJ_POWER:
            irpMajorString = IRP_MJ_POWER_STRING;
            switch (MinorCode) {
                case IRP_MN_WAIT_WAKE:
                    irpMinorString = IRP_MN_WAIT_WAKE_STRING;
                    break;
                case IRP_MN_POWER_SEQUENCE:
                    irpMinorString = IRP_MN_POWER_SEQUENCE_STRING;
                    break;
                case IRP_MN_SET_POWER:
                    irpMinorString = IRP_MN_SET_POWER_STRING;
                    break;
                case IRP_MN_QUERY_POWER:
                    irpMinorString = IRP_MN_QUERY_POWER_STRING;
                    break;
                default :
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_SYSTEM_CONTROL:
            irpMajorString = IRP_MJ_SYSTEM_CONTROL_STRING;
            switch (MinorCode) {
                case IRP_MN_QUERY_ALL_DATA:
                    irpMinorString = IRP_MN_QUERY_ALL_DATA_STRING;
                    break;
                case IRP_MN_QUERY_SINGLE_INSTANCE:
                    irpMinorString = IRP_MN_QUERY_SINGLE_INSTANCE_STRING;
                    break;
                case IRP_MN_CHANGE_SINGLE_INSTANCE:
                    irpMinorString = IRP_MN_CHANGE_SINGLE_INSTANCE_STRING;
                    break;
                case IRP_MN_CHANGE_SINGLE_ITEM:
                    irpMinorString = IRP_MN_CHANGE_SINGLE_ITEM_STRING;
                    break;
                case IRP_MN_ENABLE_EVENTS:
                    irpMinorString = IRP_MN_ENABLE_EVENTS_STRING;
                    break;
                case IRP_MN_DISABLE_EVENTS:
                    irpMinorString = IRP_MN_DISABLE_EVENTS_STRING;
                    break;
                case IRP_MN_ENABLE_COLLECTION:
                    irpMinorString = IRP_MN_ENABLE_COLLECTION_STRING;
                    break;
                case IRP_MN_DISABLE_COLLECTION:
                    irpMinorString = IRP_MN_DISABLE_COLLECTION_STRING;
                    break;
                case IRP_MN_REGINFO:
                    irpMinorString = IRP_MN_REGINFO_STRING;
                    break;
                case IRP_MN_EXECUTE_METHOD:
                    irpMinorString = IRP_MN_EXECUTE_METHOD_STRING;
                    break;
                default :
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;

        case IRP_MJ_DEVICE_CHANGE:
            irpMajorString = IRP_MJ_DEVICE_CHANGE_STRING;
            break;
        case IRP_MJ_QUERY_QUOTA:
            irpMajorString = IRP_MJ_QUERY_QUOTA_STRING;
            break;
        case IRP_MJ_SET_QUOTA:
            irpMajorString = IRP_MJ_SET_QUOTA_STRING;
            break;
        case IRP_MJ_PNP:
            irpMajorString = IRP_MJ_PNP_STRING;
            switch (MinorCode) {
                case IRP_MN_START_DEVICE:
                    irpMinorString = IRP_MN_START_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_REMOVE_DEVICE:
                    irpMinorString = IRP_MN_QUERY_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_REMOVE_DEVICE:
                    irpMinorString = IRP_MN_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_CANCEL_REMOVE_DEVICE:
                    irpMinorString = IRP_MN_CANCEL_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_STOP_DEVICE:
                    irpMinorString = IRP_MN_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_STOP_DEVICE:
                    irpMinorString = IRP_MN_QUERY_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_CANCEL_STOP_DEVICE:
                    irpMinorString = IRP_MN_CANCEL_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_DEVICE_RELATIONS:
                    irpMinorString = IRP_MN_QUERY_DEVICE_RELATIONS_STRING;
                    break;
                case IRP_MN_QUERY_INTERFACE:
                    irpMinorString = IRP_MN_QUERY_INTERFACE_STRING;
                    break;
                case IRP_MN_QUERY_CAPABILITIES:
                    irpMinorString = IRP_MN_QUERY_CAPABILITIES_STRING;
                    break;
                case IRP_MN_QUERY_RESOURCES:
                    irpMinorString = IRP_MN_QUERY_RESOURCES_STRING;
                    break;
                case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
                    irpMinorString = IRP_MN_QUERY_RESOURCE_REQUIREMENTS_STRING;
                    break;
                case IRP_MN_QUERY_DEVICE_TEXT:
                    irpMinorString = IRP_MN_QUERY_DEVICE_TEXT_STRING;
                    break;
                case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
                    irpMinorString = IRP_MN_FILTER_RESOURCE_REQUIREMENTS_STRING;
                    break;
                case IRP_MN_READ_CONFIG:
                    irpMinorString = IRP_MN_READ_CONFIG_STRING;
                    break;
                case IRP_MN_WRITE_CONFIG:
                    irpMinorString = IRP_MN_WRITE_CONFIG_STRING;
                    break;
                case IRP_MN_EJECT:
                    irpMinorString = IRP_MN_EJECT_STRING;
                    break;
                case IRP_MN_SET_LOCK:
                    irpMinorString = IRP_MN_SET_LOCK_STRING;
                    break;
                case IRP_MN_QUERY_ID:
                    irpMinorString = IRP_MN_QUERY_ID_STRING;
                    break;
                case IRP_MN_QUERY_PNP_DEVICE_STATE:
                    irpMinorString = IRP_MN_QUERY_PNP_DEVICE_STATE_STRING;
                    break;
                case IRP_MN_QUERY_BUS_INFORMATION:
                    irpMinorString = IRP_MN_QUERY_BUS_INFORMATION_STRING;
                    break;
                case IRP_MN_DEVICE_USAGE_NOTIFICATION:
                    irpMinorString = IRP_MN_DEVICE_USAGE_NOTIFICATION_STRING;
                    break;
                case IRP_MN_SURPRISE_REMOVAL:
                    irpMinorString = IRP_MN_SURPRISE_REMOVAL_STRING;
                    break;
                case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
                    irpMinorString = IRP_MN_QUERY_LEGACY_BUS_INFORMATION_STRING;
                    break;
                default :
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp minor code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;


        case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
            irpMajorString = IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
            irpMajorString = IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION_STRING;
            break;

        case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
            irpMajorString = IRP_MJ_ACQUIRE_FOR_MOD_WRITE_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_MOD_WRITE:
            irpMajorString = IRP_MJ_RELEASE_FOR_MOD_WRITE_STRING;
            break;

        case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
            irpMajorString = IRP_MJ_ACQUIRE_FOR_CC_FLUSH_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_CC_FLUSH:
            irpMajorString = IRP_MJ_RELEASE_FOR_CC_FLUSH_STRING;
            break;

        case IRP_MJ_NOTIFY_STREAM_FO_CREATION:
            irpMajorString = IRP_MJ_NOTIFY_STREAM_FO_CREATION_STRING;
            break;



        case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
            irpMajorString = IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE_STRING;
            break;

        case IRP_MJ_NETWORK_QUERY_OPEN:
            irpMajorString = IRP_MJ_NETWORK_QUERY_OPEN_STRING;
            break;

        case IRP_MJ_MDL_READ:
            irpMajorString = IRP_MJ_MDL_READ_STRING;
            break;

        case IRP_MJ_MDL_READ_COMPLETE:
            irpMajorString = IRP_MJ_MDL_READ_COMPLETE_STRING;
            break;

        case IRP_MJ_PREPARE_MDL_WRITE:
            irpMajorString = IRP_MJ_PREPARE_MDL_WRITE_STRING;
            break;

        case IRP_MJ_MDL_WRITE_COMPLETE:
            irpMajorString = IRP_MJ_MDL_WRITE_COMPLETE_STRING;
            break;

        case IRP_MJ_VOLUME_MOUNT:
            irpMajorString = IRP_MJ_VOLUME_MOUNT_STRING;
            break;

        case IRP_MJ_VOLUME_DISMOUNT:
            irpMajorString = IRP_MJ_VOLUME_DISMOUNT_STRING;
            break;

        case IRP_MJ_TRANSACTION_NOTIFY:
            irpMajorString = IRP_MJ_TRANSACTION_NOTIFY_STRING;
            switch (MinorCode) {
                case 0:
                    irpMinorString = TRANSACTION_BEGIN;
                    break;
                case TRANSACTION_NOTIFY_PREPREPARE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPARE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_PREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_COMMIT_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_COMMIT_FINALIZE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_COMMIT_FINALIZE_STRING;
                    break;
                case TRANSACTION_NOTIFY_ROLLBACK_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPARE_COMPLETE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_COMMIT_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_RECOVER_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_RECOVER_STRING;
                    break;
                case TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_DELEGATE_COMMIT_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_DELEGATE_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_RECOVER_QUERY_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_RECOVER_QUERY_STRING;
                    break;
                case TRANSACTION_NOTIFY_ENLIST_PREPREPARE_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_ENLIST_PREPREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_LAST_RECOVER_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_LAST_RECOVER_STRING;
                    break;
                case TRANSACTION_NOTIFY_INDOUBT_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_INDOUBT_STRING;
                    break;
                case TRANSACTION_NOTIFY_PROPAGATE_PULL_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PULL_STRING;
                    break;
                case TRANSACTION_NOTIFY_PROPAGATE_PUSH_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PUSH_STRING;
                    break;
                case TRANSACTION_NOTIFY_MARSHAL_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_MARSHAL_STRING;
                    break;
                case TRANSACTION_NOTIFY_ENLIST_MASK_CODE:
                    irpMinorString = TRANSACTION_NOTIFY_ENLIST_MASK_STRING;
                    break;
                default:
                    sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Transaction notication code (%u)",MinorCode);
                    irpMinorString = errorBuf;
            }
            break;


        default:
            sprintf_s(errorBuf,sizeof(errorBuf),"Unknown Irp major function (%d)",MajorCode);
            irpMajorString = errorBuf;
            break;
    }

    if (OutputFile) {

        if (irpMinorString) {

            fprintf(OutputFile, "\t%-35s\t%-35s", irpMajorString, irpMinorString);

        } else {

            fprintf(OutputFile, "\t%-35s\t                                   ", irpMajorString);
        }

    } else {

        if (PrintMajorCode) {

            printf("%-35s ", irpMajorString);

        } else {

            if (irpMinorString) {

                printf("                                                                     %-35s\n",
                        irpMinorString);
            }
        }
    }
}


ULONG
FormatSystemTime(
    _In_ SYSTEMTIME *SystemTime,
    _Out_writes_bytes_(BufferLength) CHAR *Buffer,
    _In_ ULONG BufferLength
    )
/*++
Routine Description:

    Formats the values in a SystemTime struct into the buffer
    passed in.  The resulting string is NULL terminated.  The format
    for the time is:
        hours:minutes:seconds:milliseconds

Arguments:

    SystemTime - the struct to format
    Buffer - the buffer to place the formatted time in
    BufferLength - the size of the buffer

Return Value:

    The length of the string returned in Buffer.

--*/
{
    ULONG returnLength = 0;

    if (BufferLength < TIME_BUFFER_LENGTH) {

        //
        // Buffer is too short so exit
        //

        return 0;
    }

    returnLength = sprintf_s( Buffer,
                            BufferLength,
                            "%02d:%02d:%02d:%03d",
                            SystemTime->wHour,
                            SystemTime->wMinute,
                            SystemTime->wSecond,
                            SystemTime->wMilliseconds );

    return returnLength;
}


VOID
FileDump (
    _In_ ULONG SequenceNumber,
    _In_ WCHAR CONST *Name,
    _In_ PRECORD_DATA RecordData,
    _In_ FILE *File
    )
/*++
Routine Description:

    Prints a Data log record to the specified file.  The output is in a tab
    delimited format with the fields in the following order:

    SequenceNumber, OriginatingTime, CompletionTime, CallbackMajorId, CallbackMinorId,
    Flags, NoCache, Paging I/O, Synchronous, Synchronous paging, FileName,
    ReturnStatus, FileName


Arguments:

    SequenceNumber - the sequence number for this log record
    Name - the name of the file that this Irp relates to
    RecordData - the Data record to print
    File - the file to print to

Return Value:

    None.

--*/
{
    FILETIME localTime;
    SYSTEMTIME systemTime;
    CHAR time[TIME_BUFFER_LENGTH];
    static BOOLEAN didFileHeader = FALSE;

    //
    // Is this an Irp or a FastIo?
    //

    if (!didFileHeader) {

#if defined(_WIN64)
        fprintf( File, "Opr\t  SeqNum  \t PreOp Time \tPostOp Time \t Process.Thrd\t          Major Operation          \t          Minor Operation          \t   IrpFlags    \t      DevObj      \t     FileObj      \t    Transactn     \t    status:inform            \t      Arg 1       \t      Arg 2       \t      Arg 3       \t      Arg 4       \t      Arg 5       \t  Arg 6   \tName\n");
        fprintf( File, "---\t----------\t------------\t------------\t-------------\t-----------------------------------\t-----------------------------------\t---------------\t------------------\t------------------\t------------------\t-----------------------------\t------------------\t------------------\t------------------\t------------------\t------------------\t----------\t--------------------------------------------------\n");
#else
        fprintf( File, "Opr\t  SeqNum  \t PreOp Time \tPostOp Time \t Process.Thrd\t          Major Operation          \t          Minor Operation          \t   IrpFlags    \t  DevObj  \t FileObj  \tTransactn \t    status:inform    \t  Arg 1   \t  Arg 2   \t  Arg 3   \t  Arg 4   \t  Arg 5   \t  Arg 6   \tName\n");
        fprintf( File, "---\t----------\t------------\t------------\t-------------\t-----------------------------------\t-----------------------------------\t---------------\t----------\t----------\t----------\t---------------------\t----------\t----------\t----------\t----------\t----------\t----------\t--------------------------------------------------\n");
#endif
        didFileHeader = TRUE;
    }

    //
    // Is this an Irp or a FastIo?
    //

    if (RecordData->Flags & FLT_CALLBACK_DATA_IRP_OPERATION) {

        fprintf( File, "IRP");

    } else if (RecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION) {

        fprintf( File, "FIO");

    } else if (RecordData->Flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION) {

        fprintf( File, "FSF");

    } else {

        fprintf( File, "ERR");
    }

    //
    //  Print the sequence number
    //

    fprintf( File, "\t0x%08X", SequenceNumber );

    //
    // Convert originating time
    //

    FileTimeToLocalFileTime( (FILETIME *)&(RecordData->OriginatingTime),
                             &localTime );
    FileTimeToSystemTime( &localTime,
                          &systemTime );

    if (FormatSystemTime( &systemTime, time, TIME_BUFFER_LENGTH )) {

        fprintf( File, "\t%-12s", time );

    } else {

        fprintf( File, "\t%-12s", TIME_ERROR );
    }

    //
    // Convert completion time
    //

    FileTimeToLocalFileTime( (FILETIME *)&(RecordData->CompletionTime),
                             &localTime );
    FileTimeToSystemTime( &localTime,
                          &systemTime );

    if (FormatSystemTime( &systemTime, time, TIME_BUFFER_LENGTH )) {

        fprintf( File, "\t%-12s", time );

    } else {

        fprintf( File, "\t%-12s", TIME_ERROR );
    }

    fprintf(File, "\t%8x.%-4x ", RecordData->ProcessId, RecordData->ThreadId);

    PrintIrpCode( RecordData->CallbackMajorId,
                  RecordData->CallbackMinorId,
                  File,
                  TRUE );

    //
    // Interpret set IrpFlags
    //

    fprintf( File, "\t0x%08lx ", RecordData->IrpFlags );
    fprintf( File, "%s", (RecordData->IrpFlags & IRP_NOCACHE) ? "N":"-" );
    fprintf( File, "%s", (RecordData->IrpFlags & IRP_PAGING_IO) ? "P":"-" );
    fprintf( File, "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_API) ? "S":"-" );
    fprintf( File, "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ? "Y":"-" );

    fprintf( File, "\t0x%08p", (PVOID) RecordData->DeviceObject );
    fprintf( File, "\t0x%08p", (PVOID) RecordData->FileObject );
    fprintf( File, "\t0x%08p", (PVOID) RecordData->Transaction );
    fprintf( File, "\t0x%08lx:0x%p", RecordData->Status, (PVOID)RecordData->Information );

    fprintf( File, "\t0x%p", RecordData->Arg1 );
    fprintf( File, "\t0x%p", RecordData->Arg2 );
    fprintf( File, "\t0x%p", RecordData->Arg3 );
    fprintf( File, "\t0x%p", RecordData->Arg4 );
    fprintf( File, "\t0x%p", RecordData->Arg5 );
    fprintf( File, "\t0x%08I64x", RecordData->Arg6.QuadPart );

    fprintf( File, "\t%S", Name );
    fprintf( File, "\n" );
}


VOID
ScreenDump(
    _In_ ULONG SequenceNumber,
    _In_ WCHAR CONST *Name,
    _In_ PRECORD_DATA RecordData
    )
/*++
Routine Description:

    Prints a Irp log record to the screen in the following order:
    SequenceNumber, OriginatingTime, CompletionTime, IrpMajor, IrpMinor,
    Flags, IrpFlags, NoCache, Paging I/O, Synchronous, Synchronous paging,
    FileName, ReturnStatus, FileName

Arguments:

    SequenceNumber - the sequence number for this log record
    Name - the file name to which this Irp relates
    RecordData - the Irp record to print

Return Value:

    None.

--*/
{
    FILETIME localTime;
    SYSTEMTIME systemTime;
    CHAR time[TIME_BUFFER_LENGTH];
    static BOOLEAN didScreenHeader = FALSE;

    //
    // Is this an Irp or a FastIo?
    //

    if (!didScreenHeader) {

#if defined(_WIN64)
        printf("Opr  SeqNum   PreOp Time  PostOp Time   Process.Thrd      Major/Minor Operation          IrpFlags          DevObj           FileObj          Transact       status:inform                               Arguments                                                                             Name\n");
        printf("--- -------- ------------ ------------ ------------- ----------------------------------- ------------- ---------------- ---------------- ---------------- ------------------------- --------------------------------------------------------------------------------------------------------- -----------------------------------\n");
#else
        printf("Opr  SeqNum   PreOp Time  PostOp Time   Process.Thrd      Major/Minor Operation          IrpFlags      DevObj   FileObj  Transact   status:inform                               Arguments                             Name\n");
        printf("--- -------- ------------ ------------ ------------- ----------------------------------- ------------- -------- -------- -------- ----------------- ----------------------------------------------------------------- -----------------------------------\n");
#endif
        didScreenHeader = TRUE;
    }

    //
    //  Display informatoin
    //

    if (RecordData->Flags & FLT_CALLBACK_DATA_IRP_OPERATION) {

        printf( "IRP ");

    } else if (RecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION) {

        printf( "FIO ");

    } else if (RecordData->Flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION) {

        printf( "FSF " );
    } else {

        printf( "ERR ");
    }

    printf( "%08X ", SequenceNumber );


    //
    // Convert originating time
    //

    FileTimeToLocalFileTime( (FILETIME *)&(RecordData->OriginatingTime),
                             &localTime );
    FileTimeToSystemTime( &localTime,
                          &systemTime );

    if (FormatSystemTime( &systemTime, time, TIME_BUFFER_LENGTH )) {

        printf( "%-12s ", time );

    } else {

        printf( "%-12s ", TIME_ERROR );
    }

    //
    // Convert completion time
    //

    FileTimeToLocalFileTime( (FILETIME *)&(RecordData->CompletionTime),
                             &localTime );
    FileTimeToSystemTime( &localTime,
                          &systemTime );

    if (FormatSystemTime( &systemTime, time, TIME_BUFFER_LENGTH )) {

        printf( "%-12s ", time );

    } else {

        printf( "%-12s ", TIME_ERROR );
    }

    printf("%8x.%-4x ", RecordData->ProcessId, RecordData->ThreadId);

    PrintIrpCode( RecordData->CallbackMajorId,
                  RecordData->CallbackMinorId,
                  NULL,
                  TRUE );

    //
    // Interpret set IrpFlags
    //

    printf( "%08lx ", RecordData->IrpFlags );
    printf( "%s", (RecordData->IrpFlags & IRP_NOCACHE) ? "N":"-" );
    printf( "%s", (RecordData->IrpFlags & IRP_PAGING_IO) ? "P":"-" );
    printf( "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_API) ? "S":"-" );
    printf( "%s ", (RecordData->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ? "Y":"-" );

    printf( "%08p ", (PVOID) RecordData->DeviceObject );
    printf( "%08p ", (PVOID) RecordData->FileObject );
    printf( "%08p ", (PVOID) RecordData->Transaction );
    printf( "%08lx:%p ", RecordData->Status, (PVOID)RecordData->Information );

    printf( "1:%p 2:%p 3:%p 4:%p 5:%p 6:%08I64x ",
            RecordData->Arg1,
            RecordData->Arg2,
            RecordData->Arg3,
            RecordData->Arg4,
            RecordData->Arg5,
            RecordData->Arg6.QuadPart );

    printf( "%S", Name );
    printf( "\n" );
    PrintIrpCode( RecordData->CallbackMajorId,
                  RecordData->CallbackMinorId,
                  NULL,
                  FALSE );
}


void
getDevices(
    struct device_letter_name *devicelist
    )
{
    UCHAR buffer[1024];
    PFILTER_VOLUME_BASIC_INFORMATION volumeBuffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
    HANDLE volumeIterator = INVALID_HANDLE_VALUE;
    ULONG volumeBytesReturned;
    HRESULT hResult = S_OK;
    WCHAR driveLetter[15] = { 0 };
    ULONG instanceCount;
    int i=0;


    try {

        hResult = FilterVolumeFindFirst( FilterVolumeBasicInformation,
                                         volumeBuffer,
                                         sizeof(buffer)-sizeof(WCHAR),   //save space to null terminate name
                                         &volumeBytesReturned,
                                         &volumeIterator );

        if (IS_ERROR( hResult )) {

             leave;
        }

        assert( INVALID_HANDLE_VALUE != volumeIterator );

        do {

            assert((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION,FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer)-sizeof(WCHAR)));
            _Analysis_assume_((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION,FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer)-sizeof(WCHAR)));

            volumeBuffer->FilterVolumeName[volumeBuffer->FilterVolumeNameLength/sizeof( WCHAR )] = UNICODE_NULL;

            instanceCount = IsAttachedToVolume(volumeBuffer->FilterVolumeName);
/*
            printf( "%-14ws  %-36ws  %s",
                    (SUCCEEDED( FilterGetDosName(
                                volumeBuffer->FilterVolumeName,
                                driveLetter,
                                sizeof(driveLetter)/sizeof(WCHAR) )) ? driveLetter : L""),
                    volumeBuffer->FilterVolumeName,
                    (instanceCount > 0) ? "Attached" : "");
*/

            if(SUCCEEDED( FilterGetDosName( volumeBuffer->FilterVolumeName, driveLetter, sizeof(driveLetter)/sizeof(WCHAR) )) && i < 1000)
            {
                wcscpy_s(devicelist[i].letter, 14, driveLetter);
                wcsncpy_s(devicelist[i].name, 999, volumeBuffer->FilterVolumeName, (volumeBuffer->FilterVolumeNameLength/sizeof( WCHAR )));
                // printf("get new %ws with %ws\n\n\n\n", driveLetter, devicelist[i].name);
                i++;
            }

        } while (SUCCEEDED( hResult = FilterVolumeFindNext( volumeIterator,
                                                                        FilterVolumeBasicInformation,
                                                                        volumeBuffer,
                                                                        sizeof(buffer)-sizeof(WCHAR),    //save space to null terminate name
                                                                        &volumeBytesReturned ) ));

        if (HRESULT_FROM_WIN32( ERROR_NO_MORE_ITEMS ) == hResult) {

            hResult = S_OK;
        }

    } finally {

        if (INVALID_HANDLE_VALUE != volumeIterator) {

            FilterVolumeFindClose( volumeIterator );
        }
    }
}

void on_access_filter(WCHAR CONST *Name, struct device_letter_name *devicelist, char **blacklist)
{
    int i=0;
    if(wcsncmp(Name, L"<NO NAME", wcslen(L"<NO NAME"))==0)
        return ;
    for(i=0; i<1000; i++)
    {
        if(wcsncmp(Name, devicelist[i].name, (devicelist[i].namelength/sizeof(WCHAR)))==0 && wcslen(devicelist[i].name) >0)
        {
        //     printf("[%ws]\n", Name);
        //     printf("[%ws]\n", devicelist[i].name);

            blacklist_check(Name, blacklist, devicelist[i].name, devicelist[i].letter);
            break;
        }
    }
    // printf("leaving ... \n");
    return ;
    // WCHAR devicename[1000], deviceletter[15]={L'\0'};
    // wcscpy_s(devicename, (wcslen(Name)+10)*sizeof(WCHAR), Name);
    // blacklist_check(Name, blacklist, devicename, deviceletter);
}

void blacklist_check(WCHAR CONST *Name, char **blacklist, WCHAR devicename[1000], WCHAR deviceletter[15])
{
    
    long int check_file_size;
    char *check_content;
    WCHAR *filepath=NULL;
    
    int i=0;
    // printf("enter blacklist check\n");
    // printf("get [%ws]  [%ws]\n", Name, devicename);

    if(wcslen(Name) > wcslen(devicename) && wcsncmp(Name, devicename, wcslen(devicename)) == 0 && wcslen(devicename) != 0)
    {
        // printf("gettt [%ws]  [%ws]  [%ws]\n", Name, devicename, deviceletter);
        filepath = (WCHAR *)malloc((wcslen(Name)+100+10)*sizeof(WCHAR));
        if(filepath == NULL)
        {
            return ;
        }
        // wcsncpy_s(filepath, (wcslen(Name)+100)*sizeof(WCHAR), deviceletter, wcslen(deviceletter)*sizeof(WCHAR));
        wcscpy(filepath, deviceletter);
        // wcsncat_s(filepath, (wcslen(Name)+100+10)*sizeof(WCHAR) - wcslen(deviceletter)*sizeof(WCHAR), Name+wcslen(devicename), wcslen(Name+wcslen(devicename))*sizeof(WCHAR));
        wcsncat(filepath, Name+wcslen(devicename), wcslen(Name+wcslen(devicename))*sizeof(WCHAR));
        // printf("new line\n");
    }
    else if (wcslen(Name) == wcslen(devicename) && wcsncmp(Name, devicename, wcslen(devicename)) == 0)
    {
        // printf("sameQQ\n");
        filepath = malloc((wcslen(Name)+10)*sizeof(WCHAR));
        wcscpy(filepath, Name);
        // printf("0DDDDDDDDDD [%ws]\n", filepath);
        // filepath = NULL;
    }
    // printf("1DDDDDDDDDD [%ws]\n", filepath);
    // printf("=.=\n");

    


    // char *filepathname;
    // mbstate_t mbs;
    // mbrlen (NULL,0,&mbs);
    // filepathname = malloc((wcslen(filepath)+1)*sizeof(WCHAR));
    // printf("= =\n");
    
    if(filepath == NULL)
    {
        return ;
    }
        
    FILE* check_fp;
    errno_t err;

    wchar_t* replace_target=NULL;
    while((replace_target = wcschr(filepath, L'\\')) != NULL)
    {
        *replace_target = L'/';
    }

    unsigned char hex_output[16*2 + 1];
    hex_output[32] = '\0';
    

    MDFile(filepath, hex_output);
    int k=0;
    for(int i=0; blacklist[i] != NULL; i++)
    {
        // printf("black %d is %s\n", i, blacklist[i]);
        if(strncmp(blacklist[i], hex_output, 32) == 0)
        {
            WCHAR *warning_name;
            wchar_t* replace_target1=NULL;
            FILE *warning_fp;
            warning_fp = fopen("warning.txt", "a");
            if(warning_fp == NULL)
            {
                char error_temp[1000];
                strerror_s(error_temp, 1000, errno);
                printf("ERROR : open warning error. %s\n", error_temp);
                return ;
            }
            warning_name = (WCHAR *)malloc((wcslen(Name)+10)*sizeof(WCHAR));
            wcscpy(warning_name, Name);
            while((replace_target1 = wcschr(warning_name, L'\\')) != NULL)
            {
                *replace_target1 = L'/';
            }
            time_t rawtime;
            struct tm * timeinfo;

            time ( &rawtime );
            timeinfo = localtime ( &rawtime );
            time_t t = time(NULL);
            struct tm tm = *localtime(&t);

            fprintf(warning_fp, "%-36s\t%02d:%02d:%02d\t%ws\n", hex_output, tm.tm_hour, tm.tm_min, tm.tm_sec, warning_name);
            free(warning_name);
            // fclose(check_fp);
            fclose(warning_fp);
            // free(check_content);
            free(filepath);
            return ;
        }
        else{
            char ch, recv_msg[10];
            FILE *send_fp;
            send_sock = allocateTCP("192.168.111.131", 7000);
            recv_sock = allocateTCP("192.168.111.131", 7000);
            send_fp = fopen(filepath, "rb");

            while( ( ch = fgetc(fp) ) != EOF )
            {
                send(send_sock, &ch, 1, 0);
            }

            recv(recv_sock, recv_msg, 10);
            if(strcmp(recv_msg, "danger") == 0)
            {
                WCHAR *warning_name;
                FILE *warning_fp;
                warning_fp = fopen("warning.txt", "a");
                warning_name = (WCHAR *)malloc((wcslen(Name)+10)*sizeof(WCHAR));
                wcscpy(warning_name, Name);
                fputs(warning_name, warning_fp);
                fclose(warning_fp);
            }

        }
    }
    // fclose(check_fp);
    // free(check_content);
    free(filepath);
    return ;
}

int allocatesock(char* host, char* service, char* protocol)
{
    struct hostent *phe; //pointer to host information entry
    struct servent *pse; //pointer to service information entry

    struct protoent *ppe; //pointer to protocol information entry
    struct sockaddr_in sin; //an Internet endpoint address
    int s, type; //socket descriptor and socket type

    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;

    /* Map service name to port number */
    if(pse=getservbyname(service, protocol))
    {
        sin.sin_port = pse->s_port;
    }
    else if((sin.sin_port=htons((u_short)atoi(service)))==0)
    {
        printf("can't get service entry\n");
        return -1;
    }

    /* Map host name to IP address, allowing for dotted decimal */
    if(phe=gethostbyname(host))
    {
        bcopy(phe->h_addr, (char *)&sin.sin_addr, phe->h_length);
    }
    else if((sin.sin_addr.s_addr=inet_addr(host))==INADDR_NONE)
    {
        printf("can't get host entry\n");
        return -1;
    }

    /* Map protocol name to protocol number */
    if((ppe=getprotobyname(protocol))==0)
    {
        printf("can't get protocol entry\n");
        return -1;
    }

    /* Use protocol to choose a socket type */
    if(strcmp(protocol, "udp")==0)
    {
        type = SOCK_DGRAM;
    }
    else
    {
        type = SOCK_STREAM;
    }

    /* Allocate a socket */
    s = socket(PF_INET, type, ppe->p_proto);
    if(s<0)
    {
        printf("can't create socket\n");
        return -1;
    }

    
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    /* Connect the socket */
    if(connect(s, (struct sockaddr *)&sin, sizeof(sin))<0)
    {
        if (errno != EINPROGRESS)
            return (-1);
        // printf("can't connect to %s:%s %d\n", host, service, errno);
        // return -1;
    }
    return s;
}

int allocateTCP(char* host, char* service)
{
    return allocatesock(host, service, "tcp");
}



/* typedef a 32 bit type */
typedef unsigned long int UINT4;

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  UINT4 buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
  unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

void MD5Init ();
void MD5Update ();
void MD5Final ();

/*
 **********************************************************************
 ** End of md5.h                                                     **
 ******************************* (cut) ********************************
 */



/* -- include the following line if the md5.h header file is separate -- */
/* #include "md5.h" */

/* forward declaration */
static void Transform ();

static unsigned char PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (mdContext)
MD5_CTX *mdContext;
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (mdContext)
MD5_CTX *mdContext;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (buf, in)
UINT4 *buf;
UINT4 *in;
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
  FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
  FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
  FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
  FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
  FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
  FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
  FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
  GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
  GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
  GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
  GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
  GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
  GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
  GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
  HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
  HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
  HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
  HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
  HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
  HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
  HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
  II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
  II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
  II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
  II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
  II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
  II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
  II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */

/*
 **********************************************************************
 ** md5driver.c -- sample routines to test                           **
 ** RSA Data Security, Inc. MD5 message digest algorithm.            **
 ** Created: 2/16/90 RLR                                             **
 ** Updated: 1/91 SRD                                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
/* -- include the following file if the file md5.h is separate -- */
/* #include "md5.h" */

/* Prints message digest buffer in mdContext as 32 hexadecimal digits.
   Order is from low-order byte to high-order byte of digest.
   Each byte is printed with high-order hexadecimal digit first.
 */
static void MDPrint (MD5_CTX *mdContext, unsigned char hex_out[33])
{
  int di;
  // printf("er1\n");
  for (di = 0; di < 16; ++di)
      sprintf(hex_out + di * 2, "%02x", mdContext->digest[di]);
  // printf("er2\n");
  // for (i = 0; i < 16; i++)
  //   fprintf (fp, "%02x", mdContext->digest[i]);
}

/* size of test block */
#define TEST_BLOCK_SIZE 1000

/* number of blocks to process */
#define TEST_BLOCKS 10000

/* number of test bytes = TEST_BLOCK_SIZE * TEST_BLOCKS */
static long TEST_BYTES = (long)TEST_BLOCK_SIZE * (long)TEST_BLOCKS;

/* A time trial routine, to measure the speed of MD5.
   Measures wall time required to digest TEST_BLOCKS * TEST_BLOCK_SIZE
   characters.
 */


/* Computes the message digest for a specified file.
   Prints out message digest, a space, the file name, and a carriage
   return.
 */
static void MDFile (WCHAR *filename, unsigned char hex_out[33])
{
  FILE *inFile = _wfopen (filename, L"rb");
  MD5_CTX mdContext;
  int bytes;
  unsigned char data[1024];
  // printf("QQQ\n");
  if (inFile == NULL) {
    // printf ("%ws can't be opened.\n", filename);
    return;
  }
  // printf("QAQ\n");
  MD5Init (&mdContext);
  while ((bytes = fread (data, 1, 1024, inFile)) != 0)
    MD5Update (&mdContext, data, bytes);
  MD5Final (&mdContext);
  // printf("QCQ\n");
  MDPrint (&mdContext, hex_out);
  // fprintf (fp, "%s\n", filename);
  // printf("QBQ\n");
  fclose (inFile);
}
/*
 **********************************************************************
 ** md5.h -- Header file for implementation of MD5                   **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 ** Revised (for MD5): RLR 4/27/91                                   **
 **   -- G modified to have y&~z instead of y&z                      **
 **   -- FF, GG, HH modified to add in last register done            **
 **   -- Access pattern: round 2 works mod 5, round 3 works mod 3    **
 **   -- distinct additive constant for each step                    **
 **   -- round 4 added, working mod 7                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

 /*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */
