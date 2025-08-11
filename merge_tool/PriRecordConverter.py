import os
import intelhex

#https://blog.csdn.net/u012502355/article/details/52709181
#https://blog.csdn.net/lianyunyouyou/article/details/106955710


# define BOOT_INTERRUPT_BASE_ADDRESS  0x00080000U
# define APP1_INTERRUPT_BASE_ADDRESS  0x00088000U
# define APP2_INTERRUPT_BASE_ADDRESS  0x00108000U
# Bank0
# define BANK0_HEADER_FW_VER_ADDRESS  0x00097FE0U
# define BANK0_CHECKSUM_ADDRESS       0x00097FF0U
# define BANK0_START_ADDRESS          0x00088000U
# define BANK0_END_ADDRESS            0x00098000U
# Bank1
# define BANK1_HEADER_FW_VER_ADDRESS  0x000B7FE0U
# define BANK1_CHECKSUM_ADDRESS       0x000B7FF0U
# define BANK1_START_ADDRESS          0x000A8000U
# define BANK1_END_ADDRESS            0x000B8000U
# Bank4
# define BANK4_CHECKSUM_ADDRESS       0x00102FF0U
# define BANK4_START_ADDRESS          0x00100000U
# define BANK4_END_ADDRESS            0x00103000U

#Pri
u16crctab16 = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78]
# print(u16crctab16)

def MC56F8_GetCheckSum(Length,u8BufferArry = []):
    CheckSum = 0
    for index in range(0, Length, 1):
        CheckSum += u8BufferArry[index]

    #CheckSum = 0xFF - (0x00FF & CheckSum)
     
    return (0xFF & CheckSum) 

def MC56F8_CreateRecordsByBin(output_file,u32OffsetAddress,u32Page,u8Image_ByteArray,Records = []):

    strRecordsList = []
    strRecordsList.clear()
    u32HexAddress = 0
    
    #:020000040008F2
    u8BufferArray = []
    u8BufferArray.clear()
    u32HexPage = u32Page
    u8DataLength = 2
    strType = "04"
    u32HexChecksum = u8DataLength
    u32HexChecksum += (u32HexAddress & 0xFF)
    u32HexChecksum += ((u32HexAddress >> 8 ) & 0xFF)
    u32HexChecksum += int(strType,10)
    u32HexChecksum += (u32HexPage & 0xFF)
    u32HexChecksum += ((u32HexPage >> 8 ) & 0xFF) 
    u32HexChecksum = (256 - (u32HexChecksum & 0xFF)) & 0xFF
    strHexBuffer = ":" + "{:02X}".format(u8DataLength) + "{:04X}".format(u32HexAddress) + strType + "{:04X}".format(u32HexPage) + "{:02X}".format(u32HexChecksum)   
    strRecordsList.append(strHexBuffer)

    #:20000800B2BDAABDA2BDFE048BA986A402005BA58F0581D01E42A8A97648228202008F05B3
    u8BufferArray = []
    u8BufferArray.clear()
    u32HexAddress = int(u32OffsetAddress) 
    u8CheckSum = 0

    u8DataLength = 0x20
    
    for i in range(0, len(u8Image_ByteArray), u8DataLength):
        strType = "00"
        
        u32HexChecksum = u8DataLength
        u32HexChecksum += (u32HexAddress & 0xFF)
        u32HexChecksum += ((u32HexAddress >> 8 ) & 0xFF)
        u32HexChecksum += int(strType,10)
        u8BufferArray.clear() 
        for j in range(0, u8DataLength, 1):
            if((i + j) <len(u8Image_ByteArray)):
                u8BufferArray.append(u8Image_ByteArray[i+j])

        u8CheckSum = (256 - (u32HexChecksum + MC56F8_GetCheckSum(len(u8BufferArray), u8BufferArray) & 0xFF))&0xFF
        
        u8BufferArray.append(u8CheckSum)

        strHexBuffer = ":" + "{:02X}".format(u8DataLength) + "{:04X}".format(u32HexAddress&0xFFFF) + strType
        for k in range(0, len(u8BufferArray), 1):
            strHexBuffer += "{:02X}".format(u8BufferArray[k])

        strRecordsList.append(strHexBuffer)  
        u32HexAddress = (u32HexAddress + int(u8DataLength / 2))  # word address
        if( (u32HexAddress & 0xFFFF)== 0):
            u32Page += 1
            u8BufferArray.clear()
            u32HexPage = u32Page
            strType = "04"
            u32HexChecksum = 2
            u32HexChecksum += (u32HexAddress & 0xFF)
            u32HexChecksum += ((u32HexAddress >> 8 ) & 0xFF)
            u32HexChecksum += int(strType,10)
            u32HexChecksum += (u32HexPage & 0xFF)
            u32HexChecksum += ((u32HexPage >> 8 ) & 0xFF) 
            u32HexChecksum = (256 - (u32HexChecksum & 0xFF)) & 0xFF
            strHexBuffer = ":" + "{:02X}".format(2) + "{:04X}".format(u32HexAddress & 0xFFFF) + strType + "{:04X}".format(u32HexPage) + "{:02X}".format(u32HexChecksum) 
            strRecordsList.append(strHexBuffer)     
            
    # Save original file
    Save_File = open(output_file, 'a')
    #Save_File.writelines(strRecordsList)
    for i in range(0, len(strRecordsList), 1):
        Save_File.write(strRecordsList[i]+"\n")
    Save_File.close()

def MC56F8_GetBinList(u32FlashSize,u32BinStartAddress,bin_Sizes,PageOffset,strFilePath='',Records = []):

    AddrStart = u32BinStartAddress + PageOffset*0x10000*2
    AddrEnd = AddrStart + bin_Sizes
    u8FlashBinArray = []
    u8FlashBinArray.clear()

    u8Image_ByteArray = []
    u8Image_ByteArray.clear()

    u8FlashBinArrayAddr = 0
    for i in range(0, u32FlashSize, 1):
        u8FlashBinArray.append(0xFF)

    #Hex or S-record File
    file_ReadHex = open(strFilePath, 'r')
    strLineBuffer = ""
    strHexBuffer = ""
    strPage = 0


    for strLineBuffer in file_ReadHex:
        strLineBuffer = strLineBuffer.strip('\n') #':020000040000FA\n'

        #:20000800FE0A7C491E4876483F8B520060068F084FDA021F76482613064E76483F9B52004F
 
        strRecordLength = strLineBuffer[1:1+2]  # 1-2
        strHexAddress = strLineBuffer[3: 3+4]   # 3-6
        strType = strLineBuffer[7: 7+2]         # 7-8 
        strDataBuffer = strLineBuffer[9:-2]     # 
        strCheckSum = strLineBuffer[-2:]        # 截取字符串末尾两个字符

        u32RecordLength = int(strRecordLength, 16)  #1.2
        u32HexAddress = int(strHexAddress, 16)   #3-4-5-6
        strHexBuffer = strDataBuffer 
        u8CheckSum = int(strCheckSum, 16)

        if (strType == "04"):
            strPage = int(strHexBuffer, 16)
        elif (strType == "01"):
            pass
        elif (strType == "00"):
            u8Image_ByteArray.clear()

            for indexFlash in range(0, len(strHexBuffer), 2):#两字符合并成一个16进制字节  
                u8Image_ByteArray.append(int(strHexBuffer[indexFlash:indexFlash+2],16))
                
            Addr = (u32HexAddress + strPage*0x10000) * 2
            if((Addr >= AddrStart) and (Addr < AddrEnd)): 
                # print("Address:"+"{:08X}".format((u32HexAddress + strPage*0x10000)))
                # print("Data:"+ strHexBuffer)  
                u8FlashBinArrayAddr = Addr - AddrStart       
                for u32ArrayIndex in range(0, len(u8Image_ByteArray), 1):
                    u8FlashBinArray[u8FlashBinArrayAddr + u32ArrayIndex] = u8Image_ByteArray[u32ArrayIndex]  


    file_ReadHex.close()        


    u8BinArray = []
    u8BinArray.clear()
    for i in range(0, bin_Sizes, 1):
        u8BinArray.append(u8FlashBinArray[i])

    #f=open("binfile.bin","wb")
    #f.write(u8FlashBinArray)
    #f.close()

    return u8BinArray

def MC56F8_CreateBinFile(offset,output_bin_file,u8Image_ByteArray=[]):
    u8BinArray = bytearray()
    u8BinArray.clear()
    for i in range(0, len(u8Image_ByteArray), 1):
        u8BinArray.append(u8Image_ByteArray[i])

    f=open(output_bin_file,"wb")
    f.write(u8BinArray)
    f.close()

    output_hex_file = os.path.splitext(output_bin_file)[0] + ".hex"
    intelhex.bin2hex(output_bin_file,output_hex_file,offset)


if __name__ == "__main__":
## Pri Part
    boot_u32FlashSize = 64*1024 #64KB
    # boot area
    boot_InputFile = "./TMS320F28P650DH6_pfc_cpu1_boot.hex"
    boot_Records = []
    boot_StartAddress=0x0000
    boot_page = 0x0008
    boot_Sizes=0x8000  # word address

    if(True == os.path.exists(boot_InputFile)): # True/False
        u8BootImageArray = MC56F8_GetBinList(boot_u32FlashSize,boot_StartAddress*2,boot_Sizes*2,boot_page,boot_InputFile,boot_Records)

    # app1 area
    app1_u32FlashSize = 72*1024
    app1_InputFile = "./TMS320F28P650DH6_pfc_cpu1_app.hex"
    app1_Records = []
    app1_StartAddress =0x8000
    app1_Sizes = 0x9000 #word size
    app1_Page = 0x0008
    Checksum_Sizes= (app1_Sizes - 0x10)*2
    
    app1_cal_u32FlashSize = 2*1024
    app1_cal_InputFile  = "./TMS320F28P650DH6_pfc_cpu1_app.hex"
    app1_cal_Records = []
    app1_cal_StartAddress =0xC000
    app1_cal_Sizes = 0x400 #word size
    app1_cal_Page = 0x000B

    u8App1ImageArrayWithoutCali = []
    CPU1_u16CRC = 0xFFFF
    if(True == os.path.exists(app1_InputFile)): # True/False
        u8App1ImageArray = MC56F8_GetBinList(app1_u32FlashSize,app1_StartAddress*2,app1_Sizes*2,app1_Page,app1_InputFile,app1_Records)
        u8App1CalArray =   MC56F8_GetBinList(app1_cal_u32FlashSize,app1_cal_StartAddress*2,app1_cal_Sizes*2,app1_cal_Page,app1_cal_InputFile,app1_cal_Records)
        
        # Checksum1
        for i in range(0, Checksum_Sizes, 1):
            CPU1_u16CRC = (CPU1_u16CRC >> 8) ^ u16crctab16[(CPU1_u16CRC ^ u8App1ImageArray[i]) & 0xFF]
        u8App1ImageArray[app1_Sizes*2 - 2] = (CPU1_u16CRC & 0xFF)      # CRC Lower byte
        u8App1ImageArray[app1_Sizes*2 - 1] = (CPU1_u16CRC >> 8 & 0xFF) # CRC Higher byte
        print("CPU1_CRC16 CheckSum:" + "{:04X}".format(CPU1_u16CRC & 0xFFFF))
        # print("CPU1_CRC16 CheckSum:" + str(CPU1_u16CRC))
        for i in range(0, (app1_Sizes*2), 1):
            u8App1ImageArrayWithoutCali.append(u8App1ImageArray[i]) #APP1 DATA
        
    # app2 area
    app2_u32FlashSize = 24*1024
    app2_InputFile = "./TMS320F28P650DH6_pfc_cpu2_app.hex"
    app2_Records = []
    app2_StartAddress =0x0000
    app2_Sizes = 0x3000 #word size
    app2_Page = 0x0010
    Checksum_Sizes= (app2_Sizes - 0x10)*2

    u8App2ImageArrayWithoutCali = []
    CPU2_u16CRC = 0xFFFF
    if(True == os.path.exists(app2_InputFile)): # True/False
        u8App2ImageArray = MC56F8_GetBinList(app2_u32FlashSize,app2_StartAddress*2,app2_Sizes*2,app2_Page,app2_InputFile,app2_Records)
        
        # Checksum2
        for i in range(0, Checksum_Sizes, 1):
            CPU2_u16CRC = (CPU2_u16CRC >> 8) ^ u16crctab16[(CPU2_u16CRC ^ u8App2ImageArray[i]) & 0xFF]
        u8App2ImageArray[app2_Sizes*2 - 2] = (CPU2_u16CRC & 0xFF)      # CRC Lower byte
        u8App2ImageArray[app2_Sizes*2 - 1] = (CPU2_u16CRC >> 8 & 0xFF) # CRC Higher byte
        print("CPU2_CRC16 CheckSum:" + "{:04X}".format(CPU2_u16CRC & 0xFFFF))
        # print("CPU2_CRC16 CheckSum:" + str(CPU2_u16CRC))
        for i in range(0, (app2_Sizes*2), 1):
            u8App2ImageArrayWithoutCali.append(u8App2ImageArray[i]) #APP2 DATA

    # ALL combine
    Combine_u32FlashSize = app1_u32FlashSize + app1_cal_u32FlashSize + app2_u32FlashSize
    Combine_Sizes = app1_Sizes + app1_cal_Sizes + app2_Sizes #word size

    Combine_app1bak_Page = 0x000A
    Combine_app1bak_StartAddress = 0x8000
    Combine_app1bak_Records = []
    Combine_app2bak_Page = 0x000B
    Combine_app2bak_StartAddress = 0x1000
    Combine_app2bak_Records = []

    # App1 & App2 combine ->->-> UseToBoot
    u8App1App2ToBootImageArray = []
    Origin_Page = 0x0000
    Origin_ZeroStartAddress = 0x0000
    Origin_ZeroAddress = (Origin_Page<<16) + Origin_ZeroStartAddress
    # print("{:08X}".format(Origin_ZeroAddress))
    u8App1App2ToBootImageArray = u8App1ImageArrayWithoutCali + u8App2ImageArrayWithoutCali

    # Add Bak1 & Bak2
    Combine_output_file = "./TMS320F28P650DH6_pfc_combine_B0boot_B0cpu1_B1cpu1bak_B1cpu2bak_B1cali_CS_" + "{:04X}".format(CPU1_u16CRC) + ".hex"
    Save_File = open(Combine_output_file, 'w')
    Save_File.close()
    MC56F8_CreateRecordsByBin(Combine_output_file,boot_StartAddress,boot_page,u8BootImageArray,boot_Records)
    MC56F8_CreateRecordsByBin(Combine_output_file,app1_StartAddress,app1_Page,u8App1ImageArrayWithoutCali,app1_Records)
    MC56F8_CreateRecordsByBin(Combine_output_file,Combine_app1bak_StartAddress,Combine_app1bak_Page,u8App1ImageArrayWithoutCali,Combine_app1bak_Records)
    MC56F8_CreateRecordsByBin(Combine_output_file,Combine_app2bak_StartAddress,Combine_app2bak_Page,u8App2ImageArrayWithoutCali,Combine_app2bak_Records)
    MC56F8_CreateRecordsByBin(Combine_output_file,app1_cal_StartAddress,app1_cal_Page,u8App1CalArray,app1_cal_Records)
    Save_File = open(Combine_output_file, 'a')
    Save_File.write(":00000001FF\n")
    Save_File.close()
    
    Combine_output_file = "./TMS320F28P650DH6_pfc_B4cpu2_CS_" + "{:04X}".format(CPU2_u16CRC) + ".hex"
    #清除原输出文件
    Save_File = open(Combine_output_file, 'w')
    Save_File.close()
    MC56F8_CreateRecordsByBin(Combine_output_file,app2_StartAddress,app2_Page,u8App2ImageArrayWithoutCali,app2_Records)
    Save_File = open(Combine_output_file, 'a')
    Save_File.write(":00000001FF\n")
    Save_File.close()
    
    # # App1 & App2 combine ->->-> UseToBoot
    # Combine_output_file = "./Primary_TMS320F28P650DH6_pfc_combine_B0cpu1_B4cpu2_UseToBoot.hex"
    # Save_File = open(Combine_output_file, 'w')
    # Save_File.close()
    # MC56F8_CreateBinFile(Origin_ZeroAddress,Combine_output_file,u8App1App2ToBootImageArray)
    
    print("Run Over")