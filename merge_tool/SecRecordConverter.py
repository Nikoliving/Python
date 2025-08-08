import os
import intelhex

#Sec
u16CRC16Table = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]
# print(u16CRC16Table)

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

    u32FlashBinArrayAddr = 0
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
                
            Addr = u32HexAddress + strPage*0x10000 * 2    #某数据帧的初始地址
            if((Addr >= AddrStart) and (Addr < AddrEnd)): 
                # print("Address:"+"{:08X}".format((u32HexAddress + strPage*0x10000)))
                # print("Data:"+ strHexBuffer)  
                u32FlashBinArrayAddr = Addr - AddrStart       
                
                if((u32FlashBinArrayAddr + len(u8Image_ByteArray))> bin_Sizes):
                    u8LenImage_Limit = bin_Sizes - u32FlashBinArrayAddr
                else:
                    u8LenImage_Limit = len(u8Image_ByteArray)

                for u32ArrayIndex in range(0, u8LenImage_Limit, 1):
                # for u32ArrayIndex in range(0, len(u8Image_ByteArray), 1):
                    u8FlashBinArray[u32FlashBinArrayAddr + u32ArrayIndex] = u8Image_ByteArray[u32ArrayIndex]


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

def pretty_print_hex(a, l=8, indent=''):
    """
    Format a list/bytes/bytearray object into a formatted ascii hex string
    """
    s = ''
    a = bytearray(a)
    for x in range(0, len(a), l):
        s += indent + ''.join(['0x'+'%02X, ' % y for y in a[x:x+l]])+'\n'
    return s

if __name__ == "__main__":
# ## Sec Part
    Sec_app_Page = 0x0000 #Word Page

    Sec_raw_StartAddress = 0x0000 #Word Address
    Sec_raw_u32FlashSize =  260*1024 #Byte size
    Sec_raw_Sizes = 0x20800 #Word size

    Sec_app_StartAddress = 0x9000 #Word Address
    Sec_app_u32FlashSize = 256*1024 #Byte size
    Sec_app_Sizes = 0x20000 #Word size
    Sec_app_InputFile = "./Master_CH508.X.production.hex"
    Sec_app_Records = []

    Sec_Header_Page = 0x0005 #Byte Page
    Sec_Header_StartAddress = 0x2000 #Byte Address
    Sec_Header_Sizes = 1984 #Byte size
    Sec_Header_u32FlashSize = 1984  #Byte size
    Sec_Header_InputFile = "./Header_Signature.hex"
    Sec_Header_Records = []

    Sec_app_Header_u32FlashSize = 260*1024 #Byte size #Sec_app_u32FlashSize + Sec_Header_u32FlashSize + Reserved

    Sec_app_Checksum_Offset = 4
    Sec_app_Checksum_Sizes = Sec_app_Sizes*2 - Sec_app_Checksum_Offset

    u8SecAppImageArrayWithoutCali = []

    u16Sec_app_RAW_CRC16 = 0
    u32Sec_app_CHECKSUM = 0

    if((True == os.path.exists(Sec_app_InputFile))
        & (True == os.path.exists(Sec_Header_InputFile))): # True/False
        # u8SecRawImageArray = MC56F8_GetBinList(Sec_raw_u32FlashSize,Sec_raw_StartAddress*2,Sec_raw_Sizes*2,Sec_app_Page,Sec_app_InputFile,Sec_app_Records)
        u8SecAppImageArray = MC56F8_GetBinList(Sec_app_u32FlashSize,Sec_app_StartAddress*2,Sec_app_Sizes*2,Sec_app_Page,Sec_app_InputFile,Sec_app_Records)
        u8SecHeaderArray = MC56F8_GetBinList(Sec_Header_u32FlashSize,Sec_Header_StartAddress,Sec_Header_Sizes,Sec_Header_Page,Sec_Header_InputFile,Sec_Header_Records)
        
        # print("u8SecRawImageArray:")
        # print(pretty_print_hex(u8SecRawImageArray,16,"    "))
        # print("u8SecAppImageArray:")
        # print(pretty_print_hex(u8SecAppImageArray,16,"    "))
        # print("u8SecHeaderArray:")
        # print(pretty_print_hex(u8SecHeaderArray,16,"    "))

        # Sec APP Checksum
        for i in range(0, Sec_app_Checksum_Sizes, 1):
            u16Sec_app_RAW_CRC16 = (u16Sec_app_RAW_CRC16 >> 8) ^ u16CRC16Table[((u16Sec_app_RAW_CRC16 & 0xFF) ^ u8SecAppImageArray[i])]
        u32Sec_app_CHECKSUM = (u16Sec_app_RAW_CRC16 & 0xFFFF)<<16
        print("SEC CPU CRC16 CheckSum:" + "{:08X}".format(u32Sec_app_CHECKSUM))

        u8SecAppImageArray[Sec_app_Sizes*2 - 4] = (u32Sec_app_CHECKSUM >> 16 & 0xFF)      # CRC Lower byte
        u8SecAppImageArray[Sec_app_Sizes*2 - 3] = (u32Sec_app_CHECKSUM >> 24 & 0xFF)      # CRC Higher byte
        u8SecAppImageArray[Sec_app_Sizes*2 - 2] = 0x00                                    # 
        u8SecAppImageArray[Sec_app_Sizes*2 - 1] = 0x00                                    # 

        # print("L:" + "{:02X}".format(u8SecAppImageArray[Sec_app_Sizes*2 - 4]))
        # print("H:" + "{:02X}".format(u8SecAppImageArray[Sec_app_Sizes*2 - 3]))
        # print("00:" + "{:02X}".format(u8SecAppImageArray[Sec_app_Sizes*2 - 2]))
        # print("01:" + "{:02X}".format(u8SecAppImageArray[Sec_app_Sizes*2 - 1]))

        for i in range(0, (Sec_app_Sizes*2), 1):
            u8SecAppImageArrayWithoutCali.append(u8SecAppImageArray[i]) #Sec APP DATA
        # for i in range(0, (Sec_Header_Sizes), 1):
        #     u8SecAppImageArrayWithoutCali.append(u8SecHeaderArray[i]) #Header APP DATA
        
        # print("u8SecAppImageArrayWithoutCali:")
        # print(pretty_print_hex(u8SecAppImageArrayWithoutCali,16,"    "))

    Combine_output_file = "./Flex_M1279207-902_P4020_V00000000(App)_" + "{:08X}".format(u32Sec_app_CHECKSUM) + ".hex"
    #清除原输出文件
    Save_File = open(Combine_output_file, 'w')
    Save_File.close()
    MC56F8_CreateBinFile(Sec_raw_StartAddress * 2,Combine_output_file,u8SecAppImageArrayWithoutCali)



    print("Run Over")