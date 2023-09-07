import sys
import time

def MFT_analysis(data, VBR_offset, MFT_offset):
    MFT_ptr = MFT_offset
    # print(MFT_ptr)
    restore_list = []
    MFT_count = 0

    while(True):
        if(data[MFT_ptr:MFT_ptr+4] != b'\x46\x49\x4C\x45'):
            if((MFT_count >= 12 and MFT_count <= 23) == 0):
                break
            else:
                 MFT_ptr += 1024
                 MFT_count += 1
                 continue
            
        if(int.from_bytes(data[MFT_ptr+22:MFT_ptr+23], 'little') == 0):
            restore_list.append(data[MFT_ptr:MFT_ptr + 1024])

        MFT_ptr += 1024
        MFT_count += 1

    # print(restore_list)
    # 파일 복구
    for i in range(0, len(restore_list)):
        # print(len(restore_list), i)
        # if(i == 19):
        #     with open(f"./result/mft20.dat", "wb") as restore_file:
        #         restore_file.write(bytes(restore_list[20]))
        # 속성 시작 주소
        Attribute_start_offset = int.from_bytes(restore_list[i][4:6], 'little') + ((int.from_bytes(restore_list[i][6:8], 'little') * 2) + 2)
        # print(Attribute_start_offset)
        # 각 속성 추적
        Attribute_ptr = Attribute_start_offset
        while(True):
            # MFT Entry End Marker를 이용하여 반복문 탈출 시점 결정
            # if(i == 19):
            #     print(restore_list[i][Attribute_ptr:Attribute_ptr+4])
            #     print(Attribute_ptr)
            #     time.sleep(2)
            if(restore_list[i][Attribute_ptr:Attribute_ptr+4] == b'\xFF\xFF\xFF\xFF'):
                break
            if(int.from_bytes(restore_list[i][Attribute_ptr:Attribute_ptr+4], 'little') == 0x30):
                file_name_length = (restore_list[i][Attribute_ptr + 88]) * 2
                # print(file_name_length)
                file_name = restore_list[i][Attribute_ptr + 90: (Attribute_ptr + 90) + file_name_length]
                # print(file_name)
                file_name = file_name.decode('UTF-16')
                # print(file_name)
                # with open(f"./result/list.txt", "a") as file_list:
                #     file_list.write(f"{file_name}\n")
            if(int.from_bytes(restore_list[i][Attribute_ptr:Attribute_ptr+4], 'little') == 0x80):
                # Non-resident 방식 확인
                if(restore_list[i][Attribute_ptr + 8] == 0x1):
                    # 런리스트 주소 확인
                    run_list_start_offset = int.from_bytes(restore_list[i][Attribute_ptr + 32: Attribute_ptr + 34], 'little')
                    run_list_start_offset = Attribute_ptr + run_list_start_offset
                    # print(run_list_start_offset)

                    # 런리스트 주소가 가리키는 최종 런리스트 주소 값.
                    real_data_offset_calc = restore_list[i][run_list_start_offset]
                    # print(real_data_offset_calc)

                    # 런리스트 해석
                    real_data_cluster_size = real_data_offset_calc % 0x10
                    real_data_offset = real_data_offset_calc / 0x10
                    # print(real_data_cluster_size, int(real_data_offset))
                    # print(int.from_bytes(restore_list[i][run_list_start_offset+real_data_cluster_size+1:(run_list_start_offset+real_data_cluster_size+1)+int(real_data_offset)], 'little'))

                    # 런리트를 이용해 구한 실제 파일 주소와 사이즈, 클러스터 사이즈
                    real_data_offset = int.from_bytes(restore_list[i][run_list_start_offset+real_data_cluster_size+1:(run_list_start_offset+real_data_cluster_size+1)+int(real_data_offset)], 'little')
                    real_data_cluster_size = int.from_bytes(restore_list[i][run_list_start_offset + real_data_cluster_size: run_list_start_offset + real_data_cluster_size + 1], 'little')
                    real_data_size = int.from_bytes(restore_list[i][run_list_start_offset-8:run_list_start_offset], 'little')
                    # print(real_data_size)
                    # print(real_data_cluster_size)

                    # print(real_data_offset)

                    real_data_offset = ((real_data_offset * 8)*512) + VBR_offset

                    # print(real_data_offset)

                    try:
                        with open(f"./result/{file_name}", "wb") as restore_file:
                            restore_file.write(bytes(data[real_data_offset:real_data_offset+real_data_size]))
                    except:
                        print(f"{file_name}")
                        
            
            Attribute_ptr = Attribute_ptr + int.from_bytes(restore_list[i][Attribute_ptr + 4:Attribute_ptr + 6], 'little')

def VBR_analysis(data, first_LBA, Last_LBA):
    VBR_offset = first_LBA * 512

    sector_per_cluster = data[VBR_offset+13]
    MFT_offset = ((int.from_bytes(data[VBR_offset+48:VBR_offset+56], 'little') * sector_per_cluster) * 512) + VBR_offset

    return VBR_offset, MFT_offset


def GPT_analysis(data, GPT_Header_offset):
    #GPT Header
    GPT_Header_size = int.from_bytes(data[GPT_Header_offset+12:GPT_Header_offset+16], 'little')
    GPT_Header = data[GPT_Header_offset:GPT_Header_offset+GPT_Header_size]

    # GPT Partition Entry
    activate_GPT_Partition_Entry = []
    GPT_Partition_Entry_offset = GPT_Header_offset + 512    # (0x400)
    GPT_Partition_Entry = data[GPT_Partition_Entry_offset:GPT_Partition_Entry_offset+16384] # 16384 = 0x4000 (최대 파티션 128개)
    for i in range(0, 128):
        if(GPT_Partition_Entry[i*128:(i*128)+8] == b'\x00\x00\x00\x00\x00\x00\x00\x00'):
            break
        activate_GPT_Partition_Entry.append(GPT_Partition_Entry[i*128:(i+1)*128])

    # GPT Partition Entry → Basic data partition
    # 사용자의 데이터가 저장된 영역
    data_restore_Partition = []
    for i in range(0, len(activate_GPT_Partition_Entry)):
        if(activate_GPT_Partition_Entry[i][56:96] == b'\x42\x00\x61\x00\x73\x00\x69\x00\x63\x00\x20\x00\x64\x00\x61\x00\x74\x00\x61\x00\x20\x00\x70\x00\x61\x00\x72\x00\x74\x00\x69\x00\x74\x00\x69\x00\x6F\x00\x6E\x00'):
            data_restore_Partition.append(activate_GPT_Partition_Entry[i])

    # for i in range(0, len(data_restore_Partition)):
    # 임시로 한 개 파티션 고정
    fix = data_restore_Partition[0]

    first_LBA = int.from_bytes(fix[32:40], 'little')
    Last_LBA = int.from_bytes(fix[40:48], 'little')

    return first_LBA, Last_LBA



if __name__ == '__main__':
    with open(sys.argv[1], "rb") as imaging_file:
        data = imaging_file.read()

    Partition_table_entry = []

    # Partition table
    for i in range(0,4):
        Partition_table_entry.append(data[446+(16*i):446+(16*(i+1))])

    for i in range(0,4):
        if(Partition_table_entry[i] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
            continue
        else:
            # GPT Partition
            if(Partition_table_entry[i][4] == 0xEE):
                # 1 sector -> 512 bytes
                # GPT 구조 분석
                GPT_Header_offset = int.from_bytes(Partition_table_entry[i][8:12], 'little') * 512
                first_LBA, Last_LBA = GPT_analysis(data, GPT_Header_offset)
                # VBR 구조 분석
                VBR_offset, MFT_offset = VBR_analysis(data, first_LBA, Last_LBA)
                # MFT 구조 분석
                MFT_analysis(data, VBR_offset, MFT_offset)