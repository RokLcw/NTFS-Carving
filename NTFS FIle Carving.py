import sys
import os
import time

def MFT_analysis(data, restore_Partition_cnt, VBR_offset, MFT_offset):
    for partition_cnt in range(0, restore_Partition_cnt):
        try:
            os.mkdir(f"./result/data{partition_cnt}")
        except Exception as e:
            print(f"{e}")

        MFT_ptr = MFT_offset[partition_cnt]
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
            # MFT 플래그 확인
            if(int.from_bytes(data[MFT_ptr+22:MFT_ptr+23], 'little') == 0):
                restore_list.append(data[MFT_ptr:MFT_ptr + 1024])

            MFT_ptr += 1024
            MFT_count += 1
        
        # 파일 복구
        for i in range(0, len(restore_list)):
            # 속성 시작 주소
            Attribute_start_offset = int.from_bytes(restore_list[i][20:22], 'little')
            # 각 속성 추적
            Attribute_ptr = Attribute_start_offset
            while(True):
                # MFT Entry End Marker를 이용하여 반복문 탈출 시점 결정
                if(restore_list[i][Attribute_ptr:Attribute_ptr+4] == b'\xFF\xFF\xFF\xFF'):
                    break
                # 파일명 복구
                if(int.from_bytes(restore_list[i][Attribute_ptr:Attribute_ptr+4], 'little') == 0x30):
                    file_name_length = (restore_list[i][Attribute_ptr + 88]) * 2
                    file_name = restore_list[i][Attribute_ptr + 90: (Attribute_ptr + 90) + file_name_length]
                    file_name = file_name.decode('UTF-16')  # UTF-16 디코딩

                if(int.from_bytes(restore_list[i][Attribute_ptr:Attribute_ptr+4], 'little') == 0x80):
                    # Non-resident 방식 확인
                    if(restore_list[i][Attribute_ptr + 8] == 0x1):
                        # 런리스트 주소 확인
                        run_list_start_offset = int.from_bytes(restore_list[i][Attribute_ptr + 32: Attribute_ptr + 34], 'little')
                        run_list_start_offset = Attribute_ptr + run_list_start_offset

                        # 런리스트 주소가 가리키는 최종 런리스트 주소 값.
                        real_data_offset_calc = restore_list[i][run_list_start_offset]

                        # 런리스트 해석
                        real_data_cluster_size = real_data_offset_calc % 0x10
                        real_data_offset = real_data_offset_calc / 0x10

                        # 런리트를 이용해 구한 실제 파일 주소와 사이즈, 클러스터 사이즈
                        real_data_offset = int.from_bytes(restore_list[i][run_list_start_offset+real_data_cluster_size+1:(run_list_start_offset+real_data_cluster_size+1)+int(real_data_offset)], 'little')
                        real_data_cluster_size = int.from_bytes(restore_list[i][run_list_start_offset + 1: run_list_start_offset + real_data_cluster_size + 1], 'little')
                        real_data_size = int.from_bytes(restore_list[i][run_list_start_offset-8:run_list_start_offset], 'little')

                        real_data_offset = ((real_data_offset * 8)*512) + VBR_offset[partition_cnt]

                        try:
                            with open(f"./result/data{partition_cnt}/{file_name}", "wb") as restore_file:
                                restore_file.write(bytes(data[real_data_offset:real_data_offset+real_data_size]))
                            # print(f"복구성공: {file_name}")
                        except:
                            print(f"복구실패: {file_name}")

                        break
                            
                
                Attribute_ptr = Attribute_ptr + int.from_bytes(restore_list[i][Attribute_ptr + 4:Attribute_ptr + 6], 'little')

def VBR_analysis(data, first_LBA, Last_LBA):
    VBR_offset = []
    MFT_offset = []

    for i in range(0, len(first_LBA)):
        VBR_offset.append(first_LBA[i] * 512)
        sector_per_cluster = data[VBR_offset[i]+13]
        MFT_offset.append(((int.from_bytes(data[VBR_offset[i]+48:VBR_offset[i]+56], 'little') * sector_per_cluster) * 512) + VBR_offset[i])

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

    first_LBA = []
    Last_LBA = []
    for i in range(0, len(data_restore_Partition)):
        partition = data_restore_Partition[i]

        first_LBA.append(int.from_bytes(partition[32:40], 'little'))
        Last_LBA.append(int.from_bytes(partition[40:48], 'little'))

    return len(data_restore_Partition), first_LBA, Last_LBA



if __name__ == '__main__':
    start = time.time()

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
                restore_Partition_cnt, first_LBA, Last_LBA = GPT_analysis(data, GPT_Header_offset)
                # VBR 구조 분석
                VBR_offset, MFT_offset = VBR_analysis(data, first_LBA, Last_LBA)
                # MFT 구조 분석
                MFT_analysis(data, restore_Partition_cnt, VBR_offset, MFT_offset)
    
    print("time :", time.time() - start)