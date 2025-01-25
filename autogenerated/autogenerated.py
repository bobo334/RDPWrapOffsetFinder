import os
import sys
import pefile
import configparser
from win32api import GetFileVersionInfo, LOWORD, HIWORD

def get_version_info(dll_path):
    """Get DLL file version information
    获取DLL文件的版本信息"""
    info = GetFileVersionInfo(dll_path, "\\")
    ms = info['FileVersionMS']
    ls = info['FileVersionLS']
    version_number = f"{HIWORD(ms)}.{LOWORD(ms)}.{HIWORD(ls)}.{LOWORD(ls)}"
    return version_number

def get_data_file_path(file_name):
    """Get the path of the data file
    获取数据文件的路径"""
    if getattr(sys, 'frozen', False):
        # If it's a packaged executable
        # 如果是打包后的可执行文件
        base_path = sys._MEIPASS
    else:
        # If it's in the development environment
        # 如果是在开发环境中
        base_path = os.path.dirname(__file__)
    
    return os.path.join(base_path, file_name)

def get_architecture_type(dll_path):
    """Get the architecture type of the DLL file
    获取DLL文件的架构类型"""
    pe = pefile.PE(dll_path)
    if pe.FILE_HEADER.Machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
        return "x86"
    elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
        return "x64"
    else:
        return None

import subprocess

def execute_command(file_path, arch, dllfilepath, output_dir, ini_name, symbol):
    """Prepare and execute the command based on the provided parameters
    根据提供的参数准备并执行命令"""
    # Prepare the command based on the provided symbol
    # 根据提供的符号准备命令
    if symbol == "-nosymbol":
        command = [os.path.join(file_path, "RDPWrapOffsetFinder_nosymbol.exe"), dllfilepath]
    elif symbol == "-symbol":
        command = [os.path.join(file_path, "RDPWrapOffsetFinder.exe"), dllfilepath]
    else:
        return None  # Return None if the symbol is invalid
    # 返回 None 如果符号无效

    # Define the output file
    # 定义输出文件
    output_file = os.path.join(output_dir, ini_name)

    # Open the output file for writing
    # 打开输出文件以进行写入
    with open(output_file, 'w') as outfile:
        # Run the command using subprocess and redirect the output to the file
        # 使用 subprocess 运行命令并将输出重定向到文件
        subprocess.run(command, stdout=outfile, stderr=subprocess.STDOUT)

def read_config_file(filename):
    """Read the configuration file
    读取配置文件"""
    config = configparser.ConfigParser()
    config.read(filename)
    return config

def parse_config_file(filename):
    """Parse the configuration file and extract critical information
    解析配置文件并提取关键信息"""
    SLInit = LocalOnly = SLPolicy = EXIT = 0
    with open(filename, 'r') as file:
        for line in file:
            if "LocalOnly" in line:
                LocalOnly = 1
            if "SLInit" in line:
                SLInit = 1
            if "SLPolicy" in line:
                SLPolicy = 1
            if "Symbol not found" in line:
                EXIT = 1
            if SLInit and LocalOnly:
                break
    return SLInit, LocalOnly, SLPolicy, EXIT

def get_offsets(config, arch, version_number, SLInit, LocalOnly, SLPolicy):
    """Get all the necessary offsets
    获取所有需要的偏移量"""
    offsets = {}
    if LocalOnly:
        offsets['LocalOnlyOffset'] = config.get(version_number, f'LocalOnlyOffset.{arch}')
        offsets['LocalOnlyCode'] = config.get(version_number, f'LocalOnlyCode.{arch}')
    offsets['SingleUserOffset'] = config.get(version_number, f'SingleUserOffset.{arch}')
    offsets['SingleUserCode'] = config.get(version_number, f'SingleUserCode.{arch}')
    offsets['DefPolicyOffset'] = config.get(version_number, f'DefPolicyOffset.{arch}')
    offsets['DefPolicyCode'] = config.get(version_number, f'DefPolicyCode.{arch}')
    if SLInit:
        slinit = f"{version_number}-SLInit"
        offsets['SLInitOffset'] = config.get(version_number, f'SLInitOffset.{arch}')
        offsets['bInitialized'] = config.get(slinit, f'bInitialized.{arch}')
        offsets['bServerSku'] = config.get(slinit, f'bServerSku.{arch}')
        offsets['lMaxUserSessions'] = config.get(slinit, f'lMaxUserSessions.{arch}')
        offsets['bAppServerAllowed'] = config.get(slinit, f'bAppServerAllowed.{arch}')
        offsets['bRemoteConnAllowed'] = config.get(slinit, f'bRemoteConnAllowed.{arch}')
        offsets['bMultimonAllowed'] = config.get(slinit, f'bMultimonAllowed.{arch}')
        offsets['ulMaxDebugSessions'] = config.get(slinit, f'ulMaxDebugSessions.{arch}')
        offsets['bFUSEnabled'] = config.get(slinit, f'bFUSEnabled.{arch}')
    if SLPolicy:
        offsets['SLPolicyOffset'] = config.get(version_number, f'SLPolicyOffset.{arch}')
        offsets['SLPolicyFunc'] = config.get(version_number, f'SLPolicyFunc.{arch}')
    return offsets

def print_offsets(version_number, arch, offsets, SLInit, LocalOnly, SLPolicy):
    """Print offset information
    打印偏移量信息"""
    print(f"[{version_number}]")
    if LocalOnly:
        print(f"LocalOnlyPatch.{arch}=1")
        print(f"LocalOnlyOffset.{arch}={offsets['LocalOnlyOffset']}")
        print(f"LocalOnlyCode.{arch}={offsets['LocalOnlyCode']}")
    print(f"SingleUserPatch.{arch}=1")
    print(f"SingleUserOffset.{arch}={offsets['SingleUserOffset']}")
    print(f"SingleUserCode.{arch}={offsets['SingleUserCode']}")
    print(f"DefPolicyPatch.{arch}=1")
    print(f"DefPolicyOffset.{arch}={offsets['DefPolicyOffset']}")
    print(f"DefPolicyCode.{arch}={offsets['DefPolicyCode']}")
    if SLPolicy:
        print(f"SLPolicyInternal.{arch}=1")
        print(f"SLPolicyOffset.{arch}={offsets['SLPolicyOffset']}")
        print(f"SLPolicyFunc.{arch}={offsets['SLPolicyFunc']}")
    if SLInit:
        slinit = f"{version_number}-SLInit"
        print(f"SLInitHook.{arch}=1")
        print(f"SLInitOffset.{arch}={offsets['SLInitOffset']}")
        print(f"SLInitFunc.{arch}=New_CSLQuery_Initialize")
        print(f"\n[{slinit}]")
        print(f"bInitialized.{arch}      ={offsets['bInitialized']}")
        print(f"bServerSku.{arch}        ={offsets['bServerSku']}")
        print(f"lMaxUserSessions.{arch}  ={offsets['lMaxUserSessions']}")
        print(f"bAppServerAllowed.{arch} ={offsets['bAppServerAllowed']}")
        print(f"bRemoteConnAllowed.{arch}={offsets['bRemoteConnAllowed']}")
        print(f"bMultimonAllowed.{arch}  ={offsets['bMultimonAllowed']}")
        print(f"ulMaxDebugSessions.{arch}={offsets['ulMaxDebugSessions']}")
        print(f"bFUSEnabled.{arch}       ={offsets['bFUSEnabled']}")

def delete_file(filename):
    """Delete the specified file
    删除指定文件"""
    os.remove(filename)

import datetime

def generate_ini_file(version_number, arch, LocalOnly, SLPolicy, SLInit, offsets):
    """Generate and write the INI configuration file
    生成并写入INI配置文件"""
    now = datetime.datetime.now()
    date = now.strftime("%Y-%m-%d")
    path = "rdpwrap.txt"
    
    file_path = f"{version_number}-autogenerated_{arch}.ini"
    
    with open(file_path, "w") as f:
        def write_line(content):
            f.write(content + "\n")
        
        write_line("[Main]")
        write_line(f"Updated={date}")
        write_line(f"LogFile=\\{path}")
        write_line("SLPolicyHookNT60=1")
        write_line("SLPolicyHookNT61=1")
        write_line("");
        write_line("[SLPolicy]")
        write_line("TerminalServices-RemoteConnectionManager-AllowRemoteConnections=1")
        write_line("TerminalServices-RemoteConnectionManager-AllowMultipleSessions=1")
        write_line("TerminalServices-RemoteConnectionManager-AllowAppServerMode=1")
        write_line("TerminalServices-RemoteConnectionManager-AllowMultimon=1")
        write_line("TerminalServices-RemoteConnectionManager-MaxUserSessions=0")
        write_line("TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions=0")
        write_line("TerminalServices-RemoteConnectionManager-45344fe7-00e6-4ac6-9f01-d01fd4ffadfb-MaxSessions=2")
        write_line("TerminalServices-RDP-7-Advanced-Compression-Allowed=1")
        write_line("TerminalServices-RemoteConnectionManager-45344fe7-00e6-4ac6-9f01-d01fd4ffadfb-LocalOnly=0")
        write_line("TerminalServices-RemoteConnectionManager-8dc86f1d-9969-4379-91c1-06fe1dc60575-MaxSessions=1000")
        write_line("TerminalServices-DeviceRedirection-Licenses-TSEasyPrintAllowed=1")
        write_line("TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed=1")
        write_line("TerminalServices-DeviceRedirection-Licenses-TSMFPluginAllowed=1")
        write_line("TerminalServices-RemoteConnectionManager-UiEffects-DWMRemotingAllowed=1")
        write_line("")
        write_line("[PatchCodes]")
        write_line("nop=90")
        write_line("Zero=00")
        write_line("jmpshort=EB")
        write_line("nopjmp=90E9")
        write_line("CDefPolicy_Query_edx_ecx=BA000100008991200300005E90")
        write_line("CDefPolicy_Query_eax_rcx_jmp=B80001000089813806000090EB")
        write_line("CDefPolicy_Query_eax_esi=B80001000089862003000090")
        write_line("CDefPolicy_Query_eax_rdi=B80001000089873806000090")
        write_line("CDefPolicy_Query_eax_ecx=B80001000089812403000090")
        write_line("CDefPolicy_Query_eax_ecx_jmp=B800010000898120030000EB0E")
        write_line("CDefPolicy_Query_eax_rcx=B80001000089813806000090")
        write_line("CDefPolicy_Query_edi_rcx=BF0001000089B938060000909090")
        write_line("CDefPolicy_Query_eax_rdi_jmp=B80001000089873806000090EB")
        write_line("nop_3=909090")
        write_line("nop_7=90909090909090")
        write_line("mov_eax_1_nop_1=B80100000090")
        write_line("mov_eax_1_nop_2=B8010000009090")
        write_line("nop_4=90909090")
        write_line("pop_eax_add_esp_12_nop_2=5883C40C9090")
        write_line("")
        write_line(f"[{version_number}]")
        if LocalOnly == 1:
            write_line(f"LocalOnlyPatch.{arch}=1")
            write_line(f"LocalOnlyOffset.{arch}={offsets['LocalOnlyOffset']}")
            write_line(f"LocalOnlyCode.{arch}={offsets['LocalOnlyCode']}")
        write_line(f"SingleUserPatch.{arch}=1")
        write_line(f"SingleUserOffset.{arch}={offsets['SingleUserOffset']}")
        write_line(f"SingleUserCode.{arch}={offsets['SingleUserCode']}")
        write_line(f"DefPolicyPatch.{arch}=1")
        write_line(f"DefPolicyOffset.{arch}={offsets['DefPolicyOffset']}")
        write_line(f"DefPolicyCode.{arch}={offsets['DefPolicyCode']}")
        if SLPolicy == 1:
            write_line(f"SLPolicyInternal.{arch}=1")
            write_line(f"SLPolicyOffset.{arch}={offsets['SLPolicyOffset']}")
            write_line(f"SLPolicyFunc.{arch}={offsets['SLPolicyFunc']}")
        if SLInit == 1:
            write_line(f"SLInitHook.{arch}=1")
            write_line(f"SLInitOffset.{arch}={offsets['SLInitOffset']}")
            write_line(f"SLInitFunc.{arch}=New_CSLQuery_Initialize")
        
        if SLInit == 1:
            write_line("")
            write_line("[SLInit]")
            write_line("bServerSku=1")
            write_line("bRemoteConnAllowed=1")
            write_line("bFUSEnabled=1")
            write_line("bAppServerAllowed=1")
            write_line("bMultimonAllowed=1")
            write_line("lMaxUserSessions=0")
            write_line("ulMaxDebugSessions=0")
            write_line("bInitialized=1")
            write_line("")
            write_line(f"[{version_number}-SLInit]")
            write_line(f"bInitialized.{arch}      ={offsets['bInitialized']}")
            write_line(f"bServerSku.{arch}        ={offsets['bServerSku']}")
            write_line(f"lMaxUserSessions.{arch}  ={offsets['lMaxUserSessions']}")
            write_line(f"bAppServerAllowed.{arch} ={offsets['bAppServerAllowed']}")
            write_line(f"bRemoteConnAllowed.{arch}={offsets['bRemoteConnAllowed']}")
            write_line(f"bMultimonAllowed.{arch}  ={offsets['bMultimonAllowed']}")
            write_line(f"ulMaxDebugSessions.{arch}={offsets['ulMaxDebugSessions']}")
            write_line(f"bFUSEnabled.{arch}       ={offsets['bFUSEnabled']}")

def main():
    """Main function
    主函数"""
    if len(sys.argv) < 3:
        print("Usage: python autogenerated.py <dll file path> <-symbol or -nosymbol>")
        # 用法: python autogenerated.py <dll文件路径> <-symbol 或 -nosymbol>
        return 0

    dllfilepath = sys.argv[1]
    symbol = sys.argv[2]
    if not os.path.exists(dllfilepath):
        print("[-] File not found")
        # 打印 "[-] 未找到文件"
        return 0

    version_number = get_version_info(dllfilepath)
    arch = get_architecture_type(dllfilepath)

    if not arch:
        print("[-] Unknown architecture")
        # 打印 "[-] 未知架构"
        return 0
    ini_name = "temp.ini"
    # Get the specific path of the %temp% environment variable
    # 获取%temp%环境变量的具体路径
    output_dir = os.getenv('TEMP')
    file_path = get_data_file_path("bin")
    execute_command(file_path, arch, dllfilepath, output_dir, ini_name, symbol)
    SLInit, LocalOnly, SLPolicy, EXIT = parse_config_file(output_dir + "\\" + ini_name)
    if EXIT:
        print("[-] Error: Symbol not found")
        # 打印 "[-] 错误: 未找到符号"
        return 0

    config = read_config_file(output_dir + "\\" + ini_name)

    offsets = get_offsets(config, arch, version_number, SLInit, LocalOnly, SLPolicy)
    print_offsets(version_number, arch, offsets, SLInit, LocalOnly, SLPolicy)

    delete_file(output_dir + "\\" + ini_name)
    
    generate_ini_file(version_number, arch, LocalOnly, SLPolicy, SLInit, offsets)

if __name__ == "__main__":
    main()
